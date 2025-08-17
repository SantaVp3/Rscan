use crate::{Result, ScanError};
use crate::types::{Target, Port, Protocol, PortState, Service};
use crate::config::Config;
use crate::platform;
use futures::stream::{self, StreamExt};
use log::{debug, info};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// 主机发现策略
#[derive(Debug, Clone, PartialEq)]
pub enum DiscoveryStrategy {
    /// ICMP Ping（需要特殊权限）
    IcmpPing,
    /// TCP连接测试
    TcpConnect,
    /// ARP扫描（同子网）
    ArpScan,
    /// 系统命令ping
    SystemPing,
    /// 混合策略
    Hybrid,
}

/// 主机发现结果
#[derive(Debug, Clone)]
pub struct LiveHost {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub discovery_method: String,
    pub response_time: Duration,
    pub confidence: f32,  // 存活置信度 0.0-1.0
}

/// 多层智能主机发现引擎
pub struct HostDiscoveryEngine {
    config: Config,
    icmp_available: bool,
    arp_available: bool,
    platform_info: PlatformInfo,
}

/// 平台信息
#[derive(Debug)]
struct PlatformInfo {
    os: String,
    has_admin_privileges: bool,
    raw_socket_support: bool,
}

impl HostDiscoveryEngine {
    /// 创建新的主机发现引擎
    pub fn new(config: Config) -> Result<Self> {
        let platform_info = Self::detect_platform_capabilities();
        let icmp_available = Self::test_icmp_availability(&platform_info);
        let arp_available = Self::test_arp_availability(&platform_info);

        info!("主机发现引擎初始化:");
        info!("  平台: {}", platform_info.os);
        info!("  管理员权限: {}", platform_info.has_admin_privileges);
        info!("  ICMP可用: {}", icmp_available);
        info!("  ARP扫描可用: {}", arp_available);

        Ok(Self {
            config,
            icmp_available,
            arp_available,
            platform_info,
        })
    }

    /// 智能主机发现 - 主要入口点
    pub async fn discover_hosts(&self, targets: &[String]) -> Result<Vec<LiveHost>> {
        let mut all_hosts = Vec::new();
        
        for target in targets {
            let ips = self.parse_target(target)?;
            let strategy = self.select_optimal_strategy(&ips).await;
            
            info!("目标 {} 使用策略: {:?}", target, strategy);
            
            let hosts = match strategy {
                DiscoveryStrategy::Hybrid => {
                    self.hybrid_discovery(&ips).await?
                },
                DiscoveryStrategy::IcmpPing => {
                    self.icmp_discovery(&ips).await?
                },
                DiscoveryStrategy::TcpConnect => {
                    self.tcp_discovery(&ips).await?
                },
                DiscoveryStrategy::ArpScan => {
                    self.arp_discovery(&ips).await?
                },
                DiscoveryStrategy::SystemPing => {
                    self.system_ping_discovery(&ips).await?
                }
            };
            
            all_hosts.extend(hosts);
        }

        // 去重和排序
        all_hosts.sort_by(|a, b| a.ip.cmp(&b.ip));
        all_hosts.dedup_by(|a, b| a.ip == b.ip);
        
        info!("发现 {} 个活动主机", all_hosts.len());
        Ok(all_hosts)
    }

    /// 选择最优探测策略
    async fn select_optimal_strategy(&self, ips: &[IpAddr]) -> DiscoveryStrategy {
        // 检查是否是同一子网
        let is_same_subnet = self.is_same_subnet(ips).await;
        
        // 根据平台、权限、网络环境选择策略
        if self.arp_available && is_same_subnet {
            DiscoveryStrategy::ArpScan
        } else if self.icmp_available && self.platform_info.has_admin_privileges {
            DiscoveryStrategy::Hybrid  // ICMP + TCP 组合
        } else if cfg!(windows) {
            // Windows上优先使用系统ping + TCP
            DiscoveryStrategy::Hybrid
        } else {
            // 其他平台使用TCP连接
            DiscoveryStrategy::TcpConnect
        }
    }

    /// 混合发现策略 - 最全面的方法
    async fn hybrid_discovery(&self, ips: &[IpAddr]) -> Result<Vec<LiveHost>> {
        let mut results = Vec::new();
        
        // 1. 首先尝试快速方法（ICMP或系统ping）
        let quick_results = if self.icmp_available {
            self.icmp_discovery(ips).await.unwrap_or_default()
        } else {
            self.system_ping_discovery(ips).await.unwrap_or_default()
        };
        
        results.extend(quick_results);
        
        // 2. 对没有响应的IP进行TCP探测
        let discovered_ips: Vec<IpAddr> = results.iter().map(|h| h.ip).collect();
        let remaining_ips: Vec<IpAddr> = ips.iter()
            .filter(|ip| !discovered_ips.contains(ip))
            .cloned()
            .collect();
        
        if !remaining_ips.is_empty() {
            debug!("对 {} 个IP进行TCP补充探测", remaining_ips.len());
            let tcp_results = self.tcp_discovery(&remaining_ips).await?;
            results.extend(tcp_results);
        }
        
        // 3. 如果可用，进行ARP扫描作为最后验证
        if self.arp_available && self.is_same_subnet(ips).await {
            let arp_results = self.arp_discovery(ips).await.unwrap_or_default();
            // 合并ARP结果，提高置信度
            for arp_host in arp_results {
                if let Some(existing) = results.iter_mut().find(|h| h.ip == arp_host.ip) {
                    existing.confidence = (existing.confidence + 0.3).min(1.0);
                    existing.discovery_method = format!("{} + ARP", existing.discovery_method);
                } else {
                    results.push(arp_host);
                }
            }
        }
        
        Ok(results)
    }

    /// 使用ping crate进行ping
    async fn ping_with_rust_ping(&self, ip: IpAddr) -> Result<Option<LiveHost>> {
        let start = Instant::now();
        
        // 使用tokio::spawn_blocking来调用同步的ping函数
        let result = tokio::task::spawn_blocking(move || {
            use std::time::Duration;
            
            // 使用ping crate的正确API
            ping::ping(ip, Some(Duration::from_secs(3)), None, None, None, None).is_ok()
        }).await;
        
        match result {
            Ok(true) => {
                let response_time = start.elapsed();
                debug!("主机 {} 存活 (ping crate, {}ms)", ip, response_time.as_millis());
                
                Ok(Some(LiveHost {
                    ip,
                    hostname: None,
                    discovery_method: "Ping Crate".to_string(),
                    response_time,
                    confidence: 0.9,
                }))
            }
            Ok(false) | Err(_) => {
                debug!("主机 {} ping失败", ip);
                Ok(None)
            }
        }
    }

    /// ICMP发现（使用ping crate或系统ping）
    async fn icmp_discovery(&self, ips: &[IpAddr]) -> Result<Vec<LiveHost>> {
        let mut results = Vec::new();
        
        // 优先尝试ping crate，如果失败则使用系统ping
        let ping_futures = ips.iter().map(|&ip| async move {
            // 首先尝试ping crate
            if let Ok(Some(host)) = self.ping_with_rust_ping(ip).await {
                Ok(Some(host))
            } else {
                // 回退到系统ping
                self.system_ping(ip).await
            }
        });
        
        let ping_results = futures::future::join_all(ping_futures).await;
        
        for result in ping_results {
            if let Ok(Some(host)) = result {
                results.push(host);
            }
        }
        
        Ok(results)
    }

    /// 系统命令ping发现
    async fn system_ping_discovery(&self, ips: &[IpAddr]) -> Result<Vec<LiveHost>> {
        let mut results = Vec::new();
        
        // 并发执行系统ping命令
        let ping_futures = ips.iter().map(|&ip| async move {
            self.system_ping(ip).await
        });
        
        let ping_results = stream::iter(ping_futures)
            .buffer_unordered(self.config.scan.threads)
            .collect::<Vec<_>>()
            .await;
        
        for result in ping_results {
            if let Ok(Some(host)) = result {
                results.push(host);
            }
        }
        
        Ok(results)
    }

    /// 执行系统ping命令
    async fn system_ping(&self, ip: IpAddr) -> Result<Option<LiveHost>> {
        let start = Instant::now();
        
        let ip_string = ip.to_string();
        let (cmd, args) = if cfg!(windows) {
            ("ping", vec!["-n", "1", "-w", "3000", &ip_string])
        } else {
            ("ping", vec!["-c", "1", "-W", "3", &ip_string])
        };
        
        // 使用tokio::process执行命令
        let output = tokio::process::Command::new(cmd)
            .args(&args)
            .output()
            .await
            .map_err(|e| ScanError::Discovery(format!("执行ping命令失败: {}", e)))?;
        
        let response_time = start.elapsed();
        
        if output.status.success() {
            debug!("主机 {} 存活 (系统ping, {}ms)", ip, response_time.as_millis());
            
            Ok(Some(LiveHost {
                ip,
                hostname: None,
                discovery_method: "系统Ping".to_string(),
                response_time,
                confidence: 0.95,
            }))
        } else {
            debug!("主机 {} 系统ping失败", ip);
            Ok(None)
        }
    }

    /// TCP连接发现 - 增强版本
    async fn tcp_discovery(&self, ips: &[IpAddr]) -> Result<Vec<LiveHost>> {
        let mut results = Vec::new();
        
        // 扩展的端口列表，按优先级排序
        let priority_ports = [80, 443, 22, 135, 445];  // 最常见的端口
        let common_ports = [
            21, 23, 25, 53, 110, 139, 143, 993, 995,    // 传统服务
            3389, 1433, 3306, 5432, 6379,                // 数据库和远程桌面
            8080, 8443, 9090, 9200, 5000, 8000, 8888    // Web服务
        ];
        
        for &ip in ips {
            // 先测试高优先级端口
            if let Some(host) = self.test_tcp_ports(ip, &priority_ports, "高优先级TCP").await? {
                results.push(host);
                continue;
            }
            
            // 如果高优先级端口没有响应，测试其他常见端口
            if let Some(host) = self.test_tcp_ports(ip, &common_ports, "通用TCP").await? {
                results.push(host);
            }
        }
        
        Ok(results)
    }

    /// 测试TCP端口组
    async fn test_tcp_ports(&self, ip: IpAddr, ports: &[u16], method_name: &str) -> Result<Option<LiveHost>> {
        let start = Instant::now();
        
        // 并发测试所有端口，但只要有一个成功就返回
        let port_futures = ports.iter().map(|&port| async move {
            let addr = SocketAddr::new(ip, port);
            match timeout(Duration::from_millis(2000), tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        });
        
        let results = futures::future::join_all(port_futures).await;
        
        for result in results.iter() {
            if let Some(port) = result {
                let response_time = start.elapsed();
                debug!("主机 {} 存活 ({}, 端口 {}, {}ms)", ip, method_name, port, response_time.as_millis());
                
                return Ok(Some(LiveHost {
                    ip,
                    hostname: None,
                    discovery_method: format!("{} (:{}) ", method_name, port),
                    response_time,
                    confidence: 0.8,
                }));
            }
        }
        
        Ok(None)
    }

    /// ARP扫描发现（仅同子网）
    async fn arp_discovery(&self, ips: &[IpAddr]) -> Result<Vec<LiveHost>> {
        let mut results = Vec::new();
        
        // 使用if-addrs获取本地网络接口
        let interfaces = if_addrs::get_if_addrs()
            .map_err(|e| ScanError::Discovery(format!("获取网络接口失败: {}", e)))?;
        
        for ip in ips {
            if let IpAddr::V4(ipv4) = ip {
                if let Some(host) = self.arp_ping(*ipv4, &interfaces).await? {
                    results.push(host);
                }
            }
        }
        
        Ok(results)
    }

    /// ARP ping实现
    async fn arp_ping(&self, ip: Ipv4Addr, _interfaces: &[if_addrs::Interface]) -> Result<Option<LiveHost>> {
        // 这里实现ARP ping逻辑
        // 为了简化，现在返回None，实际实现需要构造ARP包
        debug!("ARP ping {} (占位实现)", ip);
        Ok(None)
    }

    /// 检测平台能力
    fn detect_platform_capabilities() -> PlatformInfo {
        let os = std::env::consts::OS.to_string();
        let has_admin_privileges = crate::platform::has_admin_privileges();
        let raw_socket_support = crate::platform::can_create_raw_socket();
        
        PlatformInfo {
            os,
            has_admin_privileges,
            raw_socket_support,
        }
    }

    /// 测试ICMP可用性
    fn test_icmp_availability(platform_info: &PlatformInfo) -> bool {
        // 在Windows上，原始套接字需要管理员权限
        if cfg!(windows) {
            platform_info.has_admin_privileges && platform_info.raw_socket_support
        } else {
            // 在Unix系统上，通常可以使用ICMP socket
            true
        }
    }

    /// 测试ARP可用性
    fn test_arp_availability(platform_info: &PlatformInfo) -> bool {
        // ARP扫描需要原始套接字和管理员权限
        platform_info.has_admin_privileges && platform_info.raw_socket_support
    }

    /// 检查是否是同一子网
    async fn is_same_subnet(&self, ips: &[IpAddr]) -> bool {
        // 简化实现：检查是否是私有IP范围
        ips.iter().all(|ip| {
            match ip {
                IpAddr::V4(ipv4) => {
                    ipv4.is_private()
                },
                IpAddr::V6(_) => false,  // 暂不支持IPv6 ARP
            }
        })
    }

    /// 解析目标字符串为IP地址列表
    fn parse_target(&self, target: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        if target.contains('/') {
            // CIDR notation
            ips.extend(self.parse_cidr(target)?);
        } else if target.contains('-') {
            // IP range (e.g., 192.168.1.1-192.168.1.100)
            ips.extend(self.parse_range(target)?);
        } else {
            // Single IP or hostname
            match target.parse::<IpAddr>() {
                Ok(ip) => ips.push(ip),
                Err(_) => {
                    // Try to resolve hostname
                    match self.resolve_hostname_sync(target) {
                        Ok(resolved_ips) => ips.extend(resolved_ips),
                        Err(e) => return Err(ScanError::InvalidTarget(format!("Failed to resolve {}: {}", target, e))),
                    }
                }
            }
        }

        Ok(ips)
    }

    /// 解析CIDR表示法
    fn parse_cidr(&self, cidr: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(ScanError::InvalidTarget(format!("Invalid CIDR format: {}", cidr)));
        }

        let base_ip: Ipv4Addr = parts[0].parse()
            .map_err(|_| ScanError::InvalidTarget(format!("Invalid IP in CIDR: {}", parts[0])))?;
        
        let prefix_len: u8 = parts[1].parse()
            .map_err(|_| ScanError::InvalidTarget(format!("Invalid prefix length: {}", parts[1])))?;

        if prefix_len > 32 {
            return Err(ScanError::InvalidTarget("Prefix length cannot exceed 32".to_string()));
        }

        let mut ips = Vec::new();
        let base = u32::from(base_ip);
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        let network = base & mask;
        let broadcast = network | ((1u32 << (32 - prefix_len)) - 1);

        for ip_int in (network + 1)..broadcast {
            ips.push(IpAddr::V4(Ipv4Addr::from(ip_int)));
        }

        Ok(ips)
    }

    /// 解析IP范围
    fn parse_range(&self, range: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err(ScanError::InvalidTarget(format!("Invalid range format: {}", range)));
        }

        let start_ip: Ipv4Addr = parts[0].parse()
            .map_err(|_| ScanError::InvalidTarget(format!("Invalid start IP: {}", parts[0])))?;
        
        let end_ip: Ipv4Addr = parts[1].parse()
            .map_err(|_| ScanError::InvalidTarget(format!("Invalid end IP: {}", parts[1])))?;

        let mut ips = Vec::new();
        let start = u32::from(start_ip);
        let end = u32::from(end_ip);

        if start > end {
            return Err(ScanError::InvalidTarget("Start IP cannot be greater than end IP".to_string()));
        }

        for ip_int in start..=end {
            ips.push(IpAddr::V4(Ipv4Addr::from(ip_int)));
        }

        Ok(ips)
    }

    /// 同步解析主机名（用于解析目标）
    fn resolve_hostname_sync(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;

        let mut ips = Vec::new();

        match format!("{}:80", hostname).to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    ips.push(addr.ip());
                }
            }
            Err(e) => return Err(ScanError::DnsResolution(format!("Failed to resolve {}: {}", hostname, e))),
        }

        Ok(ips)
    }
}

/// 向后兼容的NetworkDiscovery结构体
pub struct NetworkDiscovery {
    engine: HostDiscoveryEngine,
}

impl NetworkDiscovery {
    /// 创建NetworkDiscovery实例
    pub fn new(config: Config) -> Result<Self> {
        let engine = HostDiscoveryEngine::new(config)?;
        Ok(Self { engine })
    }

    /// 发现活动主机（向后兼容）
    pub async fn discover_hosts(&self, targets: &[String]) -> Result<Vec<IpAddr>> {
        let live_hosts = self.engine.discover_hosts(targets).await?;
        Ok(live_hosts.into_iter().map(|h| h.ip).collect())
    }

    /// 扫描端口
    pub async fn scan_ports(&self, targets: &[IpAddr], port_range: &str) -> Result<Vec<Target>> {
        self.scan_ports_with_protocol(targets, port_range, &crate::cli::ScanType::Tcp).await
    }

    /// 使用指定协议扫描端口
    pub async fn scan_ports_with_protocol(&self, targets: &[IpAddr], port_range: &str, scan_type: &crate::cli::ScanType) -> Result<Vec<Target>> {
        let ports = self.parse_port_range(port_range)?;
        let mut results = Vec::new();
        
        for &target_ip in targets {
            let mut all_ports = Vec::new();

            match scan_type {
                crate::cli::ScanType::Tcp => {
                    let tcp_ports = stream::iter(ports.clone())
                        .map(|port| self.scan_tcp_port(target_ip, port))
                        .buffer_unordered(self.engine.config.scan.threads)
                        .collect::<Vec<_>>()
                        .await;

                    for result in tcp_ports {
                        if let Ok(Some(port)) = result {
                            all_ports.push(port);
                        }
                    }
                }
                crate::cli::ScanType::Udp => {
                    let udp_ports = stream::iter(ports.clone())
                        .map(|port| self.scan_udp_port(target_ip, port))
                        .buffer_unordered(self.engine.config.scan.threads / 2)
                        .collect::<Vec<_>>()
                        .await;

                    for result in udp_ports {
                        if let Ok(Some(port)) = result {
                            all_ports.push(port);
                        }
                    }
                }
                crate::cli::ScanType::Both => {
                    // 扫描TCP和UDP
                    let tcp_future = async {
                        let tcp_ports = stream::iter(ports.clone())
                            .map(|port| self.scan_tcp_port(target_ip, port))
                            .buffer_unordered(self.engine.config.scan.threads)
                            .collect::<Vec<_>>()
                            .await;
                        tcp_ports
                    };

                    let udp_future = async {
                        let udp_ports = stream::iter(ports.clone())
                            .map(|port| self.scan_udp_port(target_ip, port))
                            .buffer_unordered(self.engine.config.scan.threads / 2)
                            .collect::<Vec<_>>()
                            .await;
                        udp_ports
                    };

                    let (tcp_results, udp_results) = tokio::join!(tcp_future, udp_future);

                    for result in tcp_results {
                        if let Ok(Some(port)) = result {
                            all_ports.push(port);
                        }
                    }

                    for result in udp_results {
                        if let Ok(Some(port)) = result {
                            all_ports.push(port);
                        }
                    }
                }
            }

            if !all_ports.is_empty() {
                // 执行反向DNS查找
                let hostname = self.reverse_dns_lookup(target_ip).await.ok();

                results.push(Target {
                    ip: target_ip,
                    hostname,
                    ports: all_ports,
                });
            }
        }

        Ok(results)
    }

    /// 解析端口范围字符串
    fn parse_port_range(&self, range: &str) -> Result<Vec<u16>> {
        let mut ports = Vec::new();

        for part in range.split(',') {
            if part.contains('-') {
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(ScanError::InvalidTarget(format!("Invalid port range: {}", part)));
                }

                let start: u16 = range_parts[0].parse()
                    .map_err(|_| ScanError::InvalidTarget(format!("Invalid start port: {}", range_parts[0])))?;
                
                let end: u16 = range_parts[1].parse()
                    .map_err(|_| ScanError::InvalidTarget(format!("Invalid end port: {}", range_parts[1])))?;

                if start > end {
                    return Err(ScanError::InvalidTarget("Start port cannot be greater than end port".to_string()));
                }

                for port in start..=end {
                    ports.push(port);
                }
            } else {
                let port: u16 = part.parse()
                    .map_err(|_| ScanError::InvalidTarget(format!("Invalid port: {}", part)))?;
                ports.push(port);
            }
        }

        Ok(ports)
    }

    /// 扫描单个TCP端口
    async fn scan_tcp_port(&self, ip: IpAddr, port: u16) -> Result<Option<Port>> {
        let addr = SocketAddr::new(ip, port);

        match timeout(self.engine.config.tcp_connect_timeout(), tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("TCP Port {}:{} is open", ip, port);

                let service = self.detect_service(ip, port, Protocol::Tcp).await.ok();

                Ok(Some(Port {
                    number: port,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service,
                }))
            }
            Ok(Err(_)) => {
                // Connection refused - port is closed
                Ok(None)
            }
            Err(_) => {
                // Timeout - port might be filtered
                Ok(None)
            }
        }
    }

    /// 扫描单个UDP端口
    async fn scan_udp_port(&self, ip: IpAddr, port: u16) -> Result<Option<Port>> {
        let local_addr = if ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(local_addr).await
            .map_err(|e| ScanError::Discovery(format!("Failed to bind UDP socket: {}", e)))?;

        let target_addr = SocketAddr::new(ip, port);

        // 获取特定端口的UDP探测数据
        let probe_data = self.get_udp_probe(port);

        // 发送UDP探测
        match socket.send_to(&probe_data, target_addr).await {
            Ok(_) => {
                let mut buffer = vec![0; 1024];

                match timeout(self.engine.config.discovery.udp_timeout, socket.recv_from(&mut buffer)).await {
                    Ok(Ok((len, _))) if len > 0 => {
                        debug!("UDP Port {}:{} is open (response received)", ip, port);

                        let service = self.detect_service(ip, port, Protocol::Udp).await.ok();

                        Ok(Some(Port {
                            number: port,
                            protocol: Protocol::Udp,
                            state: PortState::Open,
                            service,
                        }))
                    }
                    Ok(Ok((_, _))) => {
                        Ok(None)
                    }
                    Ok(Err(_)) => {
                        Ok(None)
                    }
                    Err(_) => {
                        // 对于常见UDP服务，假设是开放的
                        if self.is_common_udp_service(port) {
                            debug!("UDP Port {}:{} might be open (timeout on common service)", ip, port);

                            let service = self.detect_service(ip, port, Protocol::Udp).await.ok();

                            Ok(Some(Port {
                                number: port,
                                protocol: Protocol::Udp,
                                state: PortState::Open,
                                service,
                            }))
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// 获取特定端口的UDP探测数据
    fn get_udp_probe(&self, port: u16) -> Vec<u8> {
        match port {
            53 => {
                // DNS查询
                vec![
                    0x12, 0x34, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                    0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
                    0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
                    0x00, // End of name
                    0x00, 0x10, // Type: TXT
                    0x00, 0x03, // Class: CHAOS
                ]
            }
            161 => {
                // SNMP GetRequest
                vec![
                    0x30, 0x26, // SEQUENCE, length 38
                    0x02, 0x01, 0x00, // INTEGER version (0)
                    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING "public"
                    0xa0, 0x19, // GetRequest PDU
                    0x02, 0x01, 0x01, // INTEGER request-id (1)
                    0x02, 0x01, 0x00, // INTEGER error-status (0)
                    0x02, 0x01, 0x00, // INTEGER error-index (0)
                    0x30, 0x0e, // SEQUENCE variable-bindings
                    0x30, 0x0c, // SEQUENCE
                    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID
                    0x05, 0x00, // NULL
                ]
            }
            123 => {
                // NTP请求
                vec![
                    0x1b, // LI=0, VN=3, Mode=3 (client)
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            }
            69 => {
                // TFTP读取请求
                vec![
                    0x00, 0x01, // Opcode: Read Request
                    0x74, 0x65, 0x73, 0x74, 0x00, // Filename: "test"
                    0x6f, 0x63, 0x74, 0x65, 0x74, 0x00, // Mode: "octet"
                ]
            }
            _ => {
                // 通用UDP探测
                b"rscan_udp_probe".to_vec()
            }
        }
    }

    /// 检查是否是常见UDP服务
    fn is_common_udp_service(&self, port: u16) -> bool {
        matches!(port, 53 | 67 | 68 | 69 | 123 | 161 | 162 | 514 | 520 | 1812 | 1813)
    }

    /// 增强的服务检测与横幅抓取
    async fn detect_service(&self, ip: IpAddr, port: u16, protocol: Protocol) -> Result<Service> {
        let service_name = match (protocol, port) {
            (Protocol::Tcp, 21) => "ftp",
            (Protocol::Tcp, 22) => "ssh",
            (Protocol::Tcp, 23) => "telnet",
            (Protocol::Tcp, 25) => "smtp",
            (Protocol::Tcp, 53) | (Protocol::Udp, 53) => "dns",
            (Protocol::Tcp, 80) => "http",
            (Protocol::Tcp, 110) => "pop3",
            (Protocol::Tcp, 135) => "msrpc",
            (Protocol::Tcp, 139) => "netbios-ssn",
            (Protocol::Tcp, 143) => "imap",
            (Protocol::Tcp, 443) => "https",
            (Protocol::Tcp, 445) => "microsoft-ds",
            (Protocol::Tcp, 993) => "imaps",
            (Protocol::Tcp, 995) => "pop3s",
            (Protocol::Tcp, 1433) => "mssql",
            (Protocol::Tcp, 3306) => "mysql",
            (Protocol::Tcp, 3389) => "rdp",
            (Protocol::Tcp, 5432) => "postgresql",
            (Protocol::Tcp, 6379) => "redis",
            (Protocol::Udp, 67) => "dhcp-server",
            (Protocol::Udp, 68) => "dhcp-client",
            (Protocol::Udp, 69) => "tftp",
            (Protocol::Udp, 123) => "ntp",
            (Protocol::Udp, 161) => "snmp",
            (Protocol::Udp, 162) => "snmp-trap",
            (Protocol::Udp, 514) => "syslog",
            (Protocol::Udp, 520) => "rip",
            _ => "unknown",
        };

        // 对TCP服务尝试横幅抓取
        let (version, banner) = if matches!(protocol, Protocol::Tcp) {
            self.grab_service_banner(ip, port).await.unwrap_or((None, None))
        } else {
            (None, None)
        };

        Ok(Service {
            name: service_name.to_string(),
            version,
            banner,
        })
    }

    /// 抓取服务横幅用于版本检测
    async fn grab_service_banner(&self, ip: IpAddr, port: u16) -> Result<(Option<String>, Option<String>)> {
        let addr = SocketAddr::new(ip, port);

        let mut stream = match timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok((None, None)),
        };

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 根据服务发送适当的探测
        let probe = match port {
            21 | 22 | 25 | 110 | 143 | 993 | 995 => {
                // 立即发送横幅的服务
                None
            }
            80 | 8080 | 8000 => {
                // HTTP探测
                Some(b"HEAD / HTTP/1.0\r\n\r\n".to_vec())
            }
            443 => {
                // HTTPS - 只是尝试连接，不发送数据
                None
            }
            23 => {
                // Telnet
                Some(b"\r\n".to_vec())
            }
            _ => None,
        };

        // 如果需要，发送探测
        if let Some(probe_data) = probe {
            let _ = stream.write_all(&probe_data).await;
        }

        // 读取响应
        let mut buffer = vec![0; 1024];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                if !banner.is_empty() {
                    let version = self.extract_version_from_banner(&banner, port);
                    debug!("Banner from {}:{}: {}", ip, port, banner);
                    Ok((version, Some(banner)))
                } else {
                    Ok((None, None))
                }
            }
            _ => Ok((None, None)),
        }
    }

    /// 从横幅中提取版本信息
    fn extract_version_from_banner(&self, banner: &str, port: u16) -> Option<String> {
        match port {
            22 => {
                // SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
                if let Some(version_part) = banner.strip_prefix("SSH-") {
                    if let Some(space_pos) = version_part.find(' ') {
                        Some(version_part[..space_pos].to_string())
                    } else {
                        Some(version_part.to_string())
                    }
                } else {
                    None
                }
            }
            21 => {
                // FTP: "220 (vsFTPd 3.0.3)"
                if banner.contains("vsFTPd") {
                    banner.split_whitespace()
                        .find(|s| s.starts_with("vsFTPd") || s.contains('.'))
                        .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric() && c != '.'))
                        .map(String::from)
                } else {
                    None
                }
            }
            80 | 8080 | 8000 => {
                // HTTP: "Server: Apache/2.4.41 (Ubuntu)"
                if let Some(server_line) = banner.lines().find(|line| line.to_lowercase().starts_with("server:")) {
                    server_line.split(':').nth(1).map(|s| s.trim().to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// 执行反向DNS查找
    async fn reverse_dns_lookup(&self, ip: IpAddr) -> Result<String> {
        // 简化的反向DNS查找
        match tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            format!("{}:80", ip).to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip().to_string())
        }).await {
            Ok(Some(hostname)) if hostname != ip.to_string() => Ok(hostname),
            _ => Err(ScanError::DnsResolution(format!("No reverse DNS for {}", ip))),
        }
    }
}
