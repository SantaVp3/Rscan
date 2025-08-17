use crate::{Result, ScanError};
use crate::types::{Target, Port, Protocol, PortState, Service};
use crate::config::Config;
use futures::stream::{self, StreamExt};
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use surge_ping::{Client, Config as PingConfig, IcmpPacket, PingIdentifier, PingSequence};
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::timeout;


pub struct NetworkDiscovery {
    config: Config,
    ping_client: Option<Client>,
}


//网络发现类
impl NetworkDiscovery {
    //创建一个网络发现对象
    pub fn new(config: Config) -> Result<Self> {
        let ping_client = match Client::new(&PingConfig::default()) {
            Ok(client) => Some(client),
            Err(e) => {
                warn!("Failed to create ping client: {}. ICMP discovery will be disabled.", e);
                None
            }
        };
    
        Ok(Self {
            config,
            ping_client,
        })
    }
    //对指定IP段进行存活扫描
    /// Discover live hosts in the given IP range
    pub async fn discover_hosts(&self, targets: &[String]) -> Result<Vec<IpAddr>> {
        let mut live_hosts = Vec::new();
        //
        for target in targets {
            let ips = self.parse_target(target)?;
            
            let ping_results = stream::iter(ips)
                .map(|ip| self.ping_host(ip))
                .buffer_unordered(self.config.scan.threads)
                .collect::<Vec<_>>()
                .await;

            for result in ping_results {
                if let Ok(Some(ip)) = result {
                    live_hosts.push(ip);
                }
            }
        }

        info!("Discovered {} live hosts", live_hosts.len());
        Ok(live_hosts)
    }

    /// Parse target string into list of IP addresses
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

    /// Parse CIDR notation
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

    /// Parse IP range
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

    /// Resolve hostname to IP addresses (synchronous version)
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

    /// Resolve hostname to IP addresses
    async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        
        match lookup_host(format!("{}:80", hostname)).await {
            Ok(addrs) => {
                for addr in addrs {
                    ips.push(addr.ip());
                }
            }
            Err(e) => return Err(ScanError::DnsResolution(format!("Failed to resolve {}: {}", hostname, e))),
        }

        Ok(ips)
    }

    /// Ping a single host
    async fn ping_host(&self, ip: IpAddr) -> Result<Option<IpAddr>> {
        if let Some(ref client) = self.ping_client {
            match ip {
                IpAddr::V4(ipv4) => {
                    let mut pinger = client.pinger(IpAddr::V4(ipv4), PingIdentifier(rand::random())).await;
                    pinger.timeout(self.config.ping_timeout());

                    match timeout(self.config.ping_timeout(), pinger.ping(PingSequence(0), &[])).await {
                        Ok(Ok((IcmpPacket::V4(_), _))) => {
                            debug!("Host {} is alive (ICMP)", ip);
                            Ok(Some(ip))
                        }
                        Ok(Ok((IcmpPacket::V6(_), _))) => {
                            debug!("Host {} is alive (ICMP IPv6)", ip);
                            Ok(Some(ip))
                        }
                        Ok(Err(_)) | Err(_) => {
                            // ICMP failed, try TCP connect
                            self.tcp_ping(ip).await
                        }
                    }
                }
                IpAddr::V6(_) => {
                    // For IPv6, fall back to TCP connect
                    self.tcp_ping(ip).await
                }
            }
        } else {
            // No ICMP client available, use TCP connect
            self.tcp_ping(ip).await
        }
    }

    /// TCP connect test for host discovery
    async fn tcp_ping(&self, ip: IpAddr) -> Result<Option<IpAddr>> {
        let common_ports = [80, 443, 22, 21, 23, 25, 53, 135, 139, 445];
        
        for &port in &common_ports {
            let addr = SocketAddr::new(ip, port);
            
            match timeout(Duration::from_millis(1000), tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_)) => {
                    debug!("Host {} is alive (TCP:{})", ip, port);
                    return Ok(Some(ip));
                }
                _ => continue,
            }
        }

        debug!("Host {} appears to be down", ip);
        Ok(None)
    }

    /// Scan ports on target hosts
    pub async fn scan_ports(&self, targets: &[IpAddr], port_range: &str) -> Result<Vec<Target>> {
        self.scan_ports_with_protocol(targets, port_range, &crate::cli::ScanType::Tcp).await
    }

    /// Scan ports with specific protocol
    pub async fn scan_ports_with_protocol(&self, targets: &[IpAddr], port_range: &str, scan_type: &crate::cli::ScanType) -> Result<Vec<Target>> {
        let ports = self.parse_port_range(port_range)?;
        let mut results = Vec::new();

        for &target_ip in targets {
            let mut all_ports = Vec::new();

            match scan_type {
                crate::cli::ScanType::Tcp => {
                    let tcp_ports = stream::iter(ports.clone())
                        .map(|port| self.scan_tcp_port(target_ip, port))
                        .buffer_unordered(self.config.scan.threads)
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
                        .buffer_unordered(self.config.scan.threads / 2) // UDP scanning is slower
                        .collect::<Vec<_>>()
                        .await;

                    for result in udp_ports {
                        if let Ok(Some(port)) = result {
                            all_ports.push(port);
                        }
                    }
                }
                crate::cli::ScanType::Both => {
                    // Scan both TCP and UDP
                    let tcp_future = async {
                        let tcp_ports = stream::iter(ports.clone())
                            .map(|port| self.scan_tcp_port(target_ip, port))
                            .buffer_unordered(self.config.scan.threads)
                            .collect::<Vec<_>>()
                            .await;
                        tcp_ports
                    };

                    let udp_future = async {
                        let udp_ports = stream::iter(ports.clone())
                            .map(|port| self.scan_udp_port(target_ip, port))
                            .buffer_unordered(self.config.scan.threads / 2)
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
                // Perform reverse DNS lookup
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

    /// Parse port range string
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

    /// Scan a single TCP port
    async fn scan_tcp_port(&self, ip: IpAddr, port: u16) -> Result<Option<Port>> {
        let addr = SocketAddr::new(ip, port);

        match timeout(self.config.tcp_connect_timeout(), tokio::net::TcpStream::connect(addr)).await {
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

    /// Scan a single UDP port
    async fn scan_udp_port(&self, ip: IpAddr, port: u16) -> Result<Option<Port>> {
        let local_addr = if ip.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(local_addr).await
            .map_err(|e| ScanError::Discovery(format!("Failed to bind UDP socket: {}", e)))?;

        let target_addr = SocketAddr::new(ip, port);

        // Get UDP probe data for specific port
        let probe_data = self.get_udp_probe(port);

        // Send UDP probe
        match socket.send_to(&probe_data, target_addr).await {
            Ok(_) => {
                // Wait for response or ICMP unreachable
                let mut buffer = vec![0; 1024];

                match timeout(self.config.discovery.udp_timeout, socket.recv_from(&mut buffer)).await {
                    Ok(Ok((len, _))) if len > 0 => {
                        // Got a response - port is open
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
                        // Empty response
                        Ok(None)
                    }
                    Ok(Err(_)) => {
                        // ICMP unreachable or other error - port likely closed
                        Ok(None)
                    }
                    Err(_) => {
                        // Timeout - could be open but not responding, or filtered
                        // For common UDP services, assume open if no ICMP unreachable
                        if self.is_common_udp_service(port) {
                            debug!("UDP Port {}:{} might be open (timeout on common service)", ip, port);

                            let service = self.detect_service(ip, port, Protocol::Udp).await.ok();

                            Ok(Some(Port {
                                number: port,
                                protocol: Protocol::Udp,
                                state: PortState::Open, // Assume open for common services
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

    /// Get UDP probe data for specific ports
    fn get_udp_probe(&self, port: u16) -> Vec<u8> {
        match port {
            53 => {
                // DNS query for "version.bind" TXT record
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
                // SNMP GetRequest for system.sysDescr.0
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
                    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
                    0x05, 0x00, // NULL
                ]
            }
            123 => {
                // NTP request
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
                // TFTP Read Request for "test"
                vec![
                    0x00, 0x01, // Opcode: Read Request
                    0x74, 0x65, 0x73, 0x74, 0x00, // Filename: "test"
                    0x6f, 0x63, 0x74, 0x65, 0x74, 0x00, // Mode: "octet"
                ]
            }
            _ => {
                // Generic UDP probe
                b"rscan_udp_probe".to_vec()
            }
        }
    }

    /// Check if port is a common UDP service
    fn is_common_udp_service(&self, port: u16) -> bool {
        matches!(port, 53 | 67 | 68 | 69 | 123 | 161 | 162 | 514 | 520 | 1812 | 1813)
    }

    /// Enhanced service detection with banner grabbing
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

        // Attempt banner grabbing for TCP services
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

    /// Grab service banner for version detection
    async fn grab_service_banner(&self, ip: IpAddr, port: u16) -> Result<(Option<String>, Option<String>)> {
        let addr = SocketAddr::new(ip, port);

        let mut stream = match timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok((None, None)),
        };

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Send appropriate probe based on service
        let probe = match port {
            21 | 22 | 25 | 110 | 143 | 993 | 995 => {
                // Services that send banner immediately
                None
            }
            80 | 8080 | 8000 => {
                // HTTP probe
                Some(b"HEAD / HTTP/1.0\r\n\r\n".to_vec())
            }
            443 => {
                // HTTPS - just try to connect, don't send data
                None
            }
            23 => {
                // Telnet
                Some(b"\r\n".to_vec())
            }
            _ => None,
        };

        // Send probe if needed
        if let Some(probe_data) = probe {
            let _ = stream.write_all(&probe_data).await;
        }

        // Read response
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

    /// Extract version information from banner
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

    /// Perform reverse DNS lookup
    async fn reverse_dns_lookup(&self, ip: IpAddr) -> Result<String> {
        use std::net::ToSocketAddrs;

        // Simple reverse DNS lookup
        match tokio::task::spawn_blocking(move || {
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
