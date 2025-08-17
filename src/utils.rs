use crate::{Result, ScanError};
use log::{debug, info};
use std::net::IpAddr;
use std::path::Path;
use tokio::fs;

/// Network utilities
pub mod network {
    use super::*;
    use std::net::Ipv4Addr;

    /// Check if an IP address is in a private range
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unicast_link_local() || ipv6.is_unique_local()
            }
        }
    }

    /// Check if an IP address is valid for scanning
    pub fn is_valid_scan_target(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                !ipv4.is_unspecified() && 
                !ipv4.is_broadcast() && 
                !ipv4.is_multicast() &&
                !ipv4.is_documentation()
            }
            IpAddr::V6(ipv6) => {
                !ipv6.is_unspecified() && 
                !ipv6.is_multicast()
            }
        }
    }

    /// Get the network address for a given IP and prefix length
    pub fn get_network_address(ip: Ipv4Addr, prefix_len: u8) -> Result<Ipv4Addr> {
        if prefix_len > 32 {
            return Err(ScanError::InvalidTarget("Invalid prefix length".to_string()));
        }
        
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        let network = u32::from(ip) & mask;
        Ok(Ipv4Addr::from(network))
    }

    /// Calculate the number of hosts in a subnet
    pub fn calculate_host_count(prefix_len: u8) -> Result<u32> {
        if prefix_len > 32 {
            return Err(ScanError::InvalidTarget("Invalid prefix length".to_string()));
        }
        
        if prefix_len == 32 {
            Ok(1)
        } else if prefix_len == 31 {
            Ok(2)
        } else {
            Ok((1u32 << (32 - prefix_len)) - 2) // Subtract network and broadcast
        }
    }
}

/// File and wordlist utilities
pub mod wordlist {
    use super::*;

    /// Load a wordlist from file
    pub async fn load_wordlist(path: &Path) -> Result<Vec<String>> {
        if !path.exists() {
            return Err(ScanError::Unknown(format!("Wordlist file not found: {}", path.display())));
        }

        let content = fs::read_to_string(path).await
            .map_err(|e| ScanError::Unknown(format!("Failed to read wordlist: {}", e)))?;

        let words: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        info!("Loaded {} words from {}", words.len(), path.display());
        Ok(words)
    }

    /// Generate common username list
    pub fn generate_common_usernames() -> Vec<String> {
        vec![
            "admin".to_string(),
            "administrator".to_string(),
            "root".to_string(),
            "user".to_string(),
            "guest".to_string(),
            "test".to_string(),
            "demo".to_string(),
            "sa".to_string(),
            "postgres".to_string(),
            "mysql".to_string(),
            "oracle".to_string(),
            "ftp".to_string(),
            "www".to_string(),
            "web".to_string(),
            "mail".to_string(),
            "email".to_string(),
            "service".to_string(),
            "support".to_string(),
            "backup".to_string(),
            "operator".to_string(),
        ]
    }

    /// Generate common password list
    pub fn generate_common_passwords() -> Vec<String> {
        vec![
            "".to_string(), // Empty password
            "password".to_string(),
            "123456".to_string(),
            "admin".to_string(),
            "root".to_string(),
            "guest".to_string(),
            "test".to_string(),
            "demo".to_string(),
            "12345".to_string(),
            "qwerty".to_string(),
            "abc123".to_string(),
            "password123".to_string(),
            "admin123".to_string(),
            "root123".to_string(),
            "welcome".to_string(),
            "login".to_string(),
            "pass".to_string(),
            "secret".to_string(),
            "changeme".to_string(),
            "default".to_string(),
        ]
    }

    /// Create default wordlist files
    pub async fn create_default_wordlists(base_dir: &Path) -> Result<()> {
        fs::create_dir_all(base_dir).await
            .map_err(|e| ScanError::Unknown(format!("Failed to create wordlist directory: {}", e)))?;

        // Create usernames wordlist
        let usernames_path = base_dir.join("usernames.txt");
        let usernames = generate_common_usernames();
        fs::write(&usernames_path, usernames.join("\n")).await
            .map_err(|e| ScanError::Unknown(format!("Failed to write usernames wordlist: {}", e)))?;

        // Create passwords wordlist
        let passwords_path = base_dir.join("passwords.txt");
        let passwords = generate_common_passwords();
        fs::write(&passwords_path, passwords.join("\n")).await
            .map_err(|e| ScanError::Unknown(format!("Failed to write passwords wordlist: {}", e)))?;

        info!("Created default wordlists in {}", base_dir.display());
        Ok(())
    }
}

/// Progress reporting utilities
pub mod progress {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;
    use colored::*;

    pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
        let pb = ProgressBar::new(total);
        
        // Enhanced progress bar style with cleaner formatting
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} [{bar:25.green/bright_black}] {pos:>3}/{len:3} {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }

    pub fn create_spinner(message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        
        // Clean spinner style
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("  {spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }
    
    /// Create a compact progress indicator for batch operations
    pub fn create_compact_bar(total: u64, prefix: &str) -> ProgressBar {
        let pb = ProgressBar::new(total);
        
        pb.set_style(
            ProgressStyle::default_bar()
                .template(&format!("  {} [{{bar:20.cyan/bright_black}}] {{pos}}/{{len}}", prefix.bright_blue()))
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        
        pb.enable_steady_tick(Duration::from_millis(150));
        pb
    }
}

/// Banner and service detection utilities
pub mod banner {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    /// Grab banner from a service
    pub async fn grab_banner(target: IpAddr, port: u16, probe: Option<&str>) -> Result<Option<String>> {
        let addr = SocketAddr::new(target, port);
        
        let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addr))
            .await
            .map_err(|_| ScanError::Timeout { operation: "TCP connect".to_string() })?
            .map_err(ScanError::Network)?;

        // Send probe if provided
        if let Some(probe_data) = probe {
            stream.write_all(probe_data.as_bytes()).await
                .map_err(ScanError::Network)?;
        }

        // Read response
        let mut buffer = vec![0; 1024];
        match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                if !banner.is_empty() {
                    debug!("Banner from {}:{}: {}", target, port, banner);
                    Ok(Some(banner))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Get HTTP banner
    pub async fn grab_http_banner(target: IpAddr, port: u16, use_https: bool) -> Result<Option<String>> {
        let scheme = if use_https { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, target, port);
        
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(ScanError::Http)?;

        match client.head(&url).send().await {
            Ok(response) => {
                let server = response.headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                
                debug!("HTTP banner from {}: {:?}", url, server);
                Ok(server)
            }
            Err(_) => Ok(None),
        }
    }
}

/// Encoding and decoding utilities
pub mod encoding {
    use base64::{Engine as _, engine::general_purpose};

    /// Base64 encode
    pub fn base64_encode(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    /// Base64 decode
    pub fn base64_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(data)
    }

    /// Hex encode
    pub fn hex_encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// Hex decode
    pub fn hex_decode(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
        hex::decode(data)
    }
}

/// Time and formatting utilities
pub mod time {
    use chrono::{DateTime, Utc};
    use std::time::{Duration, SystemTime};

    /// Get current UTC timestamp
    pub fn now_utc() -> DateTime<Utc> {
        Utc::now()
    }

    /// Format duration as human readable string
    pub fn format_duration(duration: Duration) -> String {
        let secs = duration.as_secs();
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;

        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }

    /// Calculate elapsed time since start
    pub fn elapsed_since(start: SystemTime) -> Duration {
        SystemTime::now().duration_since(start).unwrap_or_default()
    }
}

/// Performance optimization utilities
pub mod performance {
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use std::collections::HashMap;
    use std::hash::Hash;
    use parking_lot::RwLock;
    use std::time::{Duration, Instant};

    /// Simple LRU cache for DNS lookups and other expensive operations
    pub struct SimpleCache<K, V> {
        data: Arc<RwLock<HashMap<K, (V, Instant)>>>,
        ttl: Duration,
        max_size: usize,
    }

    impl<K: Clone + Hash + Eq, V: Clone> SimpleCache<K, V> {
        pub fn new(max_size: usize, ttl: Duration) -> Self {
            Self {
                data: Arc::new(RwLock::new(HashMap::new())),
                ttl,
                max_size,
            }
        }

        pub fn get(&self, key: &K) -> Option<V> {
            let data = self.data.read();
            if let Some((value, timestamp)) = data.get(key) {
                if timestamp.elapsed() < self.ttl {
                    return Some(value.clone());
                }
            }
            None
        }

        pub fn insert(&self, key: K, value: V) {
            let mut data = self.data.write();
            
            // Simple eviction: remove expired entries
            let now = Instant::now();
            data.retain(|_, (_, timestamp)| now.duration_since(*timestamp) < self.ttl);
            
            // If still too large, remove oldest entries
            if data.len() >= self.max_size {
                let oldest_key = data.iter()
                    .min_by_key(|(_, (_, timestamp))| *timestamp)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    data.remove(&key);
                }
            }
            
            data.insert(key, (value, now));
        }

        pub fn clear(&self) {
            self.data.write().clear();
        }
    }

    /// Rate limiter using token bucket algorithm
    pub struct RateLimiter {
        semaphore: Arc<Semaphore>,
        interval: Duration,
    }

    impl RateLimiter {
        pub fn new(max_concurrent: usize, requests_per_second: f64) -> Self {
            let interval = Duration::from_secs_f64(1.0 / requests_per_second);
            Self {
                semaphore: Arc::new(Semaphore::new(max_concurrent)),
                interval,
            }
        }

        pub async fn acquire(&self) -> tokio::sync::SemaphorePermit<'_> {
            let permit = self.semaphore.acquire().await.unwrap();
            tokio::time::sleep(self.interval).await;
            permit
        }
    }

    /// Memory pool for reusing expensive objects
    pub struct ObjectPool<T> {
        objects: Arc<RwLock<Vec<T>>>,
        factory: Arc<dyn Fn() -> T + Send + Sync>,
        max_size: usize,
    }

    impl<T> ObjectPool<T> {
        pub fn new<F>(factory: F, max_size: usize) -> Self 
        where 
            F: Fn() -> T + Send + Sync + 'static,
        {
            Self {
                objects: Arc::new(RwLock::new(Vec::new())),
                factory: Arc::new(factory),
                max_size,
            }
        }

        pub fn get(&self) -> T {
            let mut objects = self.objects.write();
            objects.pop().unwrap_or_else(|| (self.factory)())
        }

        pub fn return_object(&self, obj: T) {
            let mut objects = self.objects.write();
            if objects.len() < self.max_size {
                objects.push(obj);
            }
        }
    }

    /// Batch processor for efficient bulk operations
    pub struct BatchProcessor<T> {
        batch_size: usize,
        timeout: Duration,
        buffer: Arc<RwLock<Vec<T>>>,
    }

    impl<T> BatchProcessor<T> {
        pub fn new(batch_size: usize, timeout: Duration) -> Self {
            Self {
                batch_size,
                timeout,
                buffer: Arc::new(RwLock::new(Vec::new())),
            }
        }

        pub async fn add(&self, item: T) -> Option<Vec<T>> {
            let mut buffer = self.buffer.write();
            buffer.push(item);
            
            if buffer.len() >= self.batch_size {
                let batch = buffer.drain(..).collect();
                Some(batch)
            } else {
                None
            }
        }

        pub fn flush(&self) -> Vec<T> {
            let mut buffer = self.buffer.write();
            buffer.drain(..).collect()
        }
    }
}
