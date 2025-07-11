//! Evasion and Stealth Module
//! 
//! This module provides various techniques to evade detection by security devices
//! including firewalls, IDS/IPS, and other network monitoring systems.
//! 
//! # Warning
//! These techniques should only be used for authorized penetration testing and
//! security assessment purposes.

use crate::{Result, ScanError};
use crate::config::Config;
use async_trait::async_trait;
use fastrand::Rng;
use log::{debug, info, warn};
use parking_lot::RwLock;
use reqwest::{Client, Proxy};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

/// Main evasion engine that coordinates all stealth techniques
pub struct EvasionEngine {
    config: Config,
    rng: Arc<RwLock<Rng>>,
    user_agents: Vec<String>,
    proxy_chain: Vec<ProxyConfig>,
    timing_profile: TimingProfile,
    traffic_mixer: TrafficMixer,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub enum ProxyType {
    Http,
    Https,
    Socks5,
    Tor,
}

#[derive(Debug, Clone)]
pub struct TimingProfile {
    pub min_delay: Duration,
    pub max_delay: Duration,
    pub jitter_factor: f64,
    pub burst_size: u32,
    pub burst_delay: Duration,
}

/// Traffic mixer for generating decoy traffic and mimicking normal user behavior
pub struct TrafficMixer {
    decoy_targets: Vec<String>,
    normal_patterns: Vec<TrafficPattern>,
}

#[derive(Debug, Clone)]
pub struct TrafficPattern {
    pub name: String,
    pub requests: Vec<HttpRequest>,
    pub timing: Duration,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl EvasionEngine {
    pub fn new(config: Config) -> Result<Self> {
        let rng = Arc::new(RwLock::new(Rng::new()));
        
        Ok(Self {
            config: config.clone(),
            rng,
            user_agents: Self::load_user_agents(),
            proxy_chain: Self::load_proxy_config(&config)?,
            timing_profile: Self::create_timing_profile(&config),
            traffic_mixer: TrafficMixer::new(),
        })
    }

    /// Load realistic user agents for traffic masquerading
    fn load_user_agents() -> Vec<String> {
        vec![
            // Windows Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36".to_string(),
            
            // Windows Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0".to_string(),
            
            // Windows Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".to_string(),
            
            // macOS Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15".to_string(),
            
            // Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0".to_string(),
            
            // Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1".to_string(),
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36".to_string(),
        ]
    }

    /// Load proxy configuration from config
    fn load_proxy_config(config: &Config) -> Result<Vec<ProxyConfig>> {
        let mut proxies = Vec::new();
        
        // Add configured proxies from config
        if let Some(http_proxy) = &config.evasion.http_proxy {
            if let Ok(url) = Url::parse(http_proxy) {
                proxies.push(ProxyConfig {
                    proxy_type: ProxyType::Http,
                    address: url.host_str().unwrap_or("").to_string(),
                    port: url.port().unwrap_or(8080),
                    username: if !url.username().is_empty() { Some(url.username().to_string()) } else { None },
                    password: url.password().map(|p| p.to_string()),
                    enabled: true,
                });
            }
        }

        if let Some(socks_proxy) = &config.evasion.socks_proxy {
            if let Ok(url) = Url::parse(socks_proxy) {
                proxies.push(ProxyConfig {
                    proxy_type: ProxyType::Socks5,
                    address: url.host_str().unwrap_or("").to_string(),
                    port: url.port().unwrap_or(1080),
                    username: if !url.username().is_empty() { Some(url.username().to_string()) } else { None },
                    password: url.password().map(|p| p.to_string()),
                    enabled: true,
                });
            }
        }

        // Add TOR proxy if enabled
        if config.evasion.use_tor {
            proxies.push(ProxyConfig {
                proxy_type: ProxyType::Tor,
                address: "127.0.0.1".to_string(),
                port: 9050,
                username: None,
                password: None,
                enabled: true,
            });
        }

        Ok(proxies)
    }

    /// Create timing profile based on configuration
    fn create_timing_profile(config: &Config) -> TimingProfile {
        let timing_template = config.evasion.timing_template;
        
        match timing_template {
            1 => TimingProfile { // Paranoid - very slow
                min_delay: Duration::from_millis(5000),
                max_delay: Duration::from_millis(15000),
                jitter_factor: 0.8,
                burst_size: 1,
                burst_delay: Duration::from_millis(30000),
            },
            2 => TimingProfile { // Sneaky - slow
                min_delay: Duration::from_millis(2000),
                max_delay: Duration::from_millis(8000),
                jitter_factor: 0.6,
                burst_size: 2,
                burst_delay: Duration::from_millis(15000),
            },
            3 => TimingProfile { // Polite - normal
                min_delay: Duration::from_millis(1000),
                max_delay: Duration::from_millis(3000),
                jitter_factor: 0.4,
                burst_size: 3,
                burst_delay: Duration::from_millis(5000),
            },
            4 => TimingProfile { // Normal - fast
                min_delay: Duration::from_millis(500),
                max_delay: Duration::from_millis(1500),
                jitter_factor: 0.3,
                burst_size: 5,
                burst_delay: Duration::from_millis(2000),
            },
            5 => TimingProfile { // Aggressive - very fast
                min_delay: Duration::from_millis(100),
                max_delay: Duration::from_millis(500),
                jitter_factor: 0.2,
                burst_size: 10,
                burst_delay: Duration::from_millis(1000),
            },
            _ => TimingProfile { // Default
                min_delay: Duration::from_millis(1000),
                max_delay: Duration::from_millis(3000),
                jitter_factor: 0.4,
                burst_size: 3,
                burst_delay: Duration::from_millis(5000),
            },
        }
    }

    /// Get a random user agent
    pub fn get_random_user_agent(&self) -> String {
        let mut rng = self.rng.write();
        let index = rng.usize(0..self.user_agents.len());
        self.user_agents[index].clone()
    }

    /// Calculate random delay with jitter
    pub async fn random_delay(&self) {
        let mut rng = self.rng.write();
        let base_delay = rng.u64(
            self.timing_profile.min_delay.as_millis() as u64
                ..=self.timing_profile.max_delay.as_millis() as u64
        );
        
        // Apply jitter
        let jitter = (base_delay as f64 * self.timing_profile.jitter_factor * (rng.f64() - 0.5)) as u64;
        let final_delay = Duration::from_millis(base_delay.saturating_add_signed(jitter as i64));
        
        debug!("Applying evasion delay: {:?}", final_delay);
        drop(rng); // Release lock before sleeping
        sleep(final_delay).await;
    }

    /// Create HTTP client with proxy support
    pub async fn create_http_client(&self) -> Result<Client> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(self.config.web_scan.request_timeout))
            .danger_accept_invalid_certs(!self.config.web_scan.verify_ssl)
            .user_agent(self.get_random_user_agent());

        // Add proxy if configured
        if let Some(proxy_config) = self.get_random_proxy() {
            let proxy = self.create_proxy(proxy_config)?;
            client_builder = client_builder.proxy(proxy);
        }

        client_builder.build()
            .map_err(|e| ScanError::EvasionError(format!("Failed to create HTTP client: {}", e)))
    }

    /// Get a random proxy from the chain
    fn get_random_proxy(&self) -> Option<&ProxyConfig> {
        let enabled_proxies: Vec<&ProxyConfig> = self.proxy_chain.iter()
            .filter(|p| p.enabled)
            .collect();
        
        if enabled_proxies.is_empty() {
            return None;
        }

        let mut rng = self.rng.write();
        let index = rng.usize(0..enabled_proxies.len());
        Some(enabled_proxies[index])
    }

    /// Create reqwest Proxy from ProxyConfig
    fn create_proxy(&self, config: &ProxyConfig) -> Result<Proxy> {
        let proxy_url = match config.proxy_type {
            ProxyType::Http => format!("http://{}:{}", config.address, config.port),
            ProxyType::Https => format!("https://{}:{}", config.address, config.port),
            ProxyType::Socks5 | ProxyType::Tor => format!("socks5://{}:{}", config.address, config.port),
        };

        let mut proxy = Proxy::all(&proxy_url)
            .map_err(|e| ScanError::EvasionError(format!("Invalid proxy URL: {}", e)))?;

        // Add authentication if provided
        if let (Some(username), Some(password)) = (&config.username, &config.password) {
            proxy = proxy.basic_auth(username, password);
        }

        Ok(proxy)
    }

    /// Generate decoy traffic to mask real scanning activity
    pub async fn generate_decoy_traffic(&self, target_base: &str) -> Result<()> {
        if !self.config.evasion.generate_decoy_traffic {
            return Ok(());
        }

        info!("Generating decoy traffic to mask scanning activity");
        
        let client = self.create_http_client().await?;
        let patterns = &self.traffic_mixer.normal_patterns;
        
        // Generate 3-7 decoy requests
        let mut rng = self.rng.write();
        let num_requests = rng.usize(3..=7);
        drop(rng);

        for _ in 0..num_requests {
            if let Some(pattern) = self.get_random_pattern(patterns) {
                for request in &pattern.requests {
                    let url = format!("{}{}", target_base, request.path);
                    
                    let mut req_builder = match request.method.as_str() {
                        "GET" => client.get(&url),
                        "POST" => client.post(&url),
                        "HEAD" => client.head(&url),
                        _ => client.get(&url),
                    };

                    // Add headers
                    for (key, value) in &request.headers {
                        req_builder = req_builder.header(key, value);
                    }

                    // Add body if present
                    if let Some(body) = &request.body {
                        req_builder = req_builder.body(body.clone());
                    }

                    // Send request (ignore errors for decoy traffic)
                    if let Ok(_) = req_builder.send().await {
                        debug!("Sent decoy request to {}", url);
                    }

                    // Random delay between decoy requests
                    self.random_delay().await;
                }
            }
        }

        Ok(())
    }

    /// Get random traffic pattern
    fn get_random_pattern<'a>(&self, patterns: &'a [TrafficPattern]) -> Option<&'a TrafficPattern> {
        if patterns.is_empty() {
            return None;
        }
        let mut rng = self.rng.write();
        let index = rng.usize(0..patterns.len());
        Some(&patterns[index])
    }

    /// Fragment TCP packets to evade detection
    pub async fn fragment_packet(&self, _target: SocketAddr, _payload: &[u8]) -> Result<()> {
        // This would require raw socket implementation
        // For now, we'll implement this as a placeholder
        warn!("Packet fragmentation not yet implemented - requires raw socket privileges");
        Ok(())
    }

    /// Randomize source port for connections
    pub fn get_random_source_port(&self) -> u16 {
        let mut rng = self.rng.write();
        rng.u16(1024..=65535)
    }

    /// Generate random MAC address for spoofing
    pub fn generate_random_mac(&self) -> String {
        let mut rng = self.rng.write();
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            rng.u8(0x00..=0xff),
            rng.u8(0x00..=0xff),
            rng.u8(0x00..=0xff),
            rng.u8(0x00..=0xff),
            rng.u8(0x00..=0xff),
            rng.u8(0x00..=0xff)
        )
    }

    /// Check if we should apply rate limiting
    pub async fn should_rate_limit(&self, requests_in_window: u32) -> bool {
        if requests_in_window >= self.timing_profile.burst_size {
            sleep(self.timing_profile.burst_delay).await;
            true
        } else {
            false
        }
    }
}

impl Default for TrafficMixer {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMixer {
    pub fn new() -> Self {
        Self {
            decoy_targets: vec![
                "www.google.com".to_string(),
                "www.microsoft.com".to_string(),
                "www.cloudflare.com".to_string(),
                "www.amazon.com".to_string(),
                "www.github.com".to_string(),
            ],
            normal_patterns: Self::create_normal_patterns(),
        }
    }

    fn create_normal_patterns() -> Vec<TrafficPattern> {
        vec![
            // Browser-like behavior
            TrafficPattern {
                name: "Browser Navigation".to_string(),
                requests: vec![
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/".to_string(),
                        headers: Self::create_browser_headers(),
                        body: None,
                    },
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/favicon.ico".to_string(),
                        headers: Self::create_browser_headers(),
                        body: None,
                    },
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/robots.txt".to_string(),
                        headers: Self::create_browser_headers(),
                        body: None,
                    },
                ],
                timing: Duration::from_millis(2000),
            },
            // API-like behavior
            TrafficPattern {
                name: "API Access".to_string(),
                requests: vec![
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/api/health".to_string(),
                        headers: Self::create_api_headers(),
                        body: None,
                    },
                    HttpRequest {
                        method: "GET".to_string(),
                        path: "/api/version".to_string(),
                        headers: Self::create_api_headers(),
                        body: None,
                    },
                ],
                timing: Duration::from_millis(1000),
            },
        ]
    }

    fn create_browser_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8".to_string());
        headers.insert("Accept-Language".to_string(), "en-US,en;q=0.5".to_string());
        headers.insert("Accept-Encoding".to_string(), "gzip, deflate".to_string());
        headers.insert("DNT".to_string(), "1".to_string());
        headers.insert("Connection".to_string(), "keep-alive".to_string());
        headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
        headers
    }

    fn create_api_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Cache-Control".to_string(), "no-cache".to_string());
        headers
    }
}

/// Trait for objects that support evasion techniques
#[async_trait]
pub trait EvasionCapable {
    async fn apply_evasion(&mut self, engine: &EvasionEngine) -> Result<()>;
}

/// Error types specific to evasion functionality
#[derive(Debug)]
pub enum EvasionError {
    ProxyError(String),
    TimingError(String),
    TrafficError(String),
    FragmentationError(String),
}

impl std::fmt::Display for EvasionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvasionError::ProxyError(msg) => write!(f, "Proxy error: {}", msg),
            EvasionError::TimingError(msg) => write!(f, "Timing error: {}", msg),
            EvasionError::TrafficError(msg) => write!(f, "Traffic error: {}", msg),
            EvasionError::FragmentationError(msg) => write!(f, "Fragmentation error: {}", msg),
        }
    }
}

impl std::error::Error for EvasionError {} 