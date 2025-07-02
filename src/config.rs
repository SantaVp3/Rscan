use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    pub discovery: DiscoveryConfig,
    pub brute_force: BruteForceConfig,
    pub web_scan: WebScanConfig,
    pub exploit: ExploitConfig,
    pub reporting: ReportingConfig,
    pub wordlists: WordlistConfig,
    pub evasion: EvasionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub threads: usize,
    pub timeout: u64, // seconds
    pub rate_limit: u64, // requests per second
    pub retries: u32,
    pub user_agent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
    pub ping_timeout: Duration,
    pub preferred_strategy: Option<String>,
    pub force_icmp: bool,
    pub enable_arp: bool,
    pub system_ping_fallback: bool,
    pub priority_tcp_ports: Vec<u16>,
    pub common_tcp_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    pub max_attempts: u32,
    pub delay_between_attempts: u64, // milliseconds
    pub connection_timeout: u64, // seconds
    pub enabled_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScanConfig {
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub request_timeout: u64, // seconds
    pub verify_ssl: bool,
    pub custom_headers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitConfig {
    pub enabled: bool,
    pub auto_exploit: bool,
    pub payload_timeout: u64, // seconds
    pub reverse_shell_ip: Option<IpAddr>,
    pub reverse_shell_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub output_dir: PathBuf,
    pub formats: Vec<OutputFormat>,
    pub include_raw_data: bool,
    pub compress_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistConfig {
    pub usernames: PathBuf,
    pub passwords: PathBuf,
    pub custom_wordlists: std::collections::HashMap<String, PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    pub enabled: bool,
    pub timing_template: u8, // 1-5 (1=paranoid, 5=aggressive)
    pub randomize_user_agents: bool,
    pub use_tor: bool,
    pub http_proxy: Option<String>,
    pub socks_proxy: Option<String>,
    pub proxy_rotation: bool,
    pub generate_decoy_traffic: bool,
    pub randomize_headers: bool,
    pub fragment_packets: bool,
    pub spoof_mac: Option<String>,
    pub source_port_randomization: bool,
    pub decoy_hosts: Vec<String>,
    pub max_request_rate: u64, // requests per second
    pub jitter_percentage: f64, // 0.0 - 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Csv,
    Html,
    Xml,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                threads: 100,
                timeout: 30,
                rate_limit: 100,
                retries: 3,
                user_agent: "Rscan/1.0".to_string(),
            },
            discovery: DiscoveryConfig {
                tcp_timeout: Duration::from_millis(5000),
                udp_timeout: Duration::from_millis(2000),
                ping_timeout: Duration::from_millis(1000),
                preferred_strategy: None,
                force_icmp: false,
                enable_arp: false,
                system_ping_fallback: false,
                priority_tcp_ports: vec![
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
                ],
                common_tcp_ports: vec![
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
                ],
            },
            brute_force: BruteForceConfig {
                max_attempts: 1000,
                delay_between_attempts: 100,
                connection_timeout: 10,
                enabled_services: vec![
                    "ssh".to_string(),
                    "ftp".to_string(),
                    "telnet".to_string(),
                    "smb".to_string(),
                    "rdp".to_string(),
                    "mysql".to_string(),
                    "postgres".to_string(),
                    "mssql".to_string(),
                    "redis".to_string(),
                    "oracle".to_string(),
                ],
            },
            web_scan: WebScanConfig {
                follow_redirects: true,
                max_redirects: 5,
                request_timeout: 10,
                verify_ssl: false,
                custom_headers: std::collections::HashMap::new(),
            },
            exploit: ExploitConfig {
                enabled: false,
                auto_exploit: false,
                payload_timeout: 30,
                reverse_shell_ip: None,
                reverse_shell_port: None,
            },
            reporting: ReportingConfig {
                output_dir: PathBuf::from("./reports"),
                formats: vec![OutputFormat::Json, OutputFormat::Html],
                include_raw_data: true,
                compress_output: false,
            },
            wordlists: WordlistConfig {
                usernames: PathBuf::from("./wordlists/usernames.txt"),
                passwords: PathBuf::from("./wordlists/passwords.txt"),
                custom_wordlists: std::collections::HashMap::new(),
            },
            evasion: EvasionConfig {
                enabled: false,
                timing_template: 3, // Normal timing
                randomize_user_agents: true,
                use_tor: false,
                http_proxy: None,
                socks_proxy: None,
                proxy_rotation: false,
                generate_decoy_traffic: false,
                randomize_headers: true,
                fragment_packets: false,
                spoof_mac: None,
                source_port_randomization: true,
                decoy_hosts: vec![
                    "www.google.com".to_string(),
                    "www.microsoft.com".to_string(),
                    "www.cloudflare.com".to_string(),
                ],
                max_request_rate: 10, // Conservative default
                jitter_percentage: 0.3,
            },
        }
    }
}

impl Config {
    pub fn load_from_file(path: &str) -> crate::Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()?;
        
        Ok(settings.try_deserialize()?)
    }

    pub fn save_to_file(&self, path: &str) -> crate::Result<()> {
        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| crate::ScanError::Unknown(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(path, toml_string)?;
        Ok(())
    }

    pub fn scan_timeout(&self) -> Duration {
        Duration::from_secs(self.scan.timeout)
    }

    pub fn ping_timeout(&self) -> Duration {
        self.discovery.ping_timeout
    }

    pub fn port_scan_timeout(&self) -> Duration {
        self.discovery.tcp_timeout
    }

    pub fn tcp_connect_timeout(&self) -> Duration {
        self.discovery.tcp_timeout
    }

    pub fn brute_force_delay(&self) -> Duration {
        Duration::from_millis(self.brute_force.delay_between_attempts)
    }
}
