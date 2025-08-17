use clap::{Parser, Subcommand, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rscan")]
#[command(about = "Comprehensive internal network scanning tool for vulnerability assessment")]
#[command(long_about = r#"
Rscan is a comprehensive internal network scanning tool designed for ethical 
penetration testing and security assessment purposes.

WARNING: This tool should only be used on networks and systems you own or 
have explicit permission to test. Unauthorized scanning may be illegal.

Simple Usage Examples:
  rscan --host 192.168.1.0/24                 # Quick discovery scan
  rscan --host 192.168.1.100 -p 80,443        # Port scan specific ports  
  rscan --host 192.168.1.100 -m web           # Web application scan
  rscan --host 192.168.1.100 -m vuln          # Vulnerability scan
  rscan --host 192.168.1.100 -m all           # Full comprehensive scan
  rscan --host 192.168.1.100 -m ssh           # SSH brute force
  rscan --host 192.168.1.100 --fast           # Fast aggressive scan
  rscan --host 192.168.1.100 --stealth        # Stealth mode scan
"#)]
#[command(version)]
#[command(author)]
pub struct Cli {
    /// Target IP address, range, or CIDR notation (e.g., 192.168.1.1, 192.168.1.0/24)
    #[arg(long = "host", value_name = "TARGET")]
    pub target: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Port range for scanning (e.g., 80,443 or 1-1000)
    #[arg(short, long, value_name = "PORTS")]
    pub ports: Option<String>,

    /// Scan mode: web, vuln, all, ssh, ftp, rdp, mysql, etc.
    #[arg(short, long, value_name = "MODE")]
    pub mode: Option<String>,

    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Verbose output (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Quiet mode (suppress output)
    #[arg(short, long)]
    pub quiet: bool,

    /// Number of concurrent threads
    #[arg(long, default_value = "50")]
    pub threads: usize,

    /// Request timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Output directory
    #[arg(short, long, default_value = "./reports")]
    pub output: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    pub format: OutputFormat,

    /// Enable stealth mode (slower but more evasive)
    #[arg(long)]
    pub stealth: bool,

    /// Fast mode (aggressive scanning)
    #[arg(long)]
    pub fast: bool,

    /// Skip host discovery (assume targets are alive)
    #[arg(long)]
    pub no_ping: bool,

    /// Username for authentication
    #[arg(short, long)]
    pub username: Option<String>,

    /// Password for authentication
    #[arg(long)]
    pub password: Option<String>,

    /// Wordlist file for brute force
    #[arg(short, long)]
    pub wordlist: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Network discovery and host enumeration
    Discovery {
        /// Target IP address, range, or CIDR notation
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Ping timeout in milliseconds
        #[arg(long, default_value = "1000")]
        ping_timeout: u64,

        /// Skip ping and assume hosts are alive
        #[arg(long)]
        skip_ping: bool,

        /// DNS resolution
        #[arg(long)]
        dns_resolve: bool,
    },

    /// Port scanning
    PortScan {
        /// Target IP addresses
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Port range (e.g., 1-1000, 80,443,8080)
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Scan type
        #[arg(long, value_enum, default_value = "tcp")]
        scan_type: ScanType,

        /// Service detection
        #[arg(long)]
        service_detection: bool,

        /// Banner grabbing
        #[arg(long)]
        banner_grab: bool,
    },

    /// Brute force authentication
    BruteForce {
        /// Target IP addresses
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Service to brute force
        #[arg(short, long, value_enum)]
        service: Option<ServiceType>,

        /// Username wordlist
        #[arg(short, long)]
        usernames: Option<PathBuf>,

        /// Password wordlist
        #[arg(short, long)]
        passwords: Option<PathBuf>,

        /// Single username
        #[arg(long)]
        username: Option<String>,

        /// Single password
        #[arg(long)]
        password: Option<String>,

        /// Maximum attempts per target
        #[arg(long, default_value = "1000")]
        max_attempts: u32,

        /// Delay between attempts in milliseconds
        #[arg(long, default_value = "100")]
        delay: u64,
    },

    /// Web application scanning
    WebScan {
        /// Target URLs
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Technology fingerprinting
        #[arg(long)]
        fingerprint: bool,

        /// Directory brute forcing
        #[arg(long)]
        dir_brute: bool,

        /// Vulnerability scanning
        #[arg(long)]
        vuln_scan: bool,

        /// Custom wordlist for directory brute forcing
        #[arg(long)]
        wordlist: Option<PathBuf>,
    },

    /// Vulnerability scanning
    VulnScan {
        /// Target IP addresses
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Specific vulnerability checks
        #[arg(long)]
        checks: Option<Vec<String>>,

        /// Skip MS17-010 check
        #[arg(long)]
        skip_ms17_010: bool,

        /// Skip SMB enumeration
        #[arg(long)]
        skip_smb: bool,
    },

    /// Exploitation module
    Exploit {
        /// Target IP addresses
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Exploit type
        #[arg(short, long, value_enum)]
        exploit_type: ExploitType,

        /// Payload options
        #[arg(long)]
        payload: Option<String>,

        /// Reverse shell IP
        #[arg(long)]
        lhost: Option<IpAddr>,

        /// Reverse shell port
        #[arg(long)]
        lport: Option<u16>,
    },

    /// Proof-of-Concept vulnerability exploitation
    Poc {
        /// Target IP addresses
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// POC type to execute
        #[arg(short = 'P', long, value_enum)]
        poc_type: PocType,

        /// Domain for domain-based attacks
        #[arg(long)]
        domain: Option<String>,

        /// Username for authentication-based POCs
        #[arg(long)]
        username: Option<String>,

        /// Password for authentication-based POCs
        #[arg(long)]
        password: Option<String>,

        /// Wordlist for password spraying
        #[arg(long)]
        wordlist: Option<PathBuf>,

        /// NTLM hash for pass-the-hash attacks
        #[arg(long)]
        ntlm_hash: Option<String>,

        /// Service Principal Name for Kerberoasting
        #[arg(long)]
        spn: Option<String>,

        /// Output file for captured hashes/tickets
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Network interface for network-based attacks
        #[arg(long)]
        interface: Option<String>,

        /// Safe mode (simulation only)
        #[arg(long)]
        safe_mode: bool,
    },

    /// Full comprehensive scan
    FullScan {
        /// Target IP address, range, or CIDR notation
        #[arg(short, long, required = true)]
        target: Vec<String>,

        /// Skip discovery phase
        #[arg(long)]
        skip_discovery: bool,

        /// Skip port scanning
        #[arg(long)]
        skip_port_scan: bool,

        /// Skip vulnerability scanning
        #[arg(long)]
        skip_vuln_scan: bool,

        /// Skip brute force attacks
        #[arg(long)]
        skip_brute_force: bool,

        /// Skip web scanning
        #[arg(long)]
        skip_web_scan: bool,

        /// Enable exploitation
        #[arg(long)]
        enable_exploit: bool,

        /// Output directory for reports
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "html")]
        format: OutputFormat,
    },
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Json,
    Csv,
    Html,
    Xml,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ScanType {
    Tcp,
    Udp,
    Both,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ServiceType {
    Ssh,
    Ftp,
    Telnet,
    Smb,
    Rdp,
    Mysql,
    Postgres,
    Mssql,
    Redis,
    Oracle,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ExploitType {
    // SMB exploits
    Ms17010,
    Ms08067,
    SmbNullSession,
    NtlmRelay,
    
    // Domain exploits
    Kerberoasting,
    AsrepRoasting,
    GoldenTicket,
    SilverTicket,
    Zerologon,
    Dcsync,
    
    // Network exploits
    LlmnrPoisoning,
    Mitm6,
    ResponderAttack,
    ArpSpoofing,
    
    // Service exploits
    Redis,
    Ssh,
    
    // Web exploits
    SqlInjection,
    XssAttack,
    Lfi,
    Rfi,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum PocType {
    // Windows/SMB POCs
    EternalBlue,        // MS17-010 EternalBlue exploit
    BlueKeep,          // CVE-2019-0708 RDP vulnerability
    SmbGhost,          // CVE-2020-0796 SMBv3 vulnerability
    PrintNightmare,    // CVE-2021-34527 Print Spooler
    ZeroLogon,         // CVE-2020-1472 Netlogon vulnerability
    
    // Domain/Kerberos POCs
    Kerberoasting,     // Extract service account tickets
    AsrepRoasting,     // Attack accounts without pre-auth
    GoldenTicket,      // Create golden tickets
    SilverTicket,      // Create silver tickets
    DcsyncAttack,      // DCSync to extract hashes
    PassTheHash,       // Pass-the-hash attacks
    PassTheTicket,     // Pass-the-ticket attacks
    
    // Network/Protocol POCs
    LlmnrPoisoning,    // LLMNR/NBT-NS poisoning
    Mitm6Attack,       // IPv6 DNS takeover
    ResponderAttack,   // Multi-protocol poisoning
    ArpSpoofing,       // ARP spoofing attack
    DhcpStarvation,    // DHCP starvation attack
    
    // Database POCs
    SqlInjection,      // SQL injection attacks
    MysqlUdf,          // MySQL UDF exploitation
    PostgresRce,       // PostgreSQL RCE
    OraclePrivesc,     // Oracle privilege escalation
    
    // Web Application POCs
    XssReflected,      // Reflected XSS
    XssStored,         // Stored XSS
    CsrfAttack,        // Cross-Site Request Forgery
    LfiAttack,         // Local File Inclusion
    RfiAttack,         // Remote File Inclusion
    SsrfAttack,        // Server-Side Request Forgery
    
    // Service-specific POCs
    RedisRce,          // Redis RCE via config
    ElasticsearchRce,  // Elasticsearch RCE
    JenkinsRce,        // Jenkins RCE
    TomcatDeploy,      // Tomcat WAR deployment
    
    // Linux POCs
    DirtyPipe,         // CVE-2022-0847 Linux privilege escalation
    PwnKit,            // CVE-2021-4034 Polkit privilege escalation
    SudoBypass,        // Sudo bypass vulnerabilities
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::Ssh => write!(f, "ssh"),
            ServiceType::Ftp => write!(f, "ftp"),
            ServiceType::Telnet => write!(f, "telnet"),
            ServiceType::Smb => write!(f, "smb"),
            ServiceType::Rdp => write!(f, "rdp"),
            ServiceType::Mysql => write!(f, "mysql"),
            ServiceType::Postgres => write!(f, "postgres"),
            ServiceType::Mssql => write!(f, "mssql"),
            ServiceType::Redis => write!(f, "redis"),
            ServiceType::Oracle => write!(f, "oracle"),
        }
    }
}
