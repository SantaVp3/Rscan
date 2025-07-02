# 🔒 Rscan - Comprehensive Network Security Scanner

Rscan is a powerful, fast, and comprehensive internal network scanning tool written in Rust. It provides automated vulnerability assessment capabilities for ethical penetration testing and security assessment purposes.

## ⚠️ **IMPORTANT DISCLAIMER**

**This tool is designed for authorized security testing only. Users are responsible for ensuring they have proper permission before scanning any networks or systems. Unauthorized scanning may be illegal and could result in criminal charges. Always obtain explicit written permission before using this tool.**

## 🚀 Features

### Network Discovery & Information Gathering
- **ICMP-based host discovery** to identify live hosts on the network
- **Comprehensive port scanner** with TCP and UDP support
- **Service detection** to identify services running on open ports
- **Configurable timeouts and threading** for optimal performance
- **IPv4 and IPv6 support**

### Authentication Brute Force
- **SSH** (port 22) brute force attacks
- **SMB/CIFS** (ports 139, 445) authentication testing
- **RDP** (port 3389) credential testing
- **FTP** (port 21) and **Telnet** (port 23) brute forcing
- **Database services** support:
  - MySQL (port 3306)
  - Microsoft SQL Server (port 1433)
  - Redis (port 6379)
  - PostgreSQL (port 5432)
  - Oracle (port 1521)
- **Custom wordlist support** with built-in common credentials

### System Information & Vulnerability Detection
- **NetBIOS enumeration** and domain controller identification
- **MS17-010 (EternalBlue)** detection
- **SMB version detection** and security assessment
- **Default credential detection** across multiple services
- **Web vulnerability scanning** for common issues

### Evasion & Stealth Techniques 🥷
- **Traffic obfuscation** with realistic user-agent rotation
- **Timing randomization** with configurable jitter and delays
- **Proxy chain support** for HTTP, SOCKS5, and TOR networks
- **Decoy traffic generation** to mask scanning activity
- **Request header randomization** to avoid fingerprinting
- **Source port randomization** for network-level evasion
- **Rate limiting with burst patterns** to mimic human behavior
- **Configurable timing templates** (Paranoid to Aggressive modes)

### Web Application Assessment
- **HTTP/HTTPS service detection** and banner grabbing
- **Website title extraction** and technology fingerprinting
- **CMS detection** (WordPress, Drupal, Joomla)
- **Framework identification** (React, Angular, Vue.js, PHP, ASP.NET)
- **Directory brute forcing** with common wordlists
- **Common vulnerability checks** (exposed files, directory traversal)

### Exploitation Capabilities
- **Redis exploitation**:
  - SSH public key injection
  - Cron job/scheduled task injection
- **SSH command execution** for authenticated sessions
- **MS17-010 exploitation framework** (placeholder for safety)
- **Reverse shell payload generation**

### Output & Reporting
- **Multiple output formats**: JSON, CSV, HTML, XML
- **Comprehensive HTML reports** with CSS styling
- **Real-time progress reporting** with progress bars
- **Vulnerability classification** and risk assessment
- **Executive summary generation**

## 📦 Installation

### Prerequisites
- Rust 1.70 or later
- Cargo package manager

### Building from Source
```bash
git clone https://github.com/your-org/rscan.git
cd rscan
cargo build --release
```

### Running
```bash
# Run with default configuration
./target/release/rscan --help

# Or use cargo run for development
cargo run -- --help
```

## 🛠️ Usage

### Basic Commands

#### Network Discovery
```bash
# Discover live hosts in a subnet
rscan discovery -t 192.168.1.0/24

# Discover specific IP range
rscan discovery -t 192.168.1.1-192.168.1.100

# Skip ping and assume hosts are alive
rscan discovery -t 192.168.1.0/24 --skip-ping
```

#### Port Scanning
```bash
# Scan common ports
rscan port-scan -t 192.168.1.100

# Scan specific port range
rscan port-scan -t 192.168.1.100 -p 1-1000

# Scan with service detection
rscan port-scan -t 192.168.1.100 --service-detection

# Scan multiple targets
rscan port-scan -t 192.168.1.100,192.168.1.101,192.168.1.102
```

#### Brute Force Attacks
```bash
# SSH brute force with default wordlists
rscan brute-force -t 192.168.1.100 -s ssh

# MySQL brute force with custom wordlists
rscan brute-force -t 192.168.1.100 -s mysql -u usernames.txt -p passwords.txt

# Single credential test
rscan brute-force -t 192.168.1.100 -s ssh --username admin --password password123
```

#### Web Application Scanning
```bash
# Basic web scan
rscan web-scan -t http://192.168.1.100

# Web scan with technology fingerprinting
rscan web-scan -t http://192.168.1.100 --fingerprint

# Web scan with directory brute forcing
rscan web-scan -t http://192.168.1.100 --dir-brute

# Comprehensive web vulnerability scan
rscan web-scan -t http://192.168.1.100 --fingerprint --dir-brute --vuln-scan
```

#### Vulnerability Scanning
```bash
# Full vulnerability scan
rscan vuln-scan -t 192.168.1.100

# Skip specific checks
rscan vuln-scan -t 192.168.1.100 --skip-ms17-010 --skip-smb
```

#### Comprehensive Scanning
```bash
# Full automated scan
rscan full-scan -t 192.168.1.0/24

# Full scan with exploitation enabled (use with extreme caution)
rscan full-scan -t 192.168.1.0/24 --enable-exploit

# Customized full scan
rscan full-scan -t 192.168.1.0/24 --skip-brute-force --skip-web-scan
```

#### Evasion & Stealth Techniques
```bash
# Basic stealth scan with timing randomization
rscan web-scan -t http://target.com --enable-evasion --timing 2

# Paranoid mode with maximum stealth
rscan port-scan -t 192.168.1.100 --enable-evasion --timing 1

# Using TOR network for anonymity
rscan web-scan -t http://target.com --enable-evasion --use-tor

# HTTP proxy chain
rscan web-scan -t http://target.com --enable-evasion --http-proxy http://proxy:8080

# SOCKS5 proxy with decoy traffic
rscan web-scan -t http://target.com --enable-evasion --socks-proxy socks5://proxy:1080 --decoy-traffic

# Full stealth mode combining multiple techniques
rscan full-scan -t 192.168.1.0/24 --enable-evasion --timing 1 --use-tor --decoy-traffic
```

### Advanced Options

#### Configuration File
```bash
# Use custom configuration
rscan -c custom-config.toml discovery -t 192.168.1.0/24

# Generate default configuration
cp config.toml my-config.toml
# Edit my-config.toml as needed
```

#### Output and Reporting
```bash
# Specify output directory and format
rscan discovery -t 192.168.1.0/24 --output ./my-reports --format html

# Verbose output
rscan -vv discovery -t 192.168.1.0/24

# Quiet mode
rscan -q discovery -t 192.168.1.0/24
```

#### Performance Tuning
```bash
# Increase thread count for faster scanning
rscan --threads 200 port-scan -t 192.168.1.0/24

# Adjust timeout and rate limiting
rscan --timeout 60 --rate-limit 50 discovery -t 192.168.1.0/24
```

#### Evasion Configuration
```bash
# Enable stealth mode with custom timing
rscan web-scan -t http://target.com --enable-evasion --timing 1

# Configure proxy chain in config.toml
[evasion]
enabled = true
timing_template = 2
http_proxy = "http://proxy1.example.com:8080"
socks_proxy = "socks5://proxy2.example.com:1080"
use_tor = true
generate_decoy_traffic = true

# Timing templates:
# 1 = Paranoid (5-15s delays, max stealth)
# 2 = Sneaky (2-8s delays, high stealth)
# 3 = Polite (1-3s delays, moderate stealth)
# 4 = Normal (0.5-1.5s delays, low stealth)
# 5 = Aggressive (0.1-0.5s delays, minimal stealth)
```

## 📁 Project Structure

```
rscan/
├── src/
│   ├── main.rs              # Main application entry point
│   ├── lib.rs               # Library root with common types
│   ├── cli.rs               # Command-line interface
│   ├── config.rs            # Configuration management
│   ├── discovery.rs         # Network discovery and port scanning
│   ├── brute_force.rs       # Authentication brute force attacks
│   ├── web_scan.rs          # Web application scanning
│   ├── vuln_scan.rs         # Vulnerability detection
│   ├── exploit.rs           # Exploitation capabilities
│   ├── reporting.rs         # Report generation
│   ├── utils.rs             # Utility functions
│   └── error.rs             # Error handling
├── assets/
│   └── report.css           # CSS styles for HTML reports
├── wordlists/
│   ├── usernames.txt        # Default username wordlist
│   └── passwords.txt        # Default password wordlist
├── config.toml              # Default configuration file
├── Cargo.toml               # Rust project configuration
└── README.md                # This file
```

## ⚙️ Configuration

Rscan uses a TOML configuration file for customizing scan parameters. The default configuration file `config.toml` includes:

- **Scan settings**: threads, timeouts, rate limiting
- **Discovery options**: ping timeouts, port lists
- **Brute force parameters**: attempt limits, delays
- **Web scan configuration**: redirects, SSL verification
- **Exploitation settings**: payload timeouts, reverse shell config
- **Reporting options**: output formats, compression
- **Wordlist paths**: custom username/password lists

## 🔧 Dependencies

Key Rust crates used in this project:

- **tokio**: Async runtime for concurrent operations
- **clap**: Command-line argument parsing
- **reqwest**: HTTP client for web scanning
- **ssh2**: SSH client for brute force and command execution
- **mysql_async**, **tokio-postgres**, **redis**, **tiberius**: Database clients
- **serde**: Serialization for configuration and reporting
- **surge-ping**: ICMP ping implementation
- **scraper**: HTML parsing for web scanning

## 🛡️ Security Considerations

1. **Authorization**: Always obtain explicit written permission before scanning
2. **Rate Limiting**: Use appropriate delays to avoid overwhelming target systems
3. **Logging**: All activities are logged for audit purposes
4. **Exploitation**: Exploitation features are disabled by default and should only be enabled in controlled environments
5. **Network Impact**: Be mindful of network bandwidth and system resources

## 🤝 Contributing

Contributions are welcome! Please ensure that any contributions:

1. Follow Rust best practices and coding standards
2. Include appropriate tests
3. Update documentation as needed
4. Maintain the ethical use focus of the project

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚖️ Legal Notice

This tool is provided for educational and authorized testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users are solely responsible for ensuring they have proper authorization before using this tool on any network or system.

## 🔗 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
