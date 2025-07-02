use crate::{Result, ScanError};
use crate::types::{Vulnerability, Severity, VulnerabilityCategory};
use crate::config::Config;
use crate::utils::time::now_utc;
use chrono::Utc;
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct VulnerabilityScanner {
    config: Config,
    cve_database: HashMap<String, CveInfo>,
}

#[derive(Debug, Clone)]
struct CveInfo {
    id: String,
    description: String,
    cvss_score: f32,
    severity: Severity,
    category: VulnerabilityCategory,
    remediation: String,
    references: Vec<String>,
}

impl VulnerabilityScanner {
    pub fn new(config: Config) -> Self {
        let mut scanner = Self {
            config,
            cve_database: HashMap::new(),
        };
        scanner.initialize_cve_database();
        scanner
    }

    /// Initialize the CVE database with known vulnerabilities
    fn initialize_cve_database(&mut self) {
        // MS17-010 (EternalBlue)
        self.cve_database.insert("CVE-2017-0144".to_string(), CveInfo {
            id: "CVE-2017-0144".to_string(),
            description: "Microsoft Windows SMB Remote Code Execution Vulnerability (EternalBlue)".to_string(),
            cvss_score: 8.1,
            severity: Severity::High,
            category: VulnerabilityCategory::CodeExecution,
            remediation: "Apply Microsoft Security Bulletin MS17-010".to_string(),
            references: vec![
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144".to_string(),
                "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010".to_string(),
            ],
        });

        // Heartbleed
        self.cve_database.insert("CVE-2014-0160".to_string(), CveInfo {
            id: "CVE-2014-0160".to_string(),
            description: "OpenSSL Heartbeat Extension Information Disclosure (Heartbleed)".to_string(),
            cvss_score: 7.5,
            severity: Severity::High,
            category: VulnerabilityCategory::InformationDisclosure,
            remediation: "Update OpenSSL to version 1.0.1g or later".to_string(),
            references: vec![
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160".to_string(),
                "https://heartbleed.com/".to_string(),
            ],
        });

        // Shellshock
        self.cve_database.insert("CVE-2014-6271".to_string(), CveInfo {
            id: "CVE-2014-6271".to_string(),
            description: "GNU Bash Remote Code Execution Vulnerability (Shellshock)".to_string(),
            cvss_score: 9.8,
            severity: Severity::Critical,
            category: VulnerabilityCategory::CodeExecution,
            remediation: "Update Bash to a patched version".to_string(),
            references: vec![
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271".to_string(),
            ],
        });

        // Log4Shell
        self.cve_database.insert("CVE-2021-44228".to_string(), CveInfo {
            id: "CVE-2021-44228".to_string(),
            description: "Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell)".to_string(),
            cvss_score: 10.0,
            severity: Severity::Critical,
            category: VulnerabilityCategory::CodeExecution,
            remediation: "Update Log4j to version 2.17.0 or later, or remove JndiLookup class".to_string(),
            references: vec![
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228".to_string(),
                "https://logging.apache.org/log4j/2.x/security.html".to_string(),
            ],
        });

        // BlueKeep
        self.cve_database.insert("CVE-2019-0708".to_string(), CveInfo {
            id: "CVE-2019-0708".to_string(),
            description: "Windows Remote Desktop Services Remote Code Execution Vulnerability (BlueKeep)".to_string(),
            cvss_score: 9.8,
            severity: Severity::Critical,
            category: VulnerabilityCategory::CodeExecution,
            remediation: "Apply Windows security updates for CVE-2019-0708".to_string(),
            references: vec![
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708".to_string(),
            ],
        });
    }

    pub async fn scan_target(&self, target: IpAddr) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        info!("Starting vulnerability scan for {}", target);
        
        // Check for MS17-010 (EternalBlue)
        if let Ok(vuln) = self.check_ms17_010(target).await {
            if let Some(v) = vuln {
                vulnerabilities.push(v);
            }
        }
        
        // Check SMB vulnerabilities
        if let Ok(vulns) = self.check_smb_vulnerabilities(target).await {
            vulnerabilities.extend(vulns);
        }
        
        // Check for open Redis without authentication
        if let Ok(vuln) = self.check_redis_no_auth(target).await {
            if let Some(v) = vuln {
                vulnerabilities.push(v);
            }
        }
        
        // Check for default credentials on common services
        if let Ok(vulns) = self.check_default_credentials(target).await {
            vulnerabilities.extend(vulns);
        }
        
        // Additional vulnerability checks can be added here in the future

        Ok(vulnerabilities)
    }

    pub async fn check_ms17_010(&self, target: IpAddr) -> Result<Option<Vulnerability>> {
        debug!("Checking MS17-010 (EternalBlue) on {}", target);
        
        // Try to connect to SMB port
        let addr = SocketAddr::new(target, 445);
        
        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(None),
        };
        
        // This is a simplified check - in a real implementation, you would
        // send proper SMB packets to detect the vulnerability
        let is_vulnerable = self.send_ms17_010_probe(stream).await?;
        
        if is_vulnerable {
            Ok(Some(Vulnerability {
                id: "MS17-010".to_string(),
                name: "EternalBlue SMB Vulnerability".to_string(),
                description: "The target is vulnerable to MS17-010 (EternalBlue), which allows remote code execution".to_string(),
                severity: Severity::Critical,
                target,
                port: Some(445),
                evidence: Some("SMB service vulnerable to EternalBlue exploit".to_string()),
                discovered_at: Utc::now(),
                cvss_score: Some(8.1),
                cve_id: Some("CVE-2017-0144".to_string()),
                category: VulnerabilityCategory::CodeExecution,
                remediation: Some("Apply Microsoft Security Bulletin MS17-010".to_string()),
                references: vec![
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144".to_string(),
                    "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010".to_string(),
                ],
            }))
        } else {
            Ok(None)
        }
    }

    async fn send_ms17_010_probe(&self, mut stream: TcpStream) -> Result<bool> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // SMB Negotiate Protocol Request for MS17-010 detection
        let negotiate_request = vec![
            // NetBIOS Session Service header
            0x00, 0x00, 0x00, 0x85,
            // SMB Header
            0xff, 0x53, 0x4d, 0x42, // Protocol identifier "\xffSMB"
            0x72, // SMB command: Negotiate Protocol
            0x00, 0x00, 0x00, 0x00, // NT Status
            0x18, // Flags
            0x53, 0xc8, // Flags2
            0x00, 0x00, // Process ID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00, // Reserved
            0x00, 0x00, // Tree ID
            0x2f, 0x4b, // Process ID
            0x00, 0x00, // User ID
            0xc5, 0x5e, // Multiplex ID
            // SMB Parameters
            0x00, // Word Count
            // SMB Data
            0x62, 0x00, // Byte Count
            0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00,
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
        ];

        // Send negotiate request
        match timeout(Duration::from_secs(5), stream.write_all(&negotiate_request)).await {
            Ok(Ok(_)) => {
                let mut buffer = vec![0; 1024];
                match timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check for SMB response
                        if n >= 8 && &buffer[4..8] == b"\xffSMB" {
                            // Parse SMB response to check for vulnerability indicators
                            self.analyze_smb_response(&buffer[..n])
                        } else {
                            Ok(false)
                        }
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Analyze SMB response for MS17-010 vulnerability indicators
    fn analyze_smb_response(&self, response: &[u8]) -> Result<bool> {
        if response.len() < 36 {
            return Ok(false);
        }

        // Check SMB command response (should be 0x72 for Negotiate Protocol Response)
        if response[8] != 0x72 {
            return Ok(false);
        }

        // Check NT Status (offset 9-12)
        let nt_status = u32::from_le_bytes([response[9], response[10], response[11], response[12]]);

        // If NT_STATUS_SUCCESS (0x00000000), the server responded properly
        if nt_status == 0x00000000 {
            // Check for specific SMB dialect responses that indicate vulnerability
            // Look for older SMB dialects that are vulnerable to MS17-010

            // Parse Word Count and check for dialect index
            if response.len() > 37 {
                let word_count = response[36];
                if word_count >= 17 && response.len() > 73 {
                    let dialect_index = u16::from_le_bytes([response[37], response[38]]);

                    // Dialect indices for vulnerable SMB versions:
                    // 0-5: Various older dialects vulnerable to MS17-010
                    if dialect_index <= 5 {
                        debug!("Potential MS17-010 vulnerability detected (dialect index: {})", dialect_index);
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    async fn check_smb_vulnerabilities(&self, target: IpAddr) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        debug!("Checking SMB vulnerabilities on {}", target);
        
        // Check SMB v1 (deprecated and vulnerable)
        if self.is_smbv1_enabled(target).await? {
            vulnerabilities.push(Vulnerability {
                id: "SMB-V1-ENABLED".to_string(),
                name: "SMB v1 Protocol Enabled".to_string(),
                description: "SMB v1 is enabled, which is deprecated and has known security vulnerabilities".to_string(),
                severity: Severity::High,
                target,
                port: Some(445),
                evidence: Some("SMB v1 protocol is enabled and responding".to_string()),
                discovered_at: Utc::now(),
                cvss_score: Some(7.5),
                cve_id: None,
                category: VulnerabilityCategory::Configuration,
                remediation: Some("Disable SMB v1 protocol and use SMB v2 or later".to_string()),
                references: vec![
                    "https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3".to_string(),
                ],
            });
        }
        
        // Check for null session
        if self.check_null_session(target).await? {
            vulnerabilities.push(Vulnerability {
                id: "SMB-NULL-SESSION".to_string(),
                name: "SMB Null Session Allowed".to_string(),
                description: "SMB service allows null session authentication, potentially exposing sensitive information".to_string(),
                severity: Severity::Medium,
                target,
                port: Some(445),
                evidence: Some("Null session authentication successful".to_string()),
                discovered_at: Utc::now(),
                cvss_score: Some(5.3),
                cve_id: None,
                category: VulnerabilityCategory::Authentication,
                remediation: Some("Disable null session access and require proper authentication".to_string()),
                references: vec![
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares".to_string(),
                ],
            });
        }
        
        Ok(vulnerabilities)
    }

    async fn is_smbv1_enabled(&self, target: IpAddr) -> Result<bool> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = SocketAddr::new(target, 445);
        let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(false),
        };

        // SMB v1 Negotiate Protocol Request
        let smbv1_negotiate = vec![
            // NetBIOS Session Service header
            0x00, 0x00, 0x00, 0x54,
            // SMB Header
            0xff, 0x53, 0x4d, 0x42, // Protocol identifier "\xffSMB"
            0x72, // SMB command: Negotiate Protocol
            0x00, 0x00, 0x00, 0x00, // NT Status
            0x18, // Flags
            0x53, 0xc8, // Flags2
            0x00, 0x00, // Process ID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00, // Reserved
            0x00, 0x00, // Tree ID
            0x2f, 0x4b, // Process ID
            0x00, 0x00, // User ID
            0xc5, 0x5e, // Multiplex ID
            // SMB Parameters
            0x00, // Word Count
            // SMB Data
            0x31, 0x00, // Byte Count
            // Dialects (only SMB v1 dialects)
            0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
        ];

        match timeout(Duration::from_secs(5), stream.write_all(&smbv1_negotiate)).await {
            Ok(Ok(_)) => {
                let mut buffer = vec![0; 1024];
                match timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if server responds with SMB v1
                        if n >= 8 && &buffer[4..8] == b"\xffSMB" && buffer[8] == 0x72 {
                            // Check NT Status for success
                            let nt_status = u32::from_le_bytes([buffer[9], buffer[10], buffer[11], buffer[12]]);
                            Ok(nt_status == 0x00000000)
                        } else {
                            Ok(false)
                        }
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    pub async fn check_null_session(&self, target: IpAddr) -> Result<bool> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = SocketAddr::new(target, 445);
        let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(false),
        };

        // First, negotiate protocol
        let negotiate_request = vec![
            0x00, 0x00, 0x00, 0x85,
            0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x2f, 0x4b, 0x00, 0x00, 0xc5, 0x5e, 0x00, 0x62, 0x00,
            0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00,
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
        ];

        // Send negotiate
        if let Err(_) = stream.write_all(&negotiate_request).await {
            return Ok(false);
        }

        // Read negotiate response
        let mut buffer = vec![0; 1024];
        let negotiate_response_len = match timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(false),
        };

        // Check if negotiate was successful
        if negotiate_response_len < 36 || &buffer[4..8] != b"\xffSMB" {
            return Ok(false);
        }

        // Now attempt Session Setup with null credentials
        let session_setup = vec![
            0x00, 0x00, 0x00, 0x48, // NetBIOS header
            0xff, 0x53, 0x4d, 0x42, // SMB signature
            0x73, // Session Setup AndX
            0x00, 0x00, 0x00, 0x00, // NT Status
            0x18, // Flags
            0x07, 0xc8, // Flags2
            0x00, 0x00, // Process ID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00, // Reserved
            0x00, 0x00, // Tree ID
            0x2f, 0x4b, // Process ID
            0x00, 0x00, // User ID
            0xc6, 0x5e, // Multiplex ID
            // Parameters
            0x0d, // Word Count
            0xff, // AndXCommand: No further commands
            0x00, // Reserved
            0x00, 0x00, // AndXOffset
            0xdf, 0xff, // MaxBufferSize
            0x02, 0x00, // MaxMpxCount
            0x01, 0x00, // VcNumber
            0x00, 0x00, 0x00, 0x00, // SessionKey
            0x00, 0x00, // ANSI Password Length (null)
            0x00, 0x00, // Unicode Password Length (null)
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x40, 0x00, 0x00, 0x00, // Capabilities
            // Data
            0x00, 0x00, // Byte Count (null credentials)
        ];

        // Send session setup
        if let Err(_) = stream.write_all(&session_setup).await {
            return Ok(false);
        }

        // Read session setup response
        buffer.clear();
        buffer.resize(1024, 0);
        match timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                if n >= 12 && &buffer[4..8] == b"\xffSMB" && buffer[8] == 0x73 {
                    // Check NT Status
                    let nt_status = u32::from_le_bytes([buffer[9], buffer[10], buffer[11], buffer[12]]);
                    // STATUS_SUCCESS indicates null session is allowed
                    Ok(nt_status == 0x00000000)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }

    async fn check_redis_no_auth(&self, target: IpAddr) -> Result<Option<Vulnerability>> {
        debug!("Checking Redis authentication on {}", target);
        
        let addr = SocketAddr::new(target, 6379);
        
        let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(None),
        };
        
        // Send PING command without authentication
        let ping_cmd = b"*1\r\n$4\r\nPING\r\n";
        
        match timeout(Duration::from_secs(3), stream.write_all(ping_cmd)).await {
            Ok(Ok(_)) => {
                let mut buffer = vec![0; 1024];
                match timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        if response.contains("+PONG") {
                            return Ok(Some(Vulnerability {
                                id: "REDIS-NO-AUTH".to_string(),
                                name: "Redis No Authentication".to_string(),
                                description: "Redis server is accessible without authentication".to_string(),
                                severity: Severity::High,
                                target,
                                port: Some(6379),
                                evidence: Some("PING command successful without authentication".to_string()),
                                discovered_at: Utc::now(),
                                cvss_score: Some(7.5),
                                cve_id: None,
                                category: VulnerabilityCategory::Authentication,
                                remediation: Some("Configure Redis authentication with requirepass directive".to_string()),
                                references: vec![
                                    "https://redis.io/topics/security".to_string(),
                                    "https://redis.io/commands/auth".to_string(),
                                ],
                            }));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        
        Ok(None)
    }

    async fn check_default_credentials(&self, target: IpAddr) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Check common services for default credentials
        let default_creds = vec![
            (22, "ssh", "root", "root"),
            (22, "ssh", "admin", "admin"),
            (21, "ftp", "anonymous", ""),
            (21, "ftp", "ftp", "ftp"),
            (23, "telnet", "admin", "admin"),
            (3306, "mysql", "root", ""),
            (3306, "mysql", "root", "root"),
            (5432, "postgresql", "postgres", "postgres"),
        ];
        
        for (port, service, username, password) in default_creds {
            if self.test_default_credential(target, port, service, username, password).await? {
                vulnerabilities.push(Vulnerability {
                    id: format!("DEFAULT-CREDS-{}-{}", service.to_uppercase(), port),
                    name: format!("Default Credentials on {} Service", service.to_uppercase()),
                    description: format!("Service {} on port {} accepts default credentials", service, port),
                    severity: Severity::High,
                    target,
                    port: Some(port),
                    evidence: Some(format!("Login successful with {}:{}", username, password)),
                    discovered_at: Utc::now(),
                    cvss_score: Some(7.5),
                    cve_id: None,
                    category: VulnerabilityCategory::Authentication,
                    remediation: Some("Change default credentials to strong, unique passwords".to_string()),
                    references: vec!["https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication".to_string()],
                });
            }
        }
        
        Ok(vulnerabilities)
    }

    async fn test_default_credential(&self, target: IpAddr, port: u16, service: &str, username: &str, password: &str) -> Result<bool> {
        // This is a simplified check - in a real implementation, you would
        // use the actual protocol implementations from the brute_force module
        
        let addr = SocketAddr::new(target, port);
        
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                // For now, just return false as we don't have full protocol implementations
                // In a real implementation, you would use the brute force modules
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    pub async fn check_web_vulnerabilities(&self, target: IpAddr, port: u16) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        let base_url = if port == 443 {
            format!("https://{}", target)
        } else {
            format!("http://{}:{}", target, port)
        };
        
        // Check for common web vulnerabilities
        if let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
        {
            // Check for directory traversal
            let traversal_url = format!("{}/../../../../etc/passwd", base_url);
            if let Ok(response) = client.get(&traversal_url).send().await {
                if let Ok(body) = response.text().await {
                    if body.contains("root:") {
                        vulnerabilities.push(Vulnerability {
                            id: "DIRECTORY-TRAVERSAL".to_string(),
                            name: "Directory Traversal Vulnerability".to_string(),
                            description: "Web application is vulnerable to directory traversal attacks".to_string(),
                            severity: Severity::High,
                            target,
                            port: Some(port),
                            evidence: Some("Successfully accessed /etc/passwd via directory traversal".to_string()),
                            discovered_at: Utc::now(),
                            cvss_score: Some(7.5),
                            cve_id: None,
                            category: VulnerabilityCategory::InputValidation,
                            remediation: Some("Implement proper input validation and path sanitization".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/Path_Traversal".to_string()],
                        });
                    }
                }
            }
            
            // Check for exposed .git directory
            let git_url = format!("{}/.git/config", base_url);
            if let Ok(response) = client.get(&git_url).send().await {
                if response.status().is_success() {
                    vulnerabilities.push(Vulnerability {
                        id: "EXPOSED-GIT".to_string(),
                        name: "Exposed Git Repository".to_string(),
                        description: "Git repository is exposed and accessible via web".to_string(),
                        severity: Severity::Medium,
                        target,
                        port: Some(port),
                        evidence: Some("Git configuration file accessible".to_string()),
                        discovered_at: Utc::now(),
                        cvss_score: Some(5.3),
                        cve_id: None,
                        category: VulnerabilityCategory::InformationDisclosure,
                        remediation: Some("Remove .git directory from web root or block access via web server configuration".to_string()),
                        references: vec!["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Extensions_Handling_for_Sensitive_Information".to_string()],
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
    }
}
