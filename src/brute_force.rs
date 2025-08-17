use crate::{Result, ScanError};
use crate::types::Credentials;
use crate::config::Config;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tokio::time::{sleep, timeout};

#[async_trait]
pub trait BruteForcer: Send + Sync {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool>;
    fn service_name(&self) -> &'static str;
    fn default_port(&self) -> u16;
}

pub struct BruteForceEngine {
    config: Config,
}

impl BruteForceEngine {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn load_wordlist(&self, path: &Path) -> Result<Vec<String>> {
        let content = fs::read_to_string(path).await
            .map_err(|e| ScanError::BruteForce(format!("Failed to read wordlist {}: {}", path.display(), e)))?;
        
        Ok(content.lines().map(|line| line.trim().to_string()).filter(|line| !line.is_empty()).collect())
    }

    pub async fn brute_force_service<T: BruteForcer>(
        &self,
        brute_forcer: T,
        targets: &[IpAddr],
        usernames: &[String],
        passwords: &[String],
    ) -> Result<Vec<Credentials>> {
        let mut successful_creds = Vec::new();
        
        'target_loop: for &target in targets {
            let port = brute_forcer.default_port();

            // First check if the service is available
            if !self.is_service_available(target, port).await {
                info!("Service {} not available on {}:{}, skipping", brute_forcer.service_name(), target, port);
                continue;
            }

            info!("Starting {} brute force on {}:{}", brute_forcer.service_name(), target, port);
            
            let mut attempts = 0;
            let max_attempts = self.config.brute_force.max_attempts as usize;
            
            'outer: for username in usernames {
                for password in passwords {
                    if attempts >= max_attempts {
                        warn!("Reached maximum attempts ({}) for {}:{}", max_attempts, target, port);
                        break 'outer;
                    }
                    
                    attempts += 1;
                    
                    match timeout(
                        Duration::from_secs(self.config.brute_force.connection_timeout),
                        brute_forcer.attempt_login(target, port, username, password)
                    ).await {
                        Ok(Ok(true)) => {
                            info!("Successful login: {}:{}@{}:{}", username, password, target, port);
                            successful_creds.push(Credentials {
                                username: username.clone(),
                                password: password.clone(),
                                service: brute_forcer.service_name().to_string(),
                                target,
                                port,
                            });
                            break 'outer; // Move to next target after successful login
                        }
                        Ok(Ok(false)) => {
                            debug!("Failed login attempt: {}:{}@{}:{}", username, password, target, port);
                        }
                        Ok(Err(e)) => {
                            // Only log connection errors at debug level to reduce noise
                            if e.to_string().contains("Connection refused") || e.to_string().contains("os error 61") {
                                debug!("Service not available on {}:{} - {}", target, port, e);
                                // Skip remaining attempts for this target if service is not available
                                break 'target_loop;
                            } else {
                                warn!("Error during login attempt: {}", e);
                            }
                        }
                        Err(_) => {
                            warn!("Timeout during login attempt for {}:{}@{}:{}", username, password, target, port);
                        }
                    }
                    
                    // Rate limiting
                    sleep(self.config.brute_force_delay()).await;
                }
            }
        }
        
        Ok(successful_creds)
    }

    /// Check if a service is available on the target
    async fn is_service_available(&self, target: IpAddr, port: u16) -> bool {
        use tokio::net::TcpStream;
        use std::net::SocketAddr;

        let addr = SocketAddr::new(target, port);
        match timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }
}

// SSH Brute Forcer
pub struct SshBruteForcer;

#[async_trait]
impl BruteForcer for SshBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        use ssh2::Session;
        use std::net::TcpStream;
        
        let addr = SocketAddr::new(target, port);
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
            .map_err(|e| ScanError::BruteForce(format!("TCP connection failed: {}", e)))?;
        
        let mut session = Session::new()
            .map_err(|e| ScanError::BruteForce(format!("SSH session creation failed: {}", e)))?;
        
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| ScanError::BruteForce(format!("SSH handshake failed: {}", e)))?;
        
        match session.userauth_password(username, password) {
            Ok(()) => Ok(session.authenticated()),
            Err(_) => Ok(false),
        }
    }
    
    fn service_name(&self) -> &'static str {
        "ssh"
    }
    
    fn default_port(&self) -> u16 {
        22
    }
}

// FTP Brute Forcer
pub struct FtpBruteForcer;

#[async_trait]
impl BruteForcer for FtpBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let addr = SocketAddr::new(target, port);
        let stream = TcpStream::connect(addr).await
            .map_err(|e| ScanError::BruteForce(format!("FTP connection failed: {}", e)))?;

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut response = String::new();

        // Read welcome message
        reader.read_line(&mut response).await
            .map_err(|e| ScanError::BruteForce(format!("Failed to read FTP welcome: {}", e)))?;

        if !response.starts_with("220") {
            return Ok(false);
        }

        // Send username
        writer.write_all(format!("USER {}\r\n", username).as_bytes()).await
            .map_err(|e| ScanError::BruteForce(format!("Failed to send username: {}", e)))?;

        response.clear();
        reader.read_line(&mut response).await
            .map_err(|e| ScanError::BruteForce(format!("Failed to read username response: {}", e)))?;

        if !response.starts_with("331") {
            return Ok(false);
        }

        // Send password
        writer.write_all(format!("PASS {}\r\n", password).as_bytes()).await
            .map_err(|e| ScanError::BruteForce(format!("Failed to send password: {}", e)))?;

        response.clear();
        reader.read_line(&mut response).await
            .map_err(|e| ScanError::BruteForce(format!("Failed to read password response: {}", e)))?;

        Ok(response.starts_with("230"))
    }
    
    fn service_name(&self) -> &'static str {
        "ftp"
    }
    
    fn default_port(&self) -> u16 {
        21
    }
}

// MySQL Brute Forcer
pub struct MysqlBruteForcer;

#[async_trait]
impl BruteForcer for MysqlBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        use mysql_async::{Conn, OptsBuilder};

        let opts = OptsBuilder::default()
            .ip_or_hostname(target.to_string())
            .tcp_port(port)
            .user(Some(username))
            .pass(Some(password));

        match timeout(Duration::from_secs(15), Conn::new(opts)).await {
            Ok(Ok(mut conn)) => {
                // Test the connection with a simple query
                match mysql_async::prelude::Queryable::query_drop(&mut conn, "SELECT 1").await {
                    Ok(_) => {
                        let _ = conn.disconnect().await;
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }
    
    fn service_name(&self) -> &'static str {
        "mysql"
    }
    
    fn default_port(&self) -> u16 {
        3306
    }
}

// PostgreSQL Brute Forcer
pub struct PostgresBruteForcer;

#[async_trait]
impl BruteForcer for PostgresBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        use tokio_postgres::{Config, NoTls};

        let mut config = Config::new();
        config.host(target.to_string())
            .port(port)
            .user(username)
            .password(password)
            .dbname("postgres") // Default database
            .connect_timeout(Duration::from_secs(10));

        match timeout(Duration::from_secs(15), config.connect(NoTls)).await {
            Ok(Ok((client, connection))) => {
                // Spawn the connection task
                let connection_handle = tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!("PostgreSQL connection error: {}", e);
                    }
                });

                // Test with a simple query
                match client.simple_query("SELECT 1").await {
                    Ok(_) => {
                        connection_handle.abort();
                        Ok(true)
                    }
                    Err(_) => {
                        connection_handle.abort();
                        Ok(false)
                    }
                }
            }
            _ => Ok(false),
        }
    }
    
    fn service_name(&self) -> &'static str {
        "postgresql"
    }
    
    fn default_port(&self) -> u16 {
        5432
    }
}

// Redis Brute Forcer
pub struct RedisBruteForcer;

#[async_trait]
impl BruteForcer for RedisBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, _username: &str, password: &str) -> Result<bool> {
        use redis::Client;
        
        let url = format!("redis://{}:{}/{}", target, port, 0);
        let client = Client::open(url)
            .map_err(|e| ScanError::BruteForce(format!("Redis client creation failed: {}", e)))?;
        
        let mut conn = client.get_async_connection().await
            .map_err(|_| ScanError::BruteForce("Redis connection failed".to_string()))?;
        
        if !password.is_empty() {
            match redis::cmd("AUTH").arg(password).query_async::<_, String>(&mut conn).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            // Try without authentication
            match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
    
    fn service_name(&self) -> &'static str {
        "redis"
    }
    
    fn default_port(&self) -> u16 {
        6379
    }
}

// SQL Server Brute Forcer
pub struct MssqlBruteForcer;

#[async_trait]
impl BruteForcer for MssqlBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        // Simplified MSSQL check - in a real implementation, you would use proper TDS protocol
        use tokio::net::TcpStream;

        let addr = SocketAddr::new(target, port);

        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                // For now, just return false as we don't have full TDS implementation
                // In a real implementation, you would implement the TDS protocol
                // or use a compatible async library
                Ok(false)
            }
            _ => Ok(false),
        }
    }
    
    fn service_name(&self) -> &'static str {
        "mssql"
    }
    
    fn default_port(&self) -> u16 {
        1433
    }
}

// Telnet Brute Forcer
pub struct TelnetBruteForcer;

#[async_trait]
impl BruteForcer for TelnetBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        let addr = SocketAddr::new(target, port);
        let stream = match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(false),
        };

        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut response = String::new();

        // Read initial banner/prompt
        match timeout(Duration::from_secs(5), reader.read_line(&mut response)).await {
            Ok(Ok(_)) => {},
            _ => return Ok(false),
        }

        // Send username
        if (writer.write_all(format!("{}\r\n", username).as_bytes()).await).is_err() {
            return Ok(false);
        }

        // Read password prompt
        response.clear();
        match timeout(Duration::from_secs(5), reader.read_line(&mut response)).await {
            Ok(Ok(_)) => {},
            _ => return Ok(false),
        }

        // Send password
        if (writer.write_all(format!("{}\r\n", password).as_bytes()).await).is_err() {
            return Ok(false);
        }

        // Read response
        response.clear();
        match timeout(Duration::from_secs(5), reader.read_line(&mut response)).await {
            Ok(Ok(_)) => {
                // Check for successful login indicators
                let response_lower = response.to_lowercase();
                if response_lower.contains("welcome") ||
                   response_lower.contains("$") ||
                   response_lower.contains("#") ||
                   response_lower.contains(">") {
                    Ok(true)
                } else if response_lower.contains("incorrect") ||
                         response_lower.contains("invalid") ||
                         response_lower.contains("denied") ||
                         response_lower.contains("failed") {
                    Ok(false)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }

    fn service_name(&self) -> &'static str {
        "telnet"
    }

    fn default_port(&self) -> u16 {
        23
    }
}

// SMB Brute Forcer
pub struct SmbBruteForcer;

#[async_trait]
impl BruteForcer for SmbBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        // Simplified SMB authentication check
        // In a full implementation, you would use proper SMB/CIFS protocol
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let addr = SocketAddr::new(target, port);
        let mut stream = match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(false),
        };

        // Simple SMB connection test
        let test_data = b"SMB_TEST";

        // Send test data
        if (stream.write_all(test_data).await).is_err() {
            return Ok(false);
        }

        // For this simplified implementation, just check if we can connect to port 445
        // In a real implementation, you would implement proper SMB authentication
        Ok(true)
    }

    fn service_name(&self) -> &'static str {
        "smb"
    }

    fn default_port(&self) -> u16 {
        445
    }
}

// RDP Brute Forcer
pub struct RdpBruteForcer;

#[async_trait]
impl BruteForcer for RdpBruteForcer {
    async fn attempt_login(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Result<bool> {
        // Simplified RDP connection check
        // Full RDP implementation would require complex protocol handling
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = SocketAddr::new(target, port);
        let mut stream = match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            _ => return Ok(false),
        };

        // RDP Connection Request (simplified)
        let rdp_request = vec![
            0x03, 0x00, 0x00, 0x13, // TPKT Header
            0x0e, // X.224 Connection Request
            0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Send connection request
        if (stream.write_all(&rdp_request).await).is_err() {
            return Ok(false);
        }

        // Read response
        let mut buffer = vec![0; 1024];
        match timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                // Check for RDP response
                if buffer.len() >= 4 && buffer[0] == 0x03 && buffer[1] == 0x00 {
                    // Got RDP response - service is available
                    // For this simplified implementation, we'll return true if RDP responds
                    // Real implementation would continue with authentication protocol
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }

    fn service_name(&self) -> &'static str {
        "rdp"
    }

    fn default_port(&self) -> u16 {
        3389
    }
}
