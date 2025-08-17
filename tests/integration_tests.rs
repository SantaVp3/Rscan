use rscan::{
    config::Config,
    discovery::NetworkDiscovery,
    types::{Target, Port, Protocol, PortState, Service},
    Result,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[tokio::test]
async fn test_network_discovery_creation() -> Result<()> {
    let config = Config::default();
    let _discovery = NetworkDiscovery::new(config)?;
    
    // Test that we can create a NetworkDiscovery instance
    assert!(true); // If we get here, creation was successful
    Ok(())
}

#[tokio::test]
async fn test_config_default() {
    let config = Config::default();
    
    // Test default configuration values
    assert_eq!(config.scan.threads, 100);
    assert_eq!(config.scan.timeout, 30);
    assert_eq!(config.scan.rate_limit, 100);
    assert_eq!(config.scan.retries, 3);
    assert_eq!(config.scan.user_agent, "Rscan/1.0");
    
    assert_eq!(config.discovery.ping_timeout, Duration::from_millis(1000));
    assert_eq!(config.discovery.tcp_timeout, Duration::from_millis(5000));
    assert_eq!(config.discovery.udp_timeout, Duration::from_millis(2000));
    
    assert_eq!(config.brute_force.max_attempts, 1000);
    assert_eq!(config.brute_force.delay_between_attempts, 100);
    assert_eq!(config.brute_force.connection_timeout, 10);
    
    assert!(config.web_scan.follow_redirects);
    assert_eq!(config.web_scan.max_redirects, 5);
    assert_eq!(config.web_scan.request_timeout, 10);
    assert!(!config.web_scan.verify_ssl);
    
    assert!(!config.exploit.enabled);
    assert!(!config.exploit.auto_exploit);
    assert_eq!(config.exploit.payload_timeout, 30);
    
    assert_eq!(config.reporting.output_dir.to_string_lossy(), "./reports");
    assert!(config.reporting.include_raw_data);
    assert!(!config.reporting.compress_output);
}

#[test]
fn test_target_creation() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let port = Port {
        number: 80,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        service: Some(Service {
            name: "http".to_string(),
            version: Some("Apache/2.4.41".to_string()),
            banner: Some("Apache/2.4.41 (Ubuntu)".to_string()),
        }),
    };
    
    let target = Target {
        ip,
        hostname: Some("example.com".to_string()),
        ports: vec![port.clone()],
    };
    
    assert_eq!(target.ip, ip);
    assert_eq!(target.hostname, Some("example.com".to_string()));
    assert_eq!(target.ports.len(), 1);
    assert_eq!(target.ports[0].number, 80);
    assert_eq!(target.ports[0].protocol, Protocol::Tcp);
    assert_eq!(target.ports[0].state, PortState::Open);
    
    if let Some(ref service) = target.ports[0].service {
        assert_eq!(service.name, "http");
        assert_eq!(service.version, Some("Apache/2.4.41".to_string()));
        assert_eq!(service.banner, Some("Apache/2.4.41 (Ubuntu)".to_string()));
    }
}

#[test]
fn test_config_save_and_load() -> Result<()> {
    use tempfile::Builder;

    let config = Config::default();
    let temp_file = Builder::new().suffix(".toml").tempfile().unwrap();
    let temp_path = temp_file.path().to_str().unwrap();

    // Test saving configuration
    config.save_to_file(temp_path)?;

    // Test loading configuration
    let loaded_config = Config::load_from_file(temp_path)?;

    // Verify some key values
    assert_eq!(loaded_config.scan.threads, config.scan.threads);
    assert_eq!(loaded_config.scan.timeout, config.scan.timeout);
    assert_eq!(loaded_config.discovery.ping_timeout, config.discovery.ping_timeout);

    Ok(())
}

#[tokio::test]
async fn test_wordlist_utilities() -> Result<()> {
    use rscan::utils::wordlist;
    use tempfile::NamedTempFile;
    use tokio::fs;
    
    // Test generating common usernames and passwords
    let usernames = wordlist::generate_common_usernames();
    let passwords = wordlist::generate_common_passwords();
    
    assert!(!usernames.is_empty());
    assert!(!passwords.is_empty());
    assert!(usernames.contains(&"admin".to_string()));
    assert!(passwords.contains(&"password".to_string()));
    
    // Test loading wordlist from file
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path();
    
    let test_wordlist = "admin\nroot\nuser\ntest\n";
    fs::write(temp_path, test_wordlist).await.unwrap();
    
    let loaded_words = wordlist::load_wordlist(temp_path).await?;
    assert_eq!(loaded_words.len(), 4);
    assert!(loaded_words.contains(&"admin".to_string()));
    assert!(loaded_words.contains(&"root".to_string()));
    assert!(loaded_words.contains(&"user".to_string()));
    assert!(loaded_words.contains(&"test".to_string()));
    
    Ok(())
}

#[test]
fn test_network_utilities() {
    use rscan::utils::network;
    use std::net::{IpAddr, Ipv4Addr};
    
    // Test private IP detection
    let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let public_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    
    assert!(network::is_private_ip(&private_ip));
    assert!(!network::is_private_ip(&public_ip));
    
    // Test valid scan target detection
    let valid_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let invalid_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    
    assert!(network::is_valid_scan_target(&valid_ip));
    assert!(!network::is_valid_scan_target(&invalid_ip));
    
    // Test network address calculation
    let ip = Ipv4Addr::new(192, 168, 1, 100);
    let network = network::get_network_address(ip, 24).unwrap();
    assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
    
    // Test host count calculation
    let host_count_24 = network::calculate_host_count(24).unwrap();
    let host_count_30 = network::calculate_host_count(30).unwrap();
    
    assert_eq!(host_count_24, 254); // 2^8 - 2 (network and broadcast)
    assert_eq!(host_count_30, 2);   // 2^2 - 2
}

#[test]
fn test_encoding_utilities() {
    use rscan::utils::encoding;
    
    let test_data = b"Hello, World!";
    
    // Test base64 encoding/decoding
    let encoded = encoding::base64_encode(test_data);
    let decoded = encoding::base64_decode(&encoded).unwrap();
    assert_eq!(decoded, test_data);
    
    // Test hex encoding/decoding
    let hex_encoded = encoding::hex_encode(test_data);
    let hex_decoded = encoding::hex_decode(&hex_encoded).unwrap();
    assert_eq!(hex_decoded, test_data);
}

#[test]
fn test_time_utilities() {
    use rscan::utils::time;
    use std::time::Duration;
    
    // Test duration formatting
    let duration_1h = Duration::from_secs(3661); // 1h 1m 1s
    let duration_1m = Duration::from_secs(61);   // 1m 1s
    let duration_1s = Duration::from_secs(1);    // 1s
    
    assert_eq!(time::format_duration(duration_1h), "1h 1m 1s");
    assert_eq!(time::format_duration(duration_1m), "1m 1s");
    assert_eq!(time::format_duration(duration_1s), "1s");
    
    // Test current time
    let now = time::now_utc();
    assert!(now.timestamp() > 0);
}

#[tokio::test]
async fn test_banner_grabbing() -> Result<()> {
    use rscan::utils::banner;
    use std::net::{IpAddr, Ipv4Addr};
    
    // Test banner grabbing (this will likely fail in CI, but tests the function)
    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    
    // Try to grab banner from a non-existent service (should return None or error)
    let result = banner::grab_banner(localhost, 12345, None).await;
    
    // We don't assert success here since the service likely doesn't exist
    // This just tests that the function can be called without panicking
    match result {
        Ok(_) => {}, // Banner grabbed successfully
        Err(_) => {}, // Expected for non-existent service
    }
    
    Ok(())
}

#[test]
fn test_severity_ordering() {
    use rscan::types::Severity;
    
    // Test that severity levels are properly defined
    let critical = Severity::Critical;
    let high = Severity::High;
    let medium = Severity::Medium;
    let low = Severity::Low;
    let info = Severity::Info;
    
    // Just test that they can be created and formatted
    assert_eq!(format!("{:?}", critical), "Critical");
    assert_eq!(format!("{:?}", high), "High");
    assert_eq!(format!("{:?}", medium), "Medium");
    assert_eq!(format!("{:?}", low), "Low");
    assert_eq!(format!("{:?}", info), "Info");
}
