use crate::{Result, ScanError};
use crate::config::Config;
use crate::evasion::EvasionEngine;
use log::{debug, info, warn};
use reqwest::Client;
use scraper::{Html, Selector};
use std::time::Duration;
use url::Url;

pub struct WebScanner {
    config: Config,
    client: Option<Client>, // Make it optional since we'll create it with evasion
    evasion_engine: Option<EvasionEngine>,
}

impl WebScanner {
    pub fn new(config: Config) -> Result<Self> {
        let evasion_engine = if config.evasion.enabled {
            Some(EvasionEngine::new(config.clone())?)
        } else {
            None
        };

        // Don't create client here if evasion is enabled - we'll create it per request
        let client = if config.evasion.enabled {
            None
        } else {
            Some(Client::builder()
                .timeout(Duration::from_secs(config.web_scan.request_timeout))
                .danger_accept_invalid_certs(!config.web_scan.verify_ssl)
                .redirect(if config.web_scan.follow_redirects {
                    reqwest::redirect::Policy::limited(config.web_scan.max_redirects as usize)
                } else {
                    reqwest::redirect::Policy::none()
                })
                .user_agent(&config.scan.user_agent)
                .build()
                .map_err(|e| ScanError::WebScan(format!("Failed to create HTTP client: {}", e)))?)
        };

        Ok(Self { 
            config, 
            client,
            evasion_engine,
        })
    }

    /// Get HTTP client with evasion if enabled
    async fn get_client(&self) -> Result<Client> {
        if let Some(ref evasion_engine) = self.evasion_engine {
            evasion_engine.create_http_client().await
        } else if let Some(ref client) = self.client {
            Ok(client.clone())
        } else {
            Err(ScanError::WebScan("No HTTP client available".to_string()))
        }
    }

    pub async fn scan_url(&self, url: &str) -> Result<WebScanResult> {
        info!("Scanning web application: {}", url);
        
        let parsed_url = Url::parse(url)
            .map_err(|e| ScanError::WebScan(format!("Invalid URL: {}", e)))?;

        let mut result = WebScanResult {
            url: url.to_string(),
            status_code: None,
            title: None,
            server: None,
            technologies: Vec::new(),
            vulnerabilities: Vec::new(),
            directories: Vec::new(),
        };

        // Apply evasion delay before scanning
        if let Some(ref evasion_engine) = self.evasion_engine {
            evasion_engine.random_delay().await;
            
            // Generate decoy traffic if enabled
            evasion_engine.generate_decoy_traffic(url).await?;
        }

        let client = self.get_client().await?;

        // Basic HTTP request
        match client.get(url).send().await {
            Ok(response) => {
                result.status_code = Some(response.status().as_u16());
                
                // Extract server header
                if let Some(server) = response.headers().get("server") {
                    if let Ok(server_str) = server.to_str() {
                        result.server = Some(server_str.to_string());
                    }
                }

                // Get response body
                if let Ok(body) = response.text().await {
                    result.title = self.extract_title(&body);
                    result.technologies = self.fingerprint_technologies(&body, &parsed_url);
                }
            }
            Err(e) => {
                warn!("Failed to fetch {}: {}", url, e);
            }
        }

        Ok(result)
    }

    fn extract_title(&self, html: &str) -> Option<String> {
        let document = Html::parse_document(html);
        let title_selector = Selector::parse("title").ok()?;
        
        document
            .select(&title_selector)
            .next()
            .map(|element| element.text().collect::<String>().trim().to_string())
    }

    fn fingerprint_technologies(&self, html: &str, url: &Url) -> Vec<String> {
        let mut technologies = Vec::new();
        let html_lower = html.to_lowercase();

        // Common CMS detection
        if html_lower.contains("wp-content") || html_lower.contains("wordpress") {
            technologies.push("WordPress".to_string());
        }
        if html_lower.contains("drupal") {
            technologies.push("Drupal".to_string());
        }
        if html_lower.contains("joomla") {
            technologies.push("Joomla".to_string());
        }

        // Framework detection
        if html_lower.contains("react") {
            technologies.push("React".to_string());
        }
        if html_lower.contains("angular") {
            technologies.push("Angular".to_string());
        }
        if html_lower.contains("vue.js") || html_lower.contains("vuejs") {
            technologies.push("Vue.js".to_string());
        }

        // Server-side technologies
        if html_lower.contains("php") || url.path().contains(".php") {
            technologies.push("PHP".to_string());
        }
        if html_lower.contains("asp.net") || url.path().contains(".aspx") {
            technologies.push("ASP.NET".to_string());
        }
        if html_lower.contains("jsp") || url.path().contains(".jsp") {
            technologies.push("JSP".to_string());
        }

        // Web servers (from HTML comments or specific patterns)
        if html_lower.contains("apache") {
            technologies.push("Apache".to_string());
        }
        if html_lower.contains("nginx") {
            technologies.push("Nginx".to_string());
        }
        if html_lower.contains("iis") {
            technologies.push("IIS".to_string());
        }

        technologies
    }

    pub async fn directory_bruteforce(&self, base_url: &str, wordlist: &[String]) -> Result<Vec<String>> {
        let mut found_directories = Vec::new();
        
        for directory in wordlist {
            let test_url = format!("{}/{}", base_url.trim_end_matches('/'), directory);
            
            // Apply evasion delay between requests
            if let Some(ref evasion_engine) = self.evasion_engine {
                evasion_engine.random_delay().await;
            }
            
            let client = self.get_client().await?;
            match client.head(&test_url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if status == 200 || status == 301 || status == 302 || status == 403 {
                        debug!("Found directory: {} ({})", test_url, status);
                        found_directories.push(directory.clone());
                    }
                }
                Err(_) => {
                    // Ignore errors for directory brute force
                }
            }
            
            // Additional rate limiting for non-evasion mode
            if self.evasion_engine.is_none() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        
        Ok(found_directories)
    }

    pub async fn check_common_vulnerabilities(&self, url: &str) -> Result<Vec<String>> {
        let mut vulnerabilities = Vec::new();

        // Check for common files that might indicate vulnerabilities
        let test_files = vec![
            ("robots.txt", "Robots.txt file exposed"),
            ("sitemap.xml", "Sitemap.xml file exposed"),
            (".git/config", "Git configuration exposed"),
            (".git/HEAD", "Git repository exposed"),
            (".env", "Environment file exposed"),
            (".htaccess", "Apache configuration exposed"),
            ("config.php", "PHP configuration file exposed"),
            ("wp-config.php", "WordPress configuration exposed"),
            ("web.config", "IIS configuration exposed"),
            ("admin", "Admin panel accessible"),
            ("administrator", "Administrator panel accessible"),
            ("phpmyadmin", "phpMyAdmin interface accessible"),
            ("backup.sql", "SQL backup file exposed"),
            ("database.sql", "Database file exposed"),
            ("dump.sql", "Database dump exposed"),
            ("test.php", "Test file exposed"),
            ("info.php", "PHP info file exposed"),
            ("phpinfo.php", "PHP info file exposed"),
            ("server-status", "Apache server status exposed"),
            ("server-info", "Apache server info exposed"),
        ];

        for (file, description) in test_files {
            let test_url = format!("{}/{}", url.trim_end_matches('/'), file);

            // Apply evasion delay between requests
            if let Some(ref evasion_engine) = self.evasion_engine {
                evasion_engine.random_delay().await;
            }

            let client = self.get_client().await?;
            match client.head(&test_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        vulnerabilities.push(description.to_string());
                    }
                }
                Err(_) => {
                    // Ignore errors
                }
            }
        }

        // Check for directory traversal
        let traversal_payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
        ];

        for payload in traversal_payloads {
            let test_url = format!("{}/{}", url.trim_end_matches('/'), payload);

            match self.get_client().await? {
                client => {
                    if let Ok(response) = client.get(&test_url).send().await {
                        if let Ok(body) = response.text().await {
                            if body.contains("root:") || body.contains("localhost") {
                                vulnerabilities.push("Directory traversal vulnerability detected".to_string());
                                break;
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check for SQL injection (basic)
        let sqli_payloads = vec![
            "?id=1'",
            "?id=1\"",
            "?id=1 OR 1=1",
            "?id=1; DROP TABLE users--",
        ];

        for payload in sqli_payloads {
            let test_url = format!("{}/{}", url.trim_end_matches('/'), payload);

            match self.get_client().await? {
                client => {
                    if let Ok(response) = client.get(&test_url).send().await {
                        if let Ok(body) = response.text().await {
                            let body_lower = body.to_lowercase();
                            if body_lower.contains("sql syntax") ||
                               body_lower.contains("mysql_fetch") ||
                               body_lower.contains("ora-01756") ||
                               body_lower.contains("microsoft jet database") ||
                               body_lower.contains("odbc drivers error") {
                                vulnerabilities.push("Potential SQL injection vulnerability".to_string());
                                break;
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Check for XSS (basic)
        let xss_payload = "<script>alert('XSS')</script>";
        let test_url = format!("{}/?q={}", url.trim_end_matches('/'),
                              urlencoding::encode(xss_payload));

        match self.get_client().await? {
            client => {
                if let Ok(response) = client.get(&test_url).send().await {
                    if let Ok(body) = response.text().await {
                        if body.contains(xss_payload) {
                            vulnerabilities.push("Potential XSS vulnerability detected".to_string());
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Check for specific CMS vulnerabilities
    pub async fn check_cms_vulnerabilities(&self, url: &str, cms: &str) -> Result<Vec<String>> {
        let mut vulnerabilities = Vec::new();

        match cms.to_lowercase().as_str() {
            "wordpress" => {
                // Check WordPress specific vulnerabilities
                let wp_checks = vec![
                    ("wp-admin/install.php", "WordPress installation accessible"),
                    ("wp-config.php.bak", "WordPress config backup exposed"),
                    ("wp-content/debug.log", "WordPress debug log exposed"),
                    ("wp-json/wp/v2/users", "WordPress user enumeration possible"),
                    ("xmlrpc.php", "WordPress XML-RPC enabled (potential DDoS vector)"),
                ];

                for (path, description) in wp_checks {
                    let test_url = format!("{}/{}", url.trim_end_matches('/'), path);

                    match self.get_client().await? {
                        client => {
                            if let Ok(response) = client.get(&test_url).send().await {
                                if response.status().is_success() {
                                    vulnerabilities.push(description.to_string());
                                }
                            }
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            "drupal" => {
                // Check Drupal specific vulnerabilities
                let drupal_checks = vec![
                    ("CHANGELOG.txt", "Drupal version disclosure"),
                    ("user/register", "User registration enabled"),
                    ("admin", "Admin panel accessible"),
                    ("sites/default/files", "Default files directory accessible"),
                ];

                for (path, description) in drupal_checks {
                    let test_url = format!("{}/{}", url.trim_end_matches('/'), path);

                    match self.get_client().await? {
                        client => {
                            if let Ok(response) = client.get(&test_url).send().await {
                                if response.status().is_success() {
                                    vulnerabilities.push(description.to_string());
                                }
                            }
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            "joomla" => {
                // Check Joomla specific vulnerabilities
                let joomla_checks = vec![
                    ("administrator/", "Joomla admin panel accessible"),
                    ("configuration.php", "Joomla configuration exposed"),
                    ("htaccess.txt", "Joomla htaccess template exposed"),
                ];

                for (path, description) in joomla_checks {
                    let test_url = format!("{}/{}", url.trim_end_matches('/'), path);

                    match self.get_client().await? {
                        client => {
                            if let Ok(response) = client.get(&test_url).send().await {
                                if response.status().is_success() {
                                    vulnerabilities.push(description.to_string());
                                }
                            }
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            _ => {}
        }

        Ok(vulnerabilities)
    }
}

#[derive(Debug, Clone)]
pub struct WebScanResult {
    pub url: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub vulnerabilities: Vec<String>,
    pub directories: Vec<String>,
}

// Common directory wordlist
pub fn get_common_directories() -> Vec<String> {
    vec![
        "admin".to_string(),
        "administrator".to_string(),
        "api".to_string(),
        "backup".to_string(),
        "config".to_string(),
        "css".to_string(),
        "data".to_string(),
        "db".to_string(),
        "docs".to_string(),
        "download".to_string(),
        "files".to_string(),
        "images".to_string(),
        "img".to_string(),
        "includes".to_string(),
        "js".to_string(),
        "login".to_string(),
        "logs".to_string(),
        "media".to_string(),
        "old".to_string(),
        "panel".to_string(),
        "private".to_string(),
        "public".to_string(),
        "scripts".to_string(),
        "static".to_string(),
        "temp".to_string(),
        "test".to_string(),
        "tmp".to_string(),
        "upload".to_string(),
        "uploads".to_string(),
        "user".to_string(),
        "users".to_string(),
        "www".to_string(),
    ]
}
