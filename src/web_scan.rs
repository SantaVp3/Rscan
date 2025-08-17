use std::collections::HashMap;
use crate::{Result, ScanError};
use crate::config::Config;
use crate::evasion::EvasionEngine;
use crate::template::{Template, TemplateResult, HttpRequest, Matcher, Extractor, MatchersCondition, ComplexCondition, PathInfo};
use crate::template_engine::TemplateEngine;
use crate::nuclei_dsl::{DslEvaluator, evaluate_dsl_expression, evaluate_dsl_expression_with_history,
                      detect_multi_request_requirement, MultiRequestHistory, RequestResponseData};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use log::{debug, info, warn};
use reqwest::{Client, StatusCode, header::{HeaderMap, HeaderName, HeaderValue}};
use scraper::{Html, Selector};
use std::time::Duration;
use url::Url;
use std::path::Path;
use walkdir;
use regex::Regex;
use rand::prelude::*;
use std::str::FromStr;
use colored::Colorize;

/// 匹配结果结构体
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// 匹配详情
    pub details: String,
    /// 提取的结果
    pub extracted_results: HashMap<String, Vec<String>>,
}

pub struct WebScanner {
    config: Config,
    client: Option<Client>, // Make it optional since we'll create it with evasion
    evasion_engine: Option<EvasionEngine>,
    template_engine: TemplateEngine,
    loaded_templates: Vec<Template>,
}

impl Clone for WebScanner {
    fn clone(&self) -> Self {
        WebScanner {
            config: self.config.clone(),
            client: self.client.clone(),
            evasion_engine: self.evasion_engine.clone(),
            template_engine: self.template_engine.clone(),
            loaded_templates: self.loaded_templates.clone(),
        }
    }
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

        // 创建模板引擎
        let template_engine = TemplateEngine::with_config(
            Duration::from_secs(config.web_scan.request_timeout),
            config.web_scan.max_redirects,
            config.web_scan.verify_ssl,
            config.scan.user_agent.clone(),
        )?;

        Ok(Self {
            config,
            client,
            evasion_engine,
            template_engine,
            loaded_templates: Vec::new(),
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
            template_results: Vec::new(),
            dsl_results: HashMap::new(),
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

        // 执行模板扫描（如果有加载的模板）
        if !self.loaded_templates.is_empty() {
            info!("开始执行模板扫描，共 {} 个模板", self.loaded_templates.len());

            match self.scan_with_templates(url, None, Some(20)).await {
                Ok(template_results) => {
                    let matched_count = template_results.iter().filter(|r| r.matched).count();
                    if matched_count > 0 {
                        info!("模板扫描发现 {} 个匹配结果", matched_count);

                        // 将匹配的模板结果转换为漏洞信息
                        for template_result in &template_results {
                            if template_result.matched {
                                // 查找对应的模板以获取详细信息
                                if let Some(template) = self.loaded_templates.iter()
                                    .find(|t| t.id.as_ref().map_or(false, |id| *id == template_result.template_id)) {

                                    let template_name = template.info.as_ref()
                                        .map(|info| info.name.clone())
                                        .unwrap_or_else(|| "未知模板".to_string());
                                    let template_severity = template.info.as_ref()
                                        .and_then(|info| info.severity.as_ref());

                                    let vulnerability_desc = format!(
                                        "{} (模板: {}, 严重性: {:?})",
                                        template_name,
                                        template.id.as_ref().unwrap_or(&"unknown".to_string()),
                                        template_severity
                                    );
                                    result.vulnerabilities.push(vulnerability_desc);
                                }
                            }
                        }
                    }
                    result.template_results = template_results;
                }
                Err(e) => {
                    warn!("模板扫描失败: {}", e);
                }
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

    /// 加载单个模板文件
    pub fn load_template(&mut self, template_path: &str) -> Result<()> {
        info!("加载模板文件: {}", template_path);

        let mut template = Template::from_file(template_path)?;

        // 如果模板ID为空，使用文件名作为ID
        if template.id.is_none() || template.id.as_ref().unwrap().trim().is_empty() {
            let file_name = std::path::Path::new(template_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            template.id = Some(file_name);
        }

        template.validate()?;

        self.loaded_templates.push(template);
        info!("成功加载模板: {}", template_path);

        Ok(())
    }

    /// 从目录加载所有模板文件
    pub fn load_templates_from_directory(&mut self, templates_dir: &str) -> Result<usize> {
        info!("从目录加载模板: {}", templates_dir);

        let mut loaded_count = 0;
        let templates_path = Path::new(templates_dir);

        if !templates_path.exists() {
            return Err(ScanError::InvalidInput(format!("模板目录不存在: {}", templates_dir)));
        }

        // 递归遍历目录查找.yaml和.yml文件
        for entry in walkdir::WalkDir::new(templates_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "yaml" || extension == "yml" {
                        match self.load_template(path.to_str().unwrap()) {
                            Ok(_) => loaded_count += 1,
                            Err(e) => warn!("加载模板文件 {} 失败: {}", path.display(), e),
                        }
                    }
                }
            }
        }

        info!("从目录 {} 成功加载 {} 个模板", templates_dir, loaded_count);
        Ok(loaded_count)
    }

    /// 根据标签过滤模板
    pub fn filter_templates_by_tags(&self, tags: &[String]) -> Vec<&Template> {
        if tags.is_empty() {
            return self.loaded_templates.iter().collect();
        }

        self.loaded_templates
            .iter()
            .filter(|template| {
                tags.iter().any(|tag| template.has_tag(tag))
            })
            .collect()
    }

    /// 根据严重性过滤模板
    pub fn filter_templates_by_severity(&self, min_severity: &crate::template::Severity) -> Vec<&Template> {
        use crate::template::Severity;

        let severity_order = |s: &Severity| match s {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };

        let min_level = severity_order(min_severity);

        self.loaded_templates
            .iter()
            .filter(|template| {
                let severity = template.info.as_ref()
                    .and_then(|info| info.severity.as_ref())
                    .unwrap_or(&Severity::Info); // 如果没有指定严重性，默认为Info级别
                severity_order(severity) >= min_level
            })
            .collect()
    }



    /// 使用模板并行扫描目标URL（高性能版本）
    pub async fn scan_with_templates(
        &self,
        target_url: &str,
        templates: Option<Vec<&Template>>,
        max_concurrent: Option<usize>
    ) -> Result<Vec<TemplateResult>> {
        info!("使用并行模式扫描目标: {} (最大并发: {})",
              target_url, max_concurrent.unwrap_or(50));

        let templates_to_use = templates.unwrap_or_else(|| self.loaded_templates.iter().collect());
        let template_count = templates_to_use.len();

        if template_count == 0 {
            return Ok(Vec::new());
        }

        // 设置并发限制
        let concurrent_limit = max_concurrent.unwrap_or(50).min(template_count);

        // 创建共享的结果收集器
        let results = Arc::new(Mutex::new(Vec::new()));

        // 将模板转换为拥有所有权的版本以避免生命周期问题
        let owned_templates: Vec<Template> = templates_to_use.iter().map(|t| (*t).clone()).collect();

        // 创建任务批次
        let chunks: Vec<_> = owned_templates.chunks(concurrent_limit).collect();

        for chunk in chunks {
            // 为每个批次创建并发任务
            let tasks: Vec<_> = chunk.iter().map(|template| {
                let template = template.clone();
                let target_url = target_url.to_string();
                let results = Arc::clone(&results);
                let scanner = self.clone_for_parallel();

                tokio::spawn(async move {
                    scanner.scan_single_template_parallel_owned(template, &target_url, results).await
                })
            }).collect();

            // 等待当前批次完成
            for task in tasks {
                if let Err(e) = task.await {
                    warn!("并行扫描任务失败: {}", e);
                }
            }

            // 在批次之间添加小延迟，避免过度负载
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // 提取最终结果
        let final_results = results.lock().unwrap().clone();
        let matched_count = final_results.iter().filter(|r| r.matched).count();

        info!("并行扫描完成: 总模板 {}, 匹配 {}", template_count, matched_count);

        Ok(final_results)
    }



    /// 使用DSL表达式进行高级匹配
    pub async fn scan_with_dsl(&self, target_url: &str, dsl_expressions: &[String]) -> Result<Vec<bool>> {
        info!("使用DSL表达式扫描目标: {}", target_url);

        let client = self.get_client().await?;
        let response = client.get(target_url).send().await
            .map_err(|e| ScanError::WebScan(format!("HTTP请求失败: {}", e)))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await
            .map_err(|e| ScanError::WebScan(format!("读取响应体失败: {}", e)))?;

        let mut results = Vec::new();
        for expression in dsl_expressions {
            match evaluate_dsl_expression(expression, &status, &headers, &body, target_url) {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("DSL表达式 '{}' 执行失败: {}", expression, e);
                    results.push(false);
                }
            }
        }

        Ok(results)
    }

    /// 获取已加载的模板数量
    pub fn get_loaded_templates_count(&self) -> usize {
        self.loaded_templates.len()
    }

    /// 获取已加载的模板列表
    pub fn get_loaded_templates(&self) -> &[Template] {
        &self.loaded_templates
    }

    /// 清空已加载的模板
    pub fn clear_templates(&mut self) {
        self.loaded_templates.clear();
        info!("已清空所有加载的模板");
    }

    /// 执行HTTP请求（支持原始请求格式）
    pub async fn execute_http_request(&self, request: &HttpRequest, base_url: &str) -> Result<Vec<MatchResult>> {
        self.execute_http_request_with_template_info(request, base_url, None).await
    }

    /// 执行HTTP请求（支持原始请求格式，带模板信息）
    pub async fn execute_http_request_with_template_info(&self, request: &HttpRequest, base_url: &str, template_info: Option<&str>) -> Result<Vec<MatchResult>> {
        let client = self.get_client().await?;

        let (method, url, headers, body) = self.parse_raw_or_structured(request, base_url)?;

        let mut request_builder = client.request(method, &url);

        // 添加所有的请求头
        for (key, value) in headers.iter() {
            request_builder = request_builder.header(key, value);
        }

        // 添加随机User-Agent
        request_builder = request_builder.header("User-Agent", Self::random_user_agent());
        request_builder = request_builder.header("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
        request_builder = request_builder.header("Referer", format!("https://www.baidu.com/s?wd={}&rsv_spt=1", base_url));

        // 添加请求体（如果有的话）
        if let Some(body) = body {
            request_builder = request_builder.body(body);
        }

        let response = request_builder.send().await
            .map_err(|e| ScanError::WebScan(format!("HTTP请求失败: {}", e)))?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await
            .map_err(|e| ScanError::WebScan(format!("读取响应体失败: {}", e)))?;

        let mut results = Vec::new();
        let mut extracted_results = HashMap::new();

        // 执行提取器
        if let Some(ref extractors) = request.extractors {
            for extractor in extractors {
                let extracted = self.extract_data(extractor, &status, &headers, &body, template_info)?;
                if !extracted.is_empty() {
                    let extractor_name = extractor.name.as_ref().unwrap_or(&format!("extractor_{}", extracted_results.len())).clone();
                    extracted_results.insert(extractor_name, extracted);
                }
            }
        }

        // 执行匹配器
        if let Some(ref matchers) = request.matchers {
            let matched = self.match_response(matchers, &request.matchers_condition, &status, &headers, &body, &url, template_info)?;

            if matched {
                results.push(MatchResult {
                    details: format!("{} {}", "匹配成功:".red(), url.red()),
                    extracted_results,
                });
            }
        }

        Ok(results)
    }

    /// 解析原始或结构化请求
    fn parse_raw_or_structured(&self, request: &HttpRequest, base_url: &str) -> Result<(reqwest::Method, String, HeaderMap, Option<String>)> {
        if let Some(raw) = &request.raw {
            self.parse_raw_request(raw, base_url)
        } else {
            self.parse_structured_request(request, base_url)
        }
    }

    /// 解析原始请求
    fn parse_raw_request(&self, raw: &[String], base_url: &str) -> Result<(reqwest::Method, String, HeaderMap, Option<String>)> {
        let raw_request = raw.join("\n");
        let mut parts = raw_request.splitn(2, "\n\n");

        let headers_part = parts.next().ok_or_else(|| ScanError::WebScan("无效的原始请求格式".to_string()))?;
        let body_part = parts.next().unwrap_or("").to_string().replace("\n", "");

        let mut lines = headers_part.lines();
        let request_line = lines.next().ok_or_else(|| ScanError::WebScan("空的原始请求".to_string()))?;
        let mut request_parts = request_line.split_whitespace();

        let method = request_parts.next().ok_or_else(|| ScanError::WebScan("原始请求中缺少方法".to_string()))?;
        let path = request_parts.next().ok_or_else(|| ScanError::WebScan("原始请求中缺少路径".to_string()))?;

        let method = reqwest::Method::from_str(method)
            .map_err(|e| ScanError::WebScan(format!("无效的HTTP方法: {}", e)))?;

        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{}{}", base_url.trim_end_matches('/'), path)
        };

        let mut headers = HeaderMap::new();

        for line in lines {
            let mut header_parts = line.splitn(2, ':');

            if let (Some(key), Some(value)) = (header_parts.next(), header_parts.next()) {
                let parsed_url = Url::parse(&url)
                    .map_err(|e| ScanError::WebScan(format!("无效的URL: {}", e)))?;

                let host = parsed_url.host()
                    .ok_or_else(|| ScanError::WebScan(format!("无法从URL中提取主机名: {}", url)))?
                    .to_string();

                let port = parsed_url.port().unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });
                let hostname_replacement = if (parsed_url.scheme() == "https" && port == 443) || (parsed_url.scheme() == "http" && port == 80) {
                    host
                } else {
                    format!("{}:{}", host, port)
                };

                headers.insert(
                    HeaderName::from_str(key.trim())
                        .map_err(|e| ScanError::WebScan(format!("无效的请求头名称: {}", e)))?,
                    HeaderValue::from_str(value.replace("{{Hostname}}", &hostname_replacement).trim())
                        .map_err(|e| ScanError::WebScan(format!("无效的请求头值: {}", e)))?
                );
            }
        }

        Ok((method, url, headers, if body_part.is_empty() { None } else { Some(body_part) }))
    }

    /// 解析结构化请求
    fn parse_structured_request(&self, request: &HttpRequest, base_url: &str) -> Result<(reqwest::Method, String, HeaderMap, Option<String>)> {
        let method = request.method.as_ref()
            .ok_or_else(|| ScanError::WebScan("缺少HTTP方法".to_string()))?
            .parse()
            .map_err(|e| ScanError::WebScan(format!("无效的HTTP方法: {}", e)))?;

        let path = match request.path.as_ref() {
            Some(PathInfo::Single(path)) => path,
            Some(PathInfo::Multiple(paths)) => {
                paths.get(0).ok_or_else(|| ScanError::WebScan("路径列表为空".to_string()))?
            }
            None => return Err(ScanError::WebScan("缺少请求路径".to_string())),
        };

        let url = format!("{}{}", base_url.trim_end_matches('/'), path.replace("{{BaseURL}}", ""));

        let mut headers = HeaderMap::new();
        if let Some(header_map) = &request.headers {
            for (key, value) in header_map {
                headers.insert(
                    HeaderName::from_str(key)
                        .map_err(|e| ScanError::WebScan(format!("无效的请求头名称: {}", e)))?,
                    HeaderValue::from_str(value)
                        .map_err(|e| ScanError::WebScan(format!("无效的请求头值: {}", e)))?
                );
            }
        }

        Ok((method, url, headers, request.body.clone()))
    }

    /// 匹配响应
    fn match_response(
        &self,
        matchers: &[Matcher],
        matchers_condition: &Option<MatchersCondition>,
        status: &StatusCode,
        headers: &HeaderMap,
        body: &str,
        url: &str,
        template_info: Option<&str>,
    ) -> Result<bool> {
        let matcher_results: Vec<bool> = matchers.iter()
            .map(|matcher| self.match_single(matcher, status, headers, body, url, template_info).unwrap_or(false))
            .collect();

        let default_condition = MatchersCondition::Simple("and".to_string());
        let condition = matchers_condition.as_ref().unwrap_or(&default_condition);
        self.evaluate_condition(condition, &matcher_results)
    }

    /// 评估匹配器条件
    fn evaluate_condition(&self, condition: &MatchersCondition, results: &[bool]) -> Result<bool> {
        match condition {
            MatchersCondition::Simple(cond) => {
                match cond.as_str() {
                    "and" => Ok(results.iter().all(|&x| x)),
                    "or" => Ok(results.iter().any(|&x| x)),
                    "not" => Ok(!results.iter().any(|&x| x)),
                    _ => Err(ScanError::WebScan(format!("未知的条件: {}", cond))),
                }
            },
            MatchersCondition::Complex(complex_cond) => {
                let sub_results: Result<Vec<bool>> = complex_cond.conditions.iter()
                    .map(|cond| self.evaluate_condition(cond, results))
                    .collect();
                let sub_results = sub_results?;

                match complex_cond.condition_type.as_str() {
                    "and" => Ok(sub_results.iter().all(|&x| x)),
                    "or" => Ok(sub_results.iter().any(|&x| x)),
                    "not" => Ok(!sub_results.iter().any(|&x| x)),
                    _ => Err(ScanError::WebScan(format!("未知的复杂条件类型: {}", complex_cond.condition_type))),
                }
            },
        }
    }

    /// 单个匹配器匹配
    fn match_single(
        &self,
        matcher: &Matcher,
        status: &StatusCode,
        headers: &HeaderMap,
        body: &str,
        url: &str,
        template_info: Option<&str>,
    ) -> Result<bool> {
        match matcher.matcher_type.as_str() {
            "status" => {
                if let Some(status_codes) = &matcher.status {
                    Ok(status_codes.contains(&status.as_u16()))
                } else {
                    Ok(false)
                }
            },
            "word" => {
                if let Some(words) = &matcher.words {
                    let content = match matcher.part.as_deref().unwrap_or("body") {
                        "header" => headers.iter()
                            .map(|(k, v)| format!("{}: {}\n", k.as_str(), v.to_str().unwrap_or("")))
                            .collect::<String>(),
                        "body" => body.to_string(),
                        _ => body.to_string(),
                    };

                    let condition = matcher.condition.as_deref().unwrap_or("and");
                    match condition {
                        "and" => Ok(words.iter().all(|word| content.contains(word))),
                        "or" => Ok(words.iter().any(|word| content.contains(word))),
                        _ => Ok(words.iter().all(|word| content.contains(word))),
                    }
                } else {
                    Ok(false)
                }
            },
            "dsl" => {
                if let Some(dsl_expressions) = &matcher.dsl {
                    // 检测是否需要多请求支持
                    let max_required_requests = dsl_expressions.iter()
                        .map(|dsl| detect_multi_request_requirement(dsl))
                        .max()
                        .unwrap_or(1);

                    if max_required_requests > 1 {
                        // 多请求模板：暂时返回false，需要在更高层处理
                        // 这里我们标记这个匹配器需要多请求处理
                        let template_name = template_info.unwrap_or("未知模板");
                        warn!("检测到多请求DSL模板 [{}]，需要 {} 个请求", template_name, max_required_requests);
                        Ok(false) // 暂时返回false，实际处理在enhanced_scan中
                    } else {
                        // 单请求模板：使用原有逻辑
                        let matched = dsl_expressions.iter().all(|dsl| {
                            match evaluate_dsl_expression(dsl.as_str(), status, headers, body, url) {
                                Ok(result) => result,
                                Err(e) => {
                                    let template_name = template_info.unwrap_or("未知模板");
                                    warn!("DSL表达式错误 [模板: {}]: {} - {}", template_name, dsl, e);
                                    false
                                }
                            }
                        });
                        Ok(matched)
                    }
                } else {
                    Ok(false)
                }
            },
            "regex" => {
                if let Some(patterns) = &matcher.regex {
                    let content = match matcher.part.as_deref().unwrap_or("body") {
                        "header" => headers.iter()
                            .map(|(k, v)| format!("{}: {}\n", k.as_str(), v.to_str().unwrap_or("")))
                            .collect::<String>(),
                        "body" => body.to_string(),
                        _ => body.to_string(),
                    };

                    let matched = patterns.iter().any(|pattern| {
                        match Regex::new(pattern) {
                            Ok(regex) => regex.is_match(&content),
                            Err(e) => {
                                let template_name = template_info.unwrap_or("未知模板");
                                warn!("编译正则表达式失败 [模板: {}]: {} - {}", template_name, pattern, e);
                                false
                            }
                        }
                    });
                    Ok(matched)
                } else {
                    Ok(false)
                }
            },
            _ => Ok(false),
        }
    }

    /// 提取数据
    fn extract_data(
        &self,
        extractor: &Extractor,
        _status: &StatusCode,
        _headers: &HeaderMap,
        body: &str,
        template_info: Option<&str>,
    ) -> Result<Vec<String>> {
        let mut extracted_values = Vec::new();

        // 如果定义了正则提取
        if let Some(regex_patterns) = &extractor.regex {
            for pattern in regex_patterns {
                match Regex::new(pattern) {
                    Ok(regex) => {
                        if let Some(captures) = regex.captures(body) {
                            if let Some(group) = extractor.group {
                                if let Some(value) = captures.get(group as usize) {
                                    extracted_values.push(value.as_str().to_string());
                                }
                            } else if captures.len() > 1 {
                                // 如果没有指定组，使用第一个捕获组
                                if let Some(value) = captures.get(1) {
                                    extracted_values.push(value.as_str().to_string());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let template_name = template_info.unwrap_or("未知模板");
                        warn!("编译正则表达式失败 [模板: {}]: {} - {}", template_name, pattern, e);
                        continue;
                    }
                }
            }
        }

        Ok(extracted_values)
    }

    /// 随机用户代理生成
    fn random_user_agent() -> &'static str {
        let user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        ];

        let mut rng = thread_rng();
        user_agents.choose(&mut rng).unwrap_or(&user_agents[0])
    }

    /// 使用增强的HTTP请求执行扫描单个模板
    pub async fn scan_template_enhanced(&self, template: &Template, target_url: &str) -> Result<Vec<MatchResult>> {
        info!("使用增强模式扫描模板 {} 对目标 {}", template.id.as_ref().unwrap_or(&"unknown".to_string()), target_url);

        let mut all_results = Vec::new();
        let http_requests = template.get_http_requests();

        // 检测是否有多请求DSL模板
        let mut has_multi_request_dsl = false;
        let mut max_required_requests = 1;

        for request in &http_requests {
            if let Some(ref matchers) = request.matchers {
                for matcher in matchers {
                    if let Some(ref dsl_expressions) = matcher.dsl {
                        let required = dsl_expressions.iter()
                            .map(|dsl| detect_multi_request_requirement(dsl))
                            .max()
                            .unwrap_or(1);
                        if required > 1 {
                            has_multi_request_dsl = true;
                            max_required_requests = max_required_requests.max(required);
                        }
                    }
                }
            }
        }

        if has_multi_request_dsl {
            // 处理多请求DSL模板
            let unknown_template = "unknown".to_string();
            let template_name = template.id.as_ref().unwrap_or(&unknown_template);
            info!("检测到多请求DSL模板 [{}]，需要 {} 个请求", template_name, max_required_requests);

            // 收集所有DSL表达式
            let mut all_dsl_expressions = Vec::new();
            for request in &http_requests {
                if let Some(ref matchers) = request.matchers {
                    for matcher in matchers {
                        if let Some(ref dsl_expressions) = matcher.dsl {
                            all_dsl_expressions.extend(dsl_expressions.clone());
                        }
                    }
                }
            }

            // 执行多请求DSL匹配
            match self.execute_multi_request_dsl(&all_dsl_expressions, target_url, max_required_requests, Some(template_name)).await {
                Ok(matched) => {
                    if matched {
                        all_results.push(MatchResult {
                            details: "多请求DSL匹配成功".to_string(),
                            extracted_results: HashMap::new(),
                        });
                    }
                }
                Err(e) => {
                    warn!("多请求DSL执行失败 [模板: {}]: {}", template_name, e);
                }
            }
        } else {
            // 处理普通模板
            for request in http_requests {
                // 应用逃避延迟
                if let Some(ref evasion_engine) = self.evasion_engine {
                    evasion_engine.random_delay().await;
                }

                let unknown_template = "unknown".to_string();
                let template_name = template.id.as_ref().unwrap_or(&unknown_template);
                match self.execute_http_request_with_template_info(request, target_url, Some(template_name)).await {
                    Ok(mut results) => {
                        all_results.append(&mut results);
                    }
                    Err(e) => {
                        warn!("执行HTTP请求失败: {}", e);
                    }
                }
            }
        }

        if !all_results.is_empty() {
            info!("模板 {} 匹配成功，发现 {} 个结果", template.id.as_ref().unwrap_or(&"unknown".to_string()), all_results.len());
        }

        Ok(all_results)
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
    /// 模板扫描结果
    pub template_results: Vec<TemplateResult>,
    /// DSL匹配结果
    pub dsl_results: HashMap<String, bool>,
}

impl WebScanner {
    /// 执行多请求DSL匹配
    async fn execute_multi_request_dsl(
        &self,
        dsl_expressions: &[String],
        base_url: &str,
        required_requests: usize,
        template_info: Option<&str>,
    ) -> Result<bool> {
        let mut history = MultiRequestHistory::new();
        let client = self.get_client().await?;

        // 执行多个请求以收集历史数据
        for request_index in 1..=required_requests {
            let start_time = std::time::Instant::now();

            // 构建请求URL（这里简化处理，实际应该根据模板定义构建不同的请求）
            let request_url = if request_index == 1 {
                base_url.to_string()
            } else {
                // 对于第二个及后续请求，可能需要不同的路径或参数
                // 这里简化处理，实际应该根据模板的具体定义来构建
                format!("{}?request={}", base_url, request_index)
            };

            match client.get(&request_url).send().await {
                Ok(response) => {
                    let duration = start_time.elapsed().as_millis() as f64;
                    let status_code = response.status().as_u16() as i64;
                    let headers = response.headers().clone();

                    // 构建响应头字符串
                    let headers_string = headers.iter()
                        .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join("\n");

                    match response.text().await {
                        Ok(body) => {
                            // 创建响应数据
                            let response_data = RequestResponseData {
                                status_code,
                                body: body.clone(),
                                headers: headers_string,
                                content_length: body.len() as i64,
                                duration,
                                url: request_url.clone(),
                                timestamp: std::time::SystemTime::now(),
                            };

                            // 添加到历史记录
                            history.add_response(response_data);

                            debug!("多请求DSL: 完成请求 {} 到 {}, 状态码: {}, 响应时间: {}ms",
                                   request_index, request_url, status_code, duration);
                        }
                        Err(e) => {
                            warn!("多请求DSL: 读取请求 {} 响应体失败: {}", request_index, e);
                            return Ok(false);
                        }
                    }
                }
                Err(e) => {
                    warn!("多请求DSL: 请求 {} 失败: {}", request_index, e);
                    return Ok(false);
                }
            }

            // 在请求之间添加小延迟，避免过于频繁的请求
            if request_index < required_requests {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        // 使用历史数据评估所有DSL表达式
        let matched = dsl_expressions.iter().all(|dsl| {
            match evaluate_dsl_expression_with_history(dsl, &history, base_url) {
                Ok(result) => {
                    debug!("多请求DSL表达式 '{}' 评估结果: {}", dsl, result);
                    result
                }
                Err(e) => {
                    let template_name = template_info.unwrap_or("未知模板");
                    warn!("多请求DSL表达式错误 [模板: {}]: {} - {}", template_name, dsl, e);
                    false
                }
            }
        });

        if matched {
            info!("多请求DSL匹配成功 [模板: {}]", template_info.unwrap_or("未知模板"));
        }

        Ok(matched)
    }

    /// 为并行扫描创建扫描器副本
    fn clone_for_parallel(&self) -> Self {
        self.clone()
    }

    /// 并行扫描单个模板（拥有所有权版本）
    async fn scan_single_template_parallel_owned(
        &self,
        template: Template,
        target_url: &str,
        results: Arc<Mutex<Vec<TemplateResult>>>,
    ) {
        let template_id = template.id.as_ref().unwrap_or(&"unknown".to_string()).clone();

        debug!("并行执行模板 {} 对目标 {}", template_id, target_url);

        // 应用逃避延迟（减少延迟以提高并行性能）
        if let Some(ref evasion_engine) = self.evasion_engine {
            // 在并行模式下使用更短的延迟
            tokio::time::sleep(std::time::Duration::from_millis(
                fastrand::u64(10..50) // 10-50ms随机延迟
            )).await;
        }

        // 首先尝试使用增强的扫描方法
        match self.scan_template_enhanced(&template, target_url).await {
            Ok(match_results) => {
                if !match_results.is_empty() {
                    info!("模板 {} 匹配成功，发现 {} 个结果", template_id, match_results.len());

                    // 转换为TemplateResult格式
                    let template_result = TemplateResult {
                        template_id: template_id.clone(),
                        target_url: target_url.to_string(),
                        matched: true,
                        matched_matchers: vec!["enhanced_scan".to_string()],
                        extracted_vars: HashMap::new(),
                        response_info: None,
                        error: None,
                    };

                    // 添加到结果集合
                    results.lock().unwrap().push(template_result);
                } else {
                    // 如果增强扫描没有匹配，回退到原始方法
                    match self.template_engine.execute_template(&template, target_url).await {
                        Ok(result) => {
                            if result.matched {
                                info!("模板 {} 通过原始引擎匹配成功", template_id);


                            }

                            // 添加到结果集合
                            results.lock().unwrap().push(result);
                        }
                        Err(e) => {
                            warn!("模板 {} 执行失败: {}", template_id, e);

                            // 创建错误结果
                            let error_result = TemplateResult {
                                template_id: template_id.clone(),
                                target_url: target_url.to_string(),
                                matched: false,
                                matched_matchers: vec![],
                                extracted_vars: HashMap::new(),
                                response_info: None,
                                error: Some(e.to_string()),
                            };

                            results.lock().unwrap().push(error_result);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("模板 {} 增强扫描失败: {}", template_id, e);

                // 回退到原始方法
                match self.template_engine.execute_template(&template, target_url).await {
                    Ok(result) => {
                        if result.matched {
                            info!("模板 {} 通过原始引擎匹配成功", template_id);


                        }

                        results.lock().unwrap().push(result);
                    }
                    Err(e) => {
                        warn!("模板 {} 原始引擎也执行失败: {}", template_id, e);

                        // 创建错误结果
                        let error_result = TemplateResult {
                            template_id: template_id.clone(),
                            target_url: target_url.to_string(),
                            matched: false,
                            matched_matchers: vec![],
                            extracted_vars: HashMap::new(),
                            response_info: None,
                            error: Some(e.to_string()),
                        };

                        results.lock().unwrap().push(error_result);
                    }
                }
            }
        }
    }
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
