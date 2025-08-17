use clap::Parser;
use env_logger::Env;
use rscan::{
    cli::{Cli, Commands},
    config::Config,
    discovery::NetworkDiscovery,
    display::DisplayManager,
    Result,
};
use std::process;
use std::time::SystemTime;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info", 
            2 => "debug",
            _ => "trace",
        }
    };

    env_logger::Builder::from_env(Env::default().default_filter_or(log_level))
        .format_timestamp_secs()
        .init();

    let display = DisplayManager::with_quiet(cli.quiet);

    if !cli.quiet {
        display.print_banner(
            "🔒 RSCAN - Network Security Scanner", 
            Some("Authorized Testing Only")
        );
        display.print_warning("Ensure you have proper permission before scanning any networks.");
        println!();
    }

    let mut config = if let Some(config_path) = &cli.config {
        match Config::load_from_file(&config_path.to_string_lossy()) {
            Ok(config) => {
                if !cli.quiet {
                    display.print_success(&format!("Loaded configuration from {}", config_path.display()));
                }
                config
            },
            Err(e) => {
                display.print_warning(&format!("Failed to load configuration: {}, using defaults", e));
                Config::default()
            }
        }
    } else {
        Config::default()
    };

    config.scan.threads = cli.threads;
    config.scan.timeout = cli.timeout;
    config.scan.rate_limit = cli.rate_limit;
    config.reporting.output_dir = cli.output.clone();

    if cli.enable_evasion {
        config.evasion.enabled = true;
        if let Some(timing) = cli.timing {
            config.evasion.timing_template = timing;
        }
        if cli.use_tor {
            config.evasion.use_tor = true;
        }
        if let Some(proxy) = &cli.http_proxy {
            config.evasion.http_proxy = Some(proxy.clone());
        }
        if let Some(proxy) = &cli.socks_proxy {
            config.evasion.socks_proxy = Some(proxy.clone());
        }
        if cli.decoy_traffic {
            config.evasion.generate_decoy_traffic = true;
        }
        
        if !cli.quiet {
            display.print_info("Evasion techniques enabled");
        }
    }

    let start_time = SystemTime::now();

    let result = match &cli.command {
        Commands::Discovery { target, .. } => {
            execute_discovery(&config, &display, target).await
        }
        Commands::PortScan { target, ports, .. } => {
            execute_port_scan(&config, &display, target, &Some(ports.clone())).await
        }
        Commands::BruteForce { target, service, .. } => {
            if let Some(service) = service {
                execute_brute_force(&config, &display, target, service).await
            } else {
                display.print_error("Service type must be specified for brute force attacks");
                return;
            }
        }
        Commands::WebScan { target, .. } => {
            execute_web_scan(&config, &display, target).await
        }
        Commands::VulnScan { target, .. } => {
            execute_vuln_scan(&config, &display, target).await
        }
        Commands::Exploit { target, exploit_type, .. } => {
            execute_exploit(&config, &display, target, exploit_type).await
        }
        Commands::Poc { target, poc_type, domain, username, password, wordlist, ntlm_hash, spn, output_file, interface, safe_mode, .. } => {
            execute_poc(&config, &display, target, poc_type, domain, username, password, wordlist, ntlm_hash, spn, output_file, interface, *safe_mode).await
        }
        Commands::FullScan { target, .. } => {
            execute_full_scan(&config, &display, target).await
        }
    };

    let elapsed = start_time.elapsed().unwrap_or_default();

    match result {
        Ok(_) => {
            if !cli.quiet {
                display.print_success(&format!("Scan completed in {}", rscan::utils::time::format_duration(elapsed)));
            }
        }
        Err(e) => {
            display.print_error(&format!("Scan failed: {}", e));
            process::exit(1);
        }
    }
}

async fn execute_discovery(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
) -> Result<()> {
    display.print_section_header("🔍 HOST DISCOVERY");
    
    let discovery = NetworkDiscovery::new(config.clone())?;
    let live_hosts = discovery.discover_hosts(targets).await?;

    if live_hosts.is_empty() {
        display.print_warning("No live hosts found in target range");
        return Ok(());
    }

    display.print_host_table(&live_hosts);
    display.print_success(&format!("Discovery completed: {} live hosts found", live_hosts.len()));

    Ok(())
}

async fn execute_port_scan(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
    ports: &Option<String>,
) -> Result<()> {
    display.print_section_header("🔍 PORT SCANNING");

    let discovery = NetworkDiscovery::new(config.clone())?;
    let live_hosts = discovery.discover_hosts(targets).await?;

    if live_hosts.is_empty() {
        display.print_warning("No live hosts found");
        return Ok(());
    }

    display.print_info(&format!("Scanning {} hosts for open ports", live_hosts.len()));

    let port_range = ports.as_deref().unwrap_or("1-1000");
    let mut total_open_ports = 0;
    
    for &target in &live_hosts {
        let scan_results = discovery.scan_ports(&[target], port_range).await?;
        
        for target_result in &scan_results {
            let port_info: Vec<(u16, Option<String>)> = target_result.ports.iter()
                .filter(|p| matches!(p.state, rscan::types::PortState::Open))
                .map(|p| (p.number, p.service.as_ref().map(|s| s.name.clone())))
                .collect();
            
            display.print_port_results(&target_result.ip.to_string(), &port_info);
            total_open_ports += port_info.len();
        }
    }

    display.print_success(&format!("Port scan completed: {} total open ports found", total_open_ports));

    Ok(())
}

async fn execute_brute_force(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
    service: &rscan::cli::ServiceType,
) -> Result<()> {
    display.print_section_header(&format!("🔓 {} BRUTE FORCE", service.to_string().to_uppercase()));

    let discovery = NetworkDiscovery::new(config.clone())?;
    let live_hosts = discovery.discover_hosts(targets).await?;

    if live_hosts.is_empty() {
        display.print_warning("No live hosts found");
        return Ok(());
    }

    display.print_info(&format!("Testing {} hosts", live_hosts.len()));
    
    match service {
        rscan::cli::ServiceType::Ssh => {
            display.print_info("SSH brute force attack simulation");
            display.print_warning("This is a demonstration - implement actual SSH brute forcing in production");
        }
        _ => {
            display.print_warning(&format!("Service type {:?} not yet implemented", service));
        }
    }

    display.print_info("Brute force scan completed");
    Ok(())
}

async fn execute_web_scan(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
) -> Result<()> {
    display.print_section_header("🌐 WEB APPLICATION SCAN");

    let mut web_scanner = rscan::web_scan::WebScanner::new(config.clone())?;

    // 加载所有模板
    display.print_info("Loading security templates...");
    match web_scanner.load_templates_from_directory("templates") {
        Ok(loaded_count) => {
            display.print_info(&format!("Successfully loaded {} templates from directory", loaded_count));
        }
        Err(e) => {
            display.print_warning(&format!("Failed to load templates from directory: {}", e));
            // 如果目录加载失败，尝试加载默认模板作为备选
            display.print_info("Attempting to load default templates as fallback...");
            if let Err(e) = web_scanner.load_template("templates/basic-info-disclosure.yaml") {
                display.print_warning(&format!("Failed to load basic template: {}", e));
            }
            if let Err(e) = web_scanner.load_template("templates/advanced-web-scan.yaml") {
                display.print_warning(&format!("Failed to load advanced template: {}", e));
            }
        }
    }

    let template_count = web_scanner.get_loaded_templates_count();
    display.print_info(&format!("Loaded {} security templates", template_count));

    for target in targets {
        display.print_info(&format!("🎯 Scanning {}", target));
        // 模板扫描（并行+流式输出）
        if template_count > 0 {
            display.print_info(&format!("🔍 Running parallel template scan on {} ({} templates)", target, template_count));

            // 使用并行扫描，设置合理的并发数
            let max_concurrent = if template_count > 100 { 50 } else { template_count.min(20) };

            let start_time = std::time::Instant::now();
            match web_scanner.scan_with_templates(target, None, Some(max_concurrent)).await {
                Ok(results) => {
                    let scan_duration = start_time.elapsed();
                    let final_matched_count = results.iter().filter(|r| r.matched).count();

                    // 显示所有匹配的结果
                    for result in &results {
                        if result.matched {
                            display.print_warning(&format!("🎯 发现漏洞: {} (模板: {})",
                                result.template_id, result.template_id));
                            for matcher in &result.matched_matchers {
                                display.print_info(&format!("    - 匹配器: {}", matcher));
                            }
                        }
                    }

                    if final_matched_count > 0 {
                        display.print_warning(&format!("⚠️  总计发现 {} 个安全问题 (耗时: {:.2}s, 并发: {})",
                            final_matched_count, scan_duration.as_secs_f64(), max_concurrent));
                    } else {
                        display.print_success(&format!("✅ No security issues detected by templates (耗时: {:.2}s, 并发: {})",
                            scan_duration.as_secs_f64(), max_concurrent));
                    }
                }
                Err(e) => {
                    display.print_warning(&format!("❌ Parallel template scan failed: {}", e));
                }
            }
        }

        // DSL表达式扫描
        display.print_info(&format!("🧮 Running DSL security checks on {}", target));
        let dsl_expressions = vec![
            "status_code == 200".to_string(),
            "len(body) > 100".to_string(),
            "contains(to_lower(headers), 'server')".to_string(),
            "contains(to_lower(body), 'admin') || contains(to_lower(body), 'login')".to_string(),
            "contains(to_lower(body), 'error') || contains(to_lower(body), 'exception')".to_string(),
            "!contains(to_lower(headers), 'x-frame-options')".to_string(),
            "!contains(to_lower(headers), 'x-xss-protection')".to_string(),
        ];

        match web_scanner.scan_with_dsl(target, &dsl_expressions).await {
            Ok(results) => {
                let descriptions = vec![
                    "Successful response",
                    "Non-empty content",
                    "Server header present",
                    "Admin/login content detected",
                    "Error information disclosure",
                    "Missing X-Frame-Options header",
                    "Missing X-XSS-Protection header",
                ];

                for (i, (result, desc)) in results.iter().zip(descriptions.iter()).enumerate() {
                    if *result {
                        if i >= 3 { // 安全问题
                            display.print_warning(&format!("  ⚠️  {}", desc));
                        } else { // 正常信息
                            display.print_info(&format!("  ✅ {}", desc));
                        }
                    }
                }
            }
            Err(e) => {
                display.print_warning(&format!("❌ DSL scan failed: {}", e));
            }
        }

        println!(); // 分隔不同目标的输出
    }

    display.print_success("🎉 Web application scan completed");
    Ok(())
}

async fn execute_vuln_scan(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
) -> Result<()> {
    display.print_section_header("🔍 VULNERABILITY SCAN");

    let discovery = NetworkDiscovery::new(config.clone())?;
    let live_hosts = discovery.discover_hosts(targets).await?;

    if live_hosts.is_empty() {
        display.print_warning("No live hosts found");
        return Ok(());
    }

    let vuln_scanner = rscan::vuln_scan::VulnerabilityScanner::new(config.clone());

    for &target in &live_hosts {
        display.print_info(&format!("Scanning {}", target));
        
        let vulnerabilities = vuln_scanner.scan_target(target).await?;
        
        if vulnerabilities.is_empty() {
            display.print_success(&format!("No vulnerabilities found on {}", target));
        } else {
            for vuln in &vulnerabilities {
                display.print_vulnerability(&vuln);
            }
        }
    }

    display.print_success("Vulnerability scan completed");
    Ok(())
}

async fn execute_exploit(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
    exploit_type: &rscan::cli::ExploitType,
) -> Result<()> {
    display.print_section_header("🎯 EXPLOITATION");
    display.print_warning("Exploitation mode enabled - use with extreme caution!");

    let discovery = NetworkDiscovery::new(config.clone())?;
    let live_hosts = discovery.discover_hosts(targets).await?;

    if live_hosts.is_empty() {
        display.print_warning("No live hosts found");
        return Ok(());
    }

    for &target in &live_hosts {
        match exploit_type {
            rscan::cli::ExploitType::Ms17010 => {
                display.print_exploit_result(&target.to_string(), "MS17-010", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Ms08067 => {
                display.print_exploit_result(&target.to_string(), "MS08-067", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::SmbNullSession => {
                display.print_exploit_result(&target.to_string(), "SMB Null Session", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::NtlmRelay => {
                display.print_exploit_result(&target.to_string(), "NTLM Relay", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Kerberoasting => {
                display.print_exploit_result(&target.to_string(), "Kerberoasting", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::AsrepRoasting => {
                display.print_exploit_result(&target.to_string(), "ASREPRoasting", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::GoldenTicket => {
                display.print_exploit_result(&target.to_string(), "Golden Ticket", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::SilverTicket => {
                display.print_exploit_result(&target.to_string(), "Silver Ticket", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Zerologon => {
                display.print_exploit_result(&target.to_string(), "Zerologon", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Dcsync => {
                display.print_exploit_result(&target.to_string(), "DCSync", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::LlmnrPoisoning => {
                display.print_exploit_result(&target.to_string(), "LLMNR Poisoning", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Mitm6 => {
                display.print_exploit_result(&target.to_string(), "mitm6", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::ResponderAttack => {
                display.print_exploit_result(&target.to_string(), "Responder Attack", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::ArpSpoofing => {
                display.print_exploit_result(&target.to_string(), "ARP Spoofing", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Redis => {
                display.print_exploit_result(&target.to_string(), "Redis", false, "Redis exploitation simulation");
            }
            rscan::cli::ExploitType::Ssh => {
                display.print_warning("SSH exploitation requires valid credentials");
            }
            rscan::cli::ExploitType::SqlInjection => {
                display.print_exploit_result(&target.to_string(), "SQL Injection", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::XssAttack => {
                display.print_exploit_result(&target.to_string(), "XSS Attack", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Lfi => {
                display.print_exploit_result(&target.to_string(), "LFI", false, "Exploitation simulation - not implemented");
            }
            rscan::cli::ExploitType::Rfi => {
                display.print_exploit_result(&target.to_string(), "RFI", false, "Exploitation simulation - not implemented");
            }
        }
    }

    Ok(())
}

async fn execute_poc(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
    poc_type: &rscan::cli::PocType,
    domain: &Option<String>,
    username: &Option<String>,
    password: &Option<String>,
    wordlist: &Option<std::path::PathBuf>,
    ntlm_hash: &Option<String>,
    spn: &Option<String>,
    output_file: &Option<std::path::PathBuf>,
    interface: &Option<String>,
    safe_mode: bool,
) -> Result<()> {
    use rscan::poc::{PocEngine, PocOptions};

    display.print_section_header("🎯 PROOF-OF-CONCEPT EXPLOITATION");
    
    if safe_mode {
        display.print_warning("🛡️  SAFE MODE ENABLED - All POCs will be simulated");
    } else {
        display.print_warning("⚠️  DANGER: Real exploitation mode - use with extreme caution!");
    }

    let poc_engine = PocEngine::new(config.clone(), safe_mode);
    
    let poc_options = PocOptions {
        domain: domain.clone(),
        username: username.clone(),
        password: password.clone(),
        wordlist: wordlist.clone(),
        ntlm_hash: ntlm_hash.clone(),
        spn: spn.clone(),
        output_file: output_file.clone(),
        interface: interface.clone(),
    };

    let discovery = NetworkDiscovery::new(config.clone())?;
    let live_hosts = discovery.discover_hosts(targets).await?;

    if live_hosts.is_empty() {
        display.print_warning("No live hosts found");
        return Ok(());
    }

    display.print_info(&format!("Executing POC {:?} against {} targets", poc_type, live_hosts.len()));

    let mut successful_exploits = 0;

    for &target in &live_hosts {
        match poc_engine.execute_poc(target, poc_type.clone(), poc_options.clone()).await {
            Ok(result) => {
                if result.success {
                    successful_exploits += 1;
                    if result.simulated {
                        display.print_exploit_result(
                            &target.to_string(),
                            &result.poc_name,
                            true,
                            &format!("SIMULATION: {}", result.message)
                        );
                    } else {
                        display.print_exploit_result(
                            &target.to_string(),
                            &result.poc_name,
                            true,
                            &result.message
                        );
                    }
                    
                    if !result.details.is_empty() {
                        display.print_info(&format!("  Details: {}", result.details));
                    }
                } else {
                    display.print_exploit_result(
                        &target.to_string(),
                        &result.poc_name,
                        false,
                        &result.message
                    );
                }
            }
            Err(e) => {
                display.print_exploit_result(
                    &target.to_string(),
                    &format!("{:?}", poc_type),
                    false,
                    &format!("Error: {}", e)
                );
            }
        }
    }

    if successful_exploits > 0 {
        display.print_success(&format!("POC completed: {}/{} targets affected", successful_exploits, live_hosts.len()));
    } else {
        display.print_info("POC completed: No successful exploits");
    }

    Ok(())
}

async fn execute_full_scan(
    config: &Config,
    display: &DisplayManager,
    targets: &[String],
) -> Result<()> {
    display.print_section_header("🚀 COMPREHENSIVE SCAN");
    display.print_info(&format!("Starting full scan of {} targets", targets.len()));

    let start_time = SystemTime::now();

    display.print_info("Phase 1: Host Discovery");
    execute_discovery(config, display, targets).await?;

    display.print_info("Phase 2: Port Scanning");
    execute_port_scan(config, display, targets, &None).await?;

    display.print_info("Phase 3: Vulnerability Assessment");
    execute_vuln_scan(config, display, targets).await?;

    let elapsed = start_time.elapsed().unwrap_or_default();
    display.print_success(&format!("Full scan completed in {}", rscan::utils::time::format_duration(elapsed)));

    Ok(())
}
