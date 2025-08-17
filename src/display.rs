use crate::types::{Vulnerability, Severity};
use colored::*;
use std::io::Write;

/// Enhanced display utilities for clean, colored output and formatting
pub struct DisplayManager {
    use_colors: bool,
    quiet_mode: bool,
}

impl DisplayManager {
    pub fn new() -> Self {
        Self::with_quiet(false)
    }
    
    pub fn with_quiet(quiet: bool) -> Self {
        // Simple check for color support - assume true for most terminals
        let use_colors = std::env::var("NO_COLOR").is_err() &&
                        std::env::var("TERM").map_or(true, |term| term != "dumb");

        Self {
            use_colors,
            quiet_mode: quiet,
        }
    }

    /// Print a clean vulnerability entry with enhanced formatting
    pub fn print_vulnerability(&self, vuln: &Vulnerability) {
        if self.quiet_mode { return; }
        
        let severity_color = self.get_severity_color(&vuln.severity);
        let severity_icon = self.get_severity_icon(&vuln.severity);
        
        if self.use_colors {
            println!("  {} {} {}", 
                severity_icon.color(severity_color),
                vuln.name.bright_white().bold(),
                format!("({})", vuln.target).bright_black()
            );
            
            if !vuln.description.is_empty() {
                println!("    └─ {}", vuln.description.white());
            }
            
            // Compact info display
            let mut info_parts = Vec::new();
            if let Some(port) = vuln.port {
                info_parts.push(format!("Port {}", port.to_string().yellow()));
            }
            if let Some(cvss) = vuln.cvss_score {
                let cvss_color = self.get_cvss_color(cvss);
                info_parts.push(format!("CVSS {}", format!("{:.1}", cvss).color(cvss_color).bold()));
            }
            if !info_parts.is_empty() {
                println!("    └─ {}", info_parts.join(" | ").bright_black());
            }
            
            if let Some(evidence) = &vuln.evidence {
                if !evidence.is_empty() {
                    println!("    └─ {}: {}", "Evidence".blue().bold(), evidence.cyan());
                }
            }
        } else {
            println!("  [{}] {} ({})", 
                format!("{:?}", vuln.severity).to_uppercase(), 
                vuln.name, 
                vuln.target
            );
            
            if !vuln.description.is_empty() {
                println!("    Description: {}", vuln.description);
            }
            
            if let Some(port) = vuln.port {
                println!("    Port: {}", port);
            }
            
            if let Some(cvss) = vuln.cvss_score {
                println!("    CVSS: {:.1}", cvss);
            }
            
            if let Some(evidence) = &vuln.evidence {
                if !evidence.is_empty() {
                    println!("    Evidence: {}", evidence);
                }
            }
        }
        println!(); // Add spacing
    }

    /// Print enhanced scan summary with statistics table
    pub fn print_scan_summary(&self, total_hosts: usize, total_vulns: usize, critical: usize, high: usize, medium: usize, low: usize) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            println!();
            self.print_section_header("📊 SCAN RESULTS SUMMARY");
            
            // Host statistics
            println!("  📡 {}: {}", 
                "Hosts Scanned".bright_white().bold(), 
                total_hosts.to_string().cyan().bold()
            );
            
            if total_vulns == 0 {
                println!("  ✨ {}", "No vulnerabilities found!".bright_green().bold());
                return;
            }
            
            println!("  🔍 {}: {}", 
                "Total Issues".bright_white().bold(), 
                total_vulns.to_string().yellow().bold()
            );
            
            println!();
            
            // Vulnerability breakdown table
            self.print_vulnerability_table(critical, high, medium, low);
            
        } else {
            println!("\n=== SCAN RESULTS SUMMARY ===");
            println!("Hosts Scanned: {}", total_hosts);
            if total_vulns == 0 {
                println!("No vulnerabilities found!");
                return;
            }
            println!("Total Issues: {}", total_vulns);
            println!();
            println!("Critical: {}", critical);
            println!("High: {}", high);
            println!("Medium: {}", medium);
            println!("Low: {}", low);
        }
        println!();
    }
    
    /// Print vulnerability breakdown as a clean table
    fn print_vulnerability_table(&self, critical: usize, high: usize, medium: usize, low: usize) {
        if !self.use_colors {
            return;
        }
        
        let vulnerabilities = [
            ("Critical", critical, Color::BrightRed, "🔥"),
            ("High", high, Color::Red, "⚠️"),
            ("Medium", medium, Color::Yellow, "⚡"),
            ("Low", low, Color::Green, "ℹ️"),
        ];
        
        // Only show non-zero vulnerabilities
        let active_vulns: Vec<_> = vulnerabilities.iter()
            .filter(|(_, count, _, _)| *count > 0)
            .collect();
            
        if active_vulns.is_empty() {
            return;
        }
        
        println!("  ┌─────────────┬───────┐");
        println!("  │ {} │ {} │", 
            "Severity".bright_white().bold(),
            "Count".bright_white().bold()
        );
        println!("  ├─────────────┼───────┤");
        
        for (name, count, color, icon) in active_vulns {
            println!("  │ {} {} │ {:>5} │", 
                icon,
                format!("{:<8}", name).color(*color).bold(),
                count.to_string().color(*color).bold()
            );
        }
        
        println!("  └─────────────┴───────┘");
    }

    /// Print a clean section header
    pub fn print_section_header(&self, title: &str) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            println!("{}", title.bright_cyan().bold());
            println!("{}", "─".repeat(title.chars().count()).bright_cyan());
        } else {
            println!("{}", title);
            println!("{}", "=".repeat(title.len()));
        }
    }

    /// Print a clean success message
    pub fn print_success(&self, message: &str) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            println!("  {} {}", "✓".bright_green().bold(), message.green());
        } else {
            println!("[✓] {}", message);
        }
    }

    /// Print a clean warning message
    pub fn print_warning(&self, message: &str) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            println!("  {} {}", "!".bright_yellow().bold(), message.yellow());
        } else {
            println!("[!] {}", message);
        }
    }

    /// Print a clean error message
    pub fn print_error(&self, message: &str) {
        if self.use_colors {
            eprintln!("  {} {}", "✗".bright_red().bold(), message.red().bold());
        } else {
            eprintln!("[✗] {}", message);
        }
    }

    /// Print a clean info message
    pub fn print_info(&self, message: &str) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            println!("  {} {}", "i".bright_blue().bold(), message.blue());
        } else {
            println!("[i] {}", message);
        }
    }

    /// Print compact exploitation result
    pub fn print_exploit_result(&self, target: &str, exploit_type: &str, success: bool, message: &str) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            let (status_icon, status_color) = if success { 
                ("✓", Color::BrightGreen) 
            } else { 
                ("✗", Color::BrightRed) 
            };
            
            println!("  {} {} {} → {}", 
                status_icon.color(status_color).bold(),
                target.bright_white().bold(),
                exploit_type.cyan(),
                message.white()
            );
        } else {
            println!("  [{}] {} {} → {}", 
                if success { "✓" } else { "✗" },
                target,
                exploit_type,
                message
            );
        }
    }

    /// Print enhanced progress with cleaner formatting
    pub fn print_progress(&self, current: usize, total: usize, message: &str) {
        if self.quiet_mode { return; }
        
        let percentage = (current as f64 / total as f64 * 100.0) as usize;
        
        if self.use_colors {
            let bar_length = 25;
            let filled = (current as f64 / total as f64 * bar_length as f64) as usize;
            let empty = bar_length - filled;
            
            let bar = format!("{}{}",
                "█".repeat(filled).bright_green(),
                "░".repeat(empty).bright_black()
            );
            
            print!("\r  {} [{}] {}% {}",
                "⠿".bright_blue().bold(),
                bar,
                format!("{:>3}", percentage).yellow().bold(),
                message.truncate_with_ellipsis(50).white()
            );
        } else {
            print!("\r  [{:>3}%] {}", percentage, message);
        }
        std::io::stdout().flush().unwrap();
    }

    /// Print discovery results in table format
    pub fn print_host_table(&self, hosts: &[std::net::IpAddr]) {
        if self.quiet_mode || hosts.is_empty() { return; }
        
        if self.use_colors {
            println!("\n  📡 {} {}", 
                "Discovered Hosts:".bright_white().bold(),
                format!("({})", hosts.len()).bright_black()
            );
            
            for (i, host) in hosts.iter().enumerate() {
                if i < 10 {  // Limit display to first 10 hosts
                    println!("    {} {}", "→".bright_green(), host.to_string().cyan());
                } else if i == 10 {
                    println!("    {} {} more hosts...", "...".bright_black(), hosts.len() - 10);
                    break;
                }
            }
        } else {
            println!("\nDiscovered Hosts ({}):", hosts.len());
            for host in hosts.iter().take(10) {
                println!("  → {}", host);
            }
            if hosts.len() > 10 {
                println!("  ... {} more hosts", hosts.len() - 10);
            }
        }
    }

    /// Print port scan results in compact format
    pub fn print_port_results(&self, target: &str, open_ports: &[(u16, Option<String>)]) {
        if self.quiet_mode { return; }
        
        if open_ports.is_empty() {
            if self.use_colors {
                println!("  {} {} - {}", 
                    "•".bright_black(), 
                    target.cyan(),
                    "No open ports".bright_black()
                );
            } else {
                println!("  • {} - No open ports", target);
            }
            return;
        }
        
        if self.use_colors {
            println!("  {} {} → {} ports", 
                "•".bright_green().bold(),
                target.cyan().bold(),
                open_ports.len().to_string().yellow().bold()
            );
            
            for (port, service) in open_ports.iter().take(5) {
                let service_str = service.as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                println!("    {} {}{}", 
                    "→".bright_green(),
                    port.to_string().yellow(),
                    service_str.bright_black()
                );
            }
            
            if open_ports.len() > 5 {
                println!("    {} {} more ports...", 
                    "...".bright_black(),
                    open_ports.len() - 5
                );
            }
        } else {
            println!("  • {} → {} ports", target, open_ports.len());
            for (port, service) in open_ports.iter().take(5) {
                let service_str = service.as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                println!("    → {}{}", port, service_str);
            }
            if open_ports.len() > 5 {
                println!("    ... {} more ports", open_ports.len() - 5);
            }
        }
    }

    /// Get severity icon
    fn get_severity_icon(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "🔥",
            Severity::High => "⚠️",
            Severity::Medium => "⚡",
            Severity::Low => "ℹ️",
            Severity::Info => "💡",
        }
    }

    /// Get color for severity level
    fn get_severity_color(&self, severity: &Severity) -> Color {
        match severity {
            Severity::Critical => Color::BrightRed,
            Severity::High => Color::Red,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Green,
            Severity::Info => Color::Blue,
        }
    }

    /// Get color for CVSS score
    fn get_cvss_color(&self, cvss: f32) -> Color {
        match cvss {
            score if score >= 9.0 => Color::BrightRed,
            score if score >= 7.0 => Color::Red,
            score if score >= 4.0 => Color::Yellow,
            _ => Color::Green,
        }
    }

    /// Clear the current line (for progress updates)
    pub fn clear_line(&self) {
        if self.use_colors {
            print!("\r{}", " ".repeat(80));
            print!("\r");
            std::io::stdout().flush().unwrap();
        }
    }
    
    /// Print a clean banner with enhanced styling
    pub fn print_banner(&self, title: &str, subtitle: Option<&str>) {
        if self.quiet_mode { return; }
        
        if self.use_colors {
            println!();
            println!("  {}", "┌─".bright_cyan().to_string() + &"─".repeat(title.len() + 2) + "─┐");
            println!("  {} {} {}", 
                "│".bright_cyan(), 
                title.bright_white().bold(),
                "│".bright_cyan()
            );
            if let Some(sub) = subtitle {
                println!("  {} {} {}", 
                    "│".bright_cyan(), 
                    format!("{:^width$}", sub, width = title.len()).bright_black(),
                    "│".bright_cyan()
                );
            }
            println!("  {}", "└─".bright_cyan().to_string() + &"─".repeat(title.len() + 2) + "─┘");
            println!();
        } else {
            let border = "=".repeat(title.len() + 4);
            println!("\n{}", border);
            println!("  {}  ", title);
            if let Some(sub) = subtitle {
                println!("  {}  ", sub);
            }
            println!("{}\n", border);
        }
    }
}

impl Default for DisplayManager {
    fn default() -> Self {
        Self::new()
    }
}

/// String extension trait for better output formatting
trait StringExt {
    fn truncate_with_ellipsis(&self, max_len: usize) -> String;
}

impl StringExt for str {
    fn truncate_with_ellipsis(&self, max_len: usize) -> String {
        if self.len() <= max_len {
            self.to_string()
        } else {
            format!("{}...", &self[..max_len.saturating_sub(3)])
        }
    }
}
