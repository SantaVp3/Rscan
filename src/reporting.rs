use crate::{Result, ScanError};
use crate::types::{ScanResult, Target, Vulnerability, Severity};
use crate::config::{Config, OutputFormat};
use chrono::{DateTime, Utc};
use log::{debug, info};
use serde_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;

pub struct ReportGenerator {
    config: Config,
}

impl ReportGenerator {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn generate_report(&self, scan_result: &ScanResult) -> Result<Vec<PathBuf>> {
        let mut generated_files = Vec::new();
        
        // Create output directory if it doesn't exist
        fs::create_dir_all(&self.config.reporting.output_dir).await
            .map_err(|e| ScanError::Reporting(format!("Failed to create output directory: {}", e)))?;
        
        let timestamp = scan_result.started_at.format("%Y%m%d_%H%M%S");
        let base_filename = format!("rscan_report_{}", timestamp);
        
        for format in &self.config.reporting.formats {
            let file_path = match format {
                OutputFormat::Json => {
                    let path = self.config.reporting.output_dir.join(format!("{}.json", base_filename));
                    self.generate_json_report(scan_result, &path).await?;
                    path
                }
                OutputFormat::Csv => {
                    let path = self.config.reporting.output_dir.join(format!("{}.csv", base_filename));
                    self.generate_csv_report(scan_result, &path).await?;
                    path
                }
                OutputFormat::Html => {
                    let path = self.config.reporting.output_dir.join(format!("{}.html", base_filename));
                    self.generate_html_report(scan_result, &path).await?;
                    path
                }
                OutputFormat::Xml => {
                    let path = self.config.reporting.output_dir.join(format!("{}.xml", base_filename));
                    self.generate_xml_report(scan_result, &path).await?;
                    path
                }
            };
            
            generated_files.push(file_path);
        }
        
        info!("Generated {} report files", generated_files.len());
        Ok(generated_files)
    }

    async fn generate_json_report(&self, scan_result: &ScanResult, path: &Path) -> Result<()> {
        debug!("Generating JSON report: {}", path.display());
        
        let json_data = if self.config.reporting.include_raw_data {
            serde_json::to_string_pretty(scan_result)?
        } else {
            // Create a summary version without raw data
            let summary = ScanSummary::from_scan_result(scan_result);
            serde_json::to_string_pretty(&summary)?
        };
        
        fs::write(path, json_data).await
            .map_err(|e| ScanError::Reporting(format!("Failed to write JSON report: {}", e)))?;
        
        Ok(())
    }

    async fn generate_csv_report(&self, scan_result: &ScanResult, path: &Path) -> Result<()> {
        debug!("Generating CSV report: {}", path.display());
        
        let mut csv_content = String::new();
        
        // Vulnerabilities CSV
        csv_content.push_str("Type,Target,Port,Vulnerability ID,Name,Severity,Description,Evidence,Discovered At\n");
        
        for vuln in &scan_result.vulnerabilities {
            csv_content.push_str(&format!(
                "Vulnerability,{},{},{},{},{:?},{},{},{}\n",
                vuln.target,
                vuln.port.map(|p| p.to_string()).unwrap_or_default(),
                vuln.id,
                vuln.name.replace(',', ";"),
                vuln.severity,
                vuln.description.replace(',', ";"),
                vuln.evidence.as_ref().unwrap_or(&String::new()).replace(',', ";"),
                vuln.discovered_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        
        // Targets and ports CSV
        for target in &scan_result.targets {
            for port in &target.ports {
                csv_content.push_str(&format!(
                    "Port,{},{},{},{},{},{},{},{}\n",
                    target.ip,
                    port.number,
                    format!("{:?}", port.protocol),
                    format!("{:?}", port.state),
                    port.service.as_ref().map(|s| s.name.as_str()).unwrap_or(""),
                    port.service.as_ref().and_then(|s| s.version.as_ref()).unwrap_or(&String::new()),
                    port.service.as_ref().and_then(|s| s.banner.as_ref()).unwrap_or(&String::new()).replace(',', ";"),
                    ""
                ));
            }
        }
        
        fs::write(path, csv_content).await
            .map_err(|e| ScanError::Reporting(format!("Failed to write CSV report: {}", e)))?;
        
        Ok(())
    }

    async fn generate_html_report(&self, scan_result: &ScanResult, path: &Path) -> Result<()> {
        debug!("Generating HTML report: {}", path.display());
        
        let html_content = self.create_html_report(scan_result);
        
        fs::write(path, html_content).await
            .map_err(|e| ScanError::Reporting(format!("Failed to write HTML report: {}", e)))?;
        
        Ok(())
    }

    async fn generate_xml_report(&self, scan_result: &ScanResult, path: &Path) -> Result<()> {
        debug!("Generating XML report: {}", path.display());
        
        let xml_content = self.create_xml_report(scan_result);
        
        fs::write(path, xml_content).await
            .map_err(|e| ScanError::Reporting(format!("Failed to write XML report: {}", e)))?;
        
        Ok(())
    }

    fn create_html_report(&self, scan_result: &ScanResult) -> String {
        let mut html = String::new();
        
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<title>Rscan Security Assessment Report</title>\n");
        html.push_str("<style>\n");
        html.push_str(include_str!("../assets/report.css"));
        html.push_str("</style>\n</head>\n<body>\n");
        
        // Header
        html.push_str("<div class='header'>\n");
        html.push_str("<h1>🔒 Rscan Security Assessment Report</h1>\n");
        html.push_str(&format!("<p>Scan ID: {}</p>\n", scan_result.scan_id));
        html.push_str(&format!("<p>Started: {}</p>\n", scan_result.started_at.format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(completed) = scan_result.completed_at {
            html.push_str(&format!("<p>Completed: {}</p>\n", completed.format("%Y-%m-%d %H:%M:%S UTC")));
        }
        html.push_str("</div>\n");
        
        // Executive Summary
        html.push_str("<div class='section'>\n<h2>Executive Summary</h2>\n");
        let summary = self.generate_executive_summary(scan_result);
        html.push_str(&format!("<p>{}</p>\n", summary));
        html.push_str("</div>\n");
        
        // Vulnerability Summary
        html.push_str("<div class='section'>\n<h2>Vulnerability Summary</h2>\n");
        let vuln_stats = self.calculate_vulnerability_stats(scan_result);
        html.push_str("<table class='vuln-summary'>\n");
        html.push_str("<tr><th>Severity</th><th>Count</th></tr>\n");
        for (severity, count) in vuln_stats {
            let class = match severity.as_str() {
                "Critical" => "critical",
                "High" => "high",
                "Medium" => "medium",
                "Low" => "low",
                _ => "info",
            };
            html.push_str(&format!("<tr class='{}'><td>{}</td><td>{}</td></tr>\n", class, severity, count));
        }
        html.push_str("</table>\n</div>\n");
        
        // Detailed Vulnerabilities
        if !scan_result.vulnerabilities.is_empty() {
            html.push_str("<div class='section'>\n<h2>Detailed Vulnerabilities</h2>\n");
            for vuln in &scan_result.vulnerabilities {
                html.push_str("<div class='vulnerability'>\n");
                html.push_str(&format!("<h3>{}</h3>\n", vuln.name));
                html.push_str(&format!("<p><strong>Target:</strong> {}</p>\n", vuln.target));
                if let Some(port) = vuln.port {
                    html.push_str(&format!("<p><strong>Port:</strong> {}</p>\n", port));
                }
                html.push_str(&format!("<p><strong>Severity:</strong> {:?}</p>\n", vuln.severity));
                html.push_str(&format!("<p><strong>Description:</strong> {}</p>\n", vuln.description));
                if let Some(evidence) = &vuln.evidence {
                    html.push_str(&format!("<p><strong>Evidence:</strong> {}</p>\n", evidence));
                }
                html.push_str("</div>\n");
            }
            html.push_str("</div>\n");
        }
        
        // Target Information
        html.push_str("<div class='section'>\n<h2>Target Information</h2>\n");
        for target in &scan_result.targets {
            html.push_str("<div class='target'>\n");
            html.push_str(&format!("<h3>{}</h3>\n", target.ip));
            if let Some(hostname) = &target.hostname {
                html.push_str(&format!("<p><strong>Hostname:</strong> {}</p>\n", hostname));
            }
            
            if !target.ports.is_empty() {
                html.push_str("<h4>Open Ports</h4>\n<ul>\n");
                for port in &target.ports {
                    html.push_str(&format!("<li>{}/{:?} - {}</li>\n", 
                        port.number, 
                        port.protocol,
                        port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown")
                    ));
                }
                html.push_str("</ul>\n");
            }
            html.push_str("</div>\n");
        }
        html.push_str("</div>\n");
        
        html.push_str("</body>\n</html>");
        html
    }

    fn create_xml_report(&self, scan_result: &ScanResult) -> String {
        let mut xml = String::new();
        
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<rscan_report>\n");
        xml.push_str(&format!("  <scan_id>{}</scan_id>\n", scan_result.scan_id));
        xml.push_str(&format!("  <started_at>{}</started_at>\n", scan_result.started_at.to_rfc3339()));
        if let Some(completed) = scan_result.completed_at {
            xml.push_str(&format!("  <completed_at>{}</completed_at>\n", completed.to_rfc3339()));
        }
        xml.push_str(&format!("  <scan_type>{:?}</scan_type>\n", scan_result.scan_type));
        
        // Targets
        xml.push_str("  <targets>\n");
        for target in &scan_result.targets {
            xml.push_str("    <target>\n");
            xml.push_str(&format!("      <ip>{}</ip>\n", target.ip));
            if let Some(hostname) = &target.hostname {
                xml.push_str(&format!("      <hostname>{}</hostname>\n", hostname));
            }
            
            xml.push_str("      <ports>\n");
            for port in &target.ports {
                xml.push_str("        <port>\n");
                xml.push_str(&format!("          <number>{}</number>\n", port.number));
                xml.push_str(&format!("          <protocol>{:?}</protocol>\n", port.protocol));
                xml.push_str(&format!("          <state>{:?}</state>\n", port.state));
                if let Some(service) = &port.service {
                    xml.push_str("          <service>\n");
                    xml.push_str(&format!("            <name>{}</name>\n", service.name));
                    if let Some(version) = &service.version {
                        xml.push_str(&format!("            <version>{}</version>\n", version));
                    }
                    xml.push_str("          </service>\n");
                }
                xml.push_str("        </port>\n");
            }
            xml.push_str("      </ports>\n");
            xml.push_str("    </target>\n");
        }
        xml.push_str("  </targets>\n");
        
        // Vulnerabilities
        xml.push_str("  <vulnerabilities>\n");
        for vuln in &scan_result.vulnerabilities {
            xml.push_str("    <vulnerability>\n");
            xml.push_str(&format!("      <id>{}</id>\n", vuln.id));
            xml.push_str(&format!("      <name>{}</name>\n", vuln.name));
            xml.push_str(&format!("      <severity>{:?}</severity>\n", vuln.severity));
            xml.push_str(&format!("      <target>{}</target>\n", vuln.target));
            if let Some(port) = vuln.port {
                xml.push_str(&format!("      <port>{}</port>\n", port));
            }
            xml.push_str(&format!("      <description>{}</description>\n", vuln.description));
            if let Some(evidence) = &vuln.evidence {
                xml.push_str(&format!("      <evidence>{}</evidence>\n", evidence));
            }
            xml.push_str(&format!("      <discovered_at>{}</discovered_at>\n", vuln.discovered_at.to_rfc3339()));
            xml.push_str("    </vulnerability>\n");
        }
        xml.push_str("  </vulnerabilities>\n");
        
        xml.push_str("</rscan_report>\n");
        xml
    }

    fn generate_executive_summary(&self, scan_result: &ScanResult) -> String {
        let target_count = scan_result.targets.len();
        let vuln_count = scan_result.vulnerabilities.len();
        let critical_count = scan_result.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::Critical))
            .count();
        let high_count = scan_result.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::High))
            .count();
        
        format!(
            "This security assessment scanned {} targets and identified {} vulnerabilities. \
            Of these, {} are critical severity and {} are high severity, requiring immediate attention. \
            The scan was performed using Rscan, a comprehensive network security scanner.",
            target_count, vuln_count, critical_count, high_count
        )
    }

    fn calculate_vulnerability_stats(&self, scan_result: &ScanResult) -> Vec<(String, usize)> {
        let mut stats = HashMap::new();
        
        for vuln in &scan_result.vulnerabilities {
            let severity = format!("{:?}", vuln.severity);
            *stats.entry(severity).or_insert(0) += 1;
        }
        
        let mut result: Vec<_> = stats.into_iter().collect();
        result.sort_by(|a, b| {
            let order = ["Critical", "High", "Medium", "Low", "Info"];
            let a_pos = order.iter().position(|&x| x == a.0).unwrap_or(999);
            let b_pos = order.iter().position(|&x| x == b.0).unwrap_or(999);
            a_pos.cmp(&b_pos)
        });
        
        result
    }
}

#[derive(serde::Serialize)]
struct ScanSummary {
    scan_id: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    target_count: usize,
    vulnerability_count: usize,
    critical_vulnerabilities: usize,
    high_vulnerabilities: usize,
    medium_vulnerabilities: usize,
    low_vulnerabilities: usize,
}

impl ScanSummary {
    fn from_scan_result(scan_result: &ScanResult) -> Self {
        let critical_count = scan_result.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::Critical))
            .count();
        let high_count = scan_result.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::High))
            .count();
        let medium_count = scan_result.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::Medium))
            .count();
        let low_count = scan_result.vulnerabilities.iter()
            .filter(|v| matches!(v.severity, Severity::Low))
            .count();
        
        Self {
            scan_id: scan_result.scan_id.clone(),
            started_at: scan_result.started_at,
            completed_at: scan_result.completed_at,
            target_count: scan_result.targets.len(),
            vulnerability_count: scan_result.vulnerabilities.len(),
            critical_vulnerabilities: critical_count,
            high_vulnerabilities: high_count,
            medium_vulnerabilities: medium_count,
            low_vulnerabilities: low_count,
        }
    }
}
