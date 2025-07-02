//! Rscan - Comprehensive Internal Network Scanning Tool
//! 
//! This library provides a comprehensive set of tools for internal network
//! vulnerability assessment and penetration testing.
//! 
//! # Warning
//! This tool is designed for ethical penetration testing and security assessment
//! purposes only. Users are responsible for ensuring they have proper authorization
//! before scanning any networks or systems.

pub mod cli;
pub mod config;
pub mod discovery;
pub mod brute_force;
pub mod web_scan;
pub mod vuln_scan;
pub mod exploit;
pub mod poc;
pub mod reporting;
pub mod evasion;
pub mod display;
pub mod utils;
pub mod error;

pub use error::{Result, ScanError};

/// Common types and traits used throughout the application
pub mod types {
    use serde::{Deserialize, Serialize};
    use std::net::IpAddr;
    use chrono::{DateTime, Utc};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Target {
        pub ip: IpAddr,
        pub hostname: Option<String>,
        pub ports: Vec<Port>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Port {
        pub number: u16,
        pub protocol: Protocol,
        pub state: PortState,
        pub service: Option<Service>,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
    pub enum Protocol {
        Tcp,
        Udp,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum PortState {
        Open,
        Closed,
        Filtered,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Service {
        pub name: String,
        pub version: Option<String>,
        pub banner: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Vulnerability {
        pub id: String,
        pub name: String,
        pub description: String,
        pub severity: Severity,
        pub target: IpAddr,
        pub port: Option<u16>,
        pub evidence: Option<String>,
        pub discovered_at: DateTime<Utc>,
        pub cvss_score: Option<f32>,
        pub cve_id: Option<String>,
        pub category: VulnerabilityCategory,
        pub remediation: Option<String>,
        pub references: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Severity {
        Critical,
        High,
        Medium,
        Low,
        Info,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum VulnerabilityCategory {
        NetworkService,
        WebApplication,
        Authentication,
        Configuration,
        Encryption,
        AccessControl,
        InputValidation,
        InformationDisclosure,
        DenialOfService,
        CodeExecution,
        PrivilegeEscalation,
        Other,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ScanResult {
        pub scan_id: String,
        pub targets: Vec<Target>,
        pub vulnerabilities: Vec<Vulnerability>,
        pub started_at: DateTime<Utc>,
        pub completed_at: Option<DateTime<Utc>>,
        pub scan_type: ScanType,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum ScanType {
        Discovery,
        PortScan,
        VulnerabilityScan,
        BruteForce,
        WebScan,
        FullScan,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Credentials {
        pub username: String,
        pub password: String,
        pub service: String,
        pub target: IpAddr,
        pub port: u16,
    }
}
