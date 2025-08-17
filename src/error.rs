use thiserror::Error;

pub type Result<T> = std::result::Result<T, ScanError>;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("DNS resolution error: {0}")]
    DnsResolution(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("SSH error: {0}")]
    Ssh(String),

    #[error("Database connection error: {0}")]
    Database(String),

    #[error("Authentication failed for {service} on {target}:{port}")]
    AuthenticationFailed {
        service: String,
        target: String,
        port: u16,
    },

    #[error("Timeout occurred during {operation}")]
    Timeout { operation: String },

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("Invalid target format: {0}")]
    InvalidTarget(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Exploitation failed: {0}")]
    ExploitationFailed(String),

    #[error("Vulnerability scan error: {0}")]
    VulnerabilityScan(String),

    #[error("Web scanning error: {0}")]
    WebScan(String),

    #[error("Brute force error: {0}")]
    BruteForce(String),

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Reporting error: {0}")]
    Reporting(String),

    #[error("Unknown error: {0}")]
    Unknown(String),

    #[error("Evasion error: {0}")]
    EvasionError(String),

    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("System error: {0}")]
    SystemError(String),
}

impl From<mysql_async::Error> for ScanError {
    fn from(err: mysql_async::Error) -> Self {
        ScanError::Database(format!("MySQL error: {}", err))
    }
}

impl From<tokio_postgres::Error> for ScanError {
    fn from(err: tokio_postgres::Error) -> Self {
        ScanError::Database(format!("PostgreSQL error: {}", err))
    }
}

impl From<redis::RedisError> for ScanError {
    fn from(err: redis::RedisError) -> Self {
        ScanError::Database(format!("Redis error: {}", err))
    }
}

impl From<tiberius::error::Error> for ScanError {
    fn from(err: tiberius::error::Error) -> Self {
        ScanError::Database(format!("SQL Server error: {}", err))
    }
}


