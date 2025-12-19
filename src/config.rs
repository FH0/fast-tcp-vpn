//! Configuration Management Module
//!
//! Provides configuration structures for server and client modes,
//! TOML parsing, and configuration validation.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

/// Configuration error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// File not found
    FileNotFound(String),
    /// Parse error
    ParseError(String),
    /// Validation error
    ValidationError(String),
    /// IO error
    IoError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FileNotFound(path) => write!(f, "Config file not found: {}", path),
            ConfigError::ParseError(msg) => write!(f, "Config parse error: {}", msg),
            ConfigError::ValidationError(msg) => write!(f, "Config validation error: {}", msg),
            ConfigError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Network configuration shared between server and client
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Local bind address for raw socket
    pub bind_addr: Ipv4Addr,
    /// MTU size (default: 1400)
    pub mtu: u16,
    /// Enable TCP checksum offloading
    pub checksum_offload: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_addr: Ipv4Addr::new(0, 0, 0, 0),
            mtu: 1400,
            checksum_offload: false,
        }
    }
}

impl NetworkConfig {
    /// Validate network configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mtu < 576 {
            return Err(ConfigError::ValidationError(
                "MTU must be at least 576 bytes".to_string(),
            ));
        }
        if self.mtu > 9000 {
            return Err(ConfigError::ValidationError(
                "MTU must not exceed 9000 bytes (jumbo frame)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Tunnel interface configuration
#[derive(Debug, Clone)]
pub struct TunnelInterfaceConfig {
    /// TUN interface name
    pub name: String,
    /// Virtual IP address for this endpoint
    pub address: Ipv4Addr,
    /// Netmask prefix length (e.g., 24 for /24)
    pub prefix_len: u8,
}

impl Default for TunnelInterfaceConfig {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            prefix_len: 24,
        }
    }
}

impl TunnelInterfaceConfig {
    /// Validate tunnel interface configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::ValidationError(
                "Interface name cannot be empty".to_string(),
            ));
        }
        if self.name.len() > 15 {
            return Err(ConfigError::ValidationError(
                "Interface name must not exceed 15 characters".to_string(),
            ));
        }
        if self.prefix_len > 32 {
            return Err(ConfigError::ValidationError(
                "Prefix length must be 0-32".to_string(),
            ));
        }
        Ok(())
    }
}

/// Reliability configuration (redundancy and rate control)
#[derive(Debug, Clone)]
pub struct ReliabilityConfig {
    /// Redundancy multiplier (1 = no redundancy, 2 = 2x, etc.)
    pub redundancy_multiplier: u8,
    /// Enable adaptive redundancy based on packet loss
    pub adaptive_redundancy: bool,
    /// Target packets per second
    pub packets_per_second: u64,
    /// Burst size for rate control
    pub burst_size: usize,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            redundancy_multiplier: 2,
            adaptive_redundancy: true,
            packets_per_second: 10000,
            burst_size: 16,
        }
    }
}

impl ReliabilityConfig {
    /// Validate reliability configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.redundancy_multiplier < 1 || self.redundancy_multiplier > 10 {
            return Err(ConfigError::ValidationError(
                "Redundancy multiplier must be 1-10".to_string(),
            ));
        }
        if self.packets_per_second < 100 || self.packets_per_second > 1_000_000 {
            return Err(ConfigError::ValidationError(
                "Packets per second must be 100-1000000".to_string(),
            ));
        }
        if self.burst_size < 1 || self.burst_size > 1000 {
            return Err(ConfigError::ValidationError(
                "Burst size must be 1-1000".to_string(),
            ));
        }
        Ok(())
    }
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfigParams {
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Session timeout in seconds
    pub session_timeout_secs: u64,
    /// Maximum missed heartbeats before disconnect
    pub max_missed_heartbeats: u32,
    /// Authentication timeout in seconds
    pub auth_timeout_secs: u64,
}

impl Default for SessionConfigParams {
    fn default() -> Self {
        Self {
            heartbeat_interval_secs: 30,
            session_timeout_secs: 300,
            max_missed_heartbeats: 3,
            auth_timeout_secs: 10,
        }
    }
}

impl SessionConfigParams {
    /// Validate session configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.heartbeat_interval_secs < 1 || self.heartbeat_interval_secs > 300 {
            return Err(ConfigError::ValidationError(
                "Heartbeat interval must be 1-300 seconds".to_string(),
            ));
        }
        if self.session_timeout_secs < 10 || self.session_timeout_secs > 3600 {
            return Err(ConfigError::ValidationError(
                "Session timeout must be 10-3600 seconds".to_string(),
            ));
        }
        if self.max_missed_heartbeats < 1 || self.max_missed_heartbeats > 100 {
            return Err(ConfigError::ValidationError(
                "Max missed heartbeats must be 1-100".to_string(),
            ));
        }
        if self.auth_timeout_secs < 1 || self.auth_timeout_secs > 60 {
            return Err(ConfigError::ValidationError(
                "Auth timeout must be 1-60 seconds".to_string(),
            ));
        }
        Ok(())
    }

    /// Convert to tunnel SessionConfig
    pub fn to_session_config(&self) -> crate::tunnel::SessionConfig {
        crate::tunnel::SessionConfig::default()
            .with_heartbeat_interval(Duration::from_secs(self.heartbeat_interval_secs))
            .with_session_timeout(Duration::from_secs(self.session_timeout_secs))
            .with_max_missed_heartbeats(self.max_missed_heartbeats)
            .with_auth_timeout(Duration::from_secs(self.auth_timeout_secs))
    }
}

/// Security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Pre-shared key (hex encoded, 64 chars = 32 bytes)
    pub psk: String,
    /// Enable encryption (should always be true in production)
    pub encryption_enabled: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            psk: String::new(),
            encryption_enabled: true,
        }
    }
}

impl SecurityConfig {
    /// Validate security configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.psk.is_empty() {
            return Err(ConfigError::ValidationError(
                "Pre-shared key cannot be empty".to_string(),
            ));
        }
        // PSK should be 64 hex characters (32 bytes)
        if self.psk.len() != 64 {
            return Err(ConfigError::ValidationError(
                "Pre-shared key must be 64 hex characters (32 bytes)".to_string(),
            ));
        }
        if !self.psk.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConfigError::ValidationError(
                "Pre-shared key must contain only hex characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Decode PSK from hex string to bytes
    pub fn decode_psk(&self) -> Result<[u8; 32], ConfigError> {
        if self.psk.len() != 64 {
            return Err(ConfigError::ValidationError(
                "PSK must be 64 hex characters".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        for i in 0..32 {
            let hex_byte = &self.psk[i * 2..i * 2 + 2];
            key[i] = u8::from_str_radix(hex_byte, 16).map_err(|_| {
                ConfigError::ValidationError("Invalid hex in PSK".to_string())
            })?;
        }
        Ok(key)
    }
}

/// IP Pool configuration (server only)
#[derive(Debug, Clone)]
pub struct IpPoolConfig {
    /// Start of IP range
    pub start: Ipv4Addr,
    /// End of IP range
    pub end: Ipv4Addr,
}

impl Default for IpPoolConfig {
    fn default() -> Self {
        Self {
            start: Ipv4Addr::new(10, 0, 0, 2),
            end: Ipv4Addr::new(10, 0, 0, 254),
        }
    }
}

impl IpPoolConfig {
    /// Validate IP pool configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        let start: u32 = self.start.into();
        let end: u32 = self.end.into();

        if start >= end {
            return Err(ConfigError::ValidationError(
                "IP pool start must be less than end".to_string(),
            ));
        }

        if end - start > 65534 {
            return Err(ConfigError::ValidationError(
                "IP pool range too large (max 65534 addresses)".to_string(),
            ));
        }

        Ok(())
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Listen address and port
    pub listen_addr: SocketAddr,
    /// Network configuration
    pub network: NetworkConfig,
    /// Tunnel interface configuration
    pub tunnel: TunnelInterfaceConfig,
    /// Reliability configuration
    pub reliability: ReliabilityConfig,
    /// Session configuration
    pub session: SessionConfigParams,
    /// Security configuration
    pub security: SecurityConfig,
    /// IP pool configuration
    pub ip_pool: IpPoolConfig,
    /// Maximum number of clients
    pub max_clients: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                8443,
            ),
            network: NetworkConfig::default(),
            tunnel: TunnelInterfaceConfig::default(),
            reliability: ReliabilityConfig::default(),
            session: SessionConfigParams::default(),
            security: SecurityConfig::default(),
            ip_pool: IpPoolConfig::default(),
            max_clients: 256,
        }
    }
}

impl ServerConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::FileNotFound(path.as_ref().display().to_string())
            } else {
                ConfigError::IoError(e.to_string())
            }
        })?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let mut config = ServerConfig::default();
        parse_toml_into_server_config(content, &mut config)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all configuration sections
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.network.validate()?;
        self.tunnel.validate()?;
        self.reliability.validate()?;
        self.session.validate()?;
        self.security.validate()?;
        self.ip_pool.validate()?;

        if self.max_clients < 1 || self.max_clients > 65535 {
            return Err(ConfigError::ValidationError(
                "Max clients must be 1-65535".to_string(),
            ));
        }

        Ok(())
    }
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server address to connect to
    pub server_addr: SocketAddr,
    /// Network configuration
    pub network: NetworkConfig,
    /// Tunnel interface configuration
    pub tunnel: TunnelInterfaceConfig,
    /// Reliability configuration
    pub reliability: ReliabilityConfig,
    /// Session configuration
    pub session: SessionConfigParams,
    /// Security configuration
    pub security: SecurityConfig,
    /// Auto-reconnect on disconnect
    pub auto_reconnect: bool,
    /// Reconnect delay in seconds
    pub reconnect_delay_secs: u64,
    /// Maximum reconnect attempts (0 = infinite)
    pub max_reconnect_attempts: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8443,
            ),
            network: NetworkConfig::default(),
            tunnel: TunnelInterfaceConfig {
                name: "tun0".to_string(),
                address: Ipv4Addr::new(10, 0, 0, 2),
                prefix_len: 24,
            },
            reliability: ReliabilityConfig::default(),
            session: SessionConfigParams::default(),
            security: SecurityConfig::default(),
            auto_reconnect: true,
            reconnect_delay_secs: 5,
            max_reconnect_attempts: 0,
        }
    }
}

impl ClientConfig {
    /// Load configuration from TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::FileNotFound(path.as_ref().display().to_string())
            } else {
                ConfigError::IoError(e.to_string())
            }
        })?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let mut config = ClientConfig::default();
        parse_toml_into_client_config(content, &mut config)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate all configuration sections
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.network.validate()?;
        self.tunnel.validate()?;
        self.reliability.validate()?;
        self.session.validate()?;
        self.security.validate()?;

        if self.reconnect_delay_secs < 1 || self.reconnect_delay_secs > 300 {
            return Err(ConfigError::ValidationError(
                "Reconnect delay must be 1-300 seconds".to_string(),
            ));
        }

        Ok(())
    }
}

// === Simple TOML Parser ===
// A minimal TOML parser that handles our configuration format without external dependencies

fn parse_toml_into_server_config(content: &str, config: &mut ServerConfig) -> Result<(), ConfigError> {
    let mut current_section = String::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            continue;
        }

        // Key-value pair
        if let Some((key, value)) = parse_key_value(line) {
            apply_server_value(config, &current_section, &key, &value)?;
        }
    }

    Ok(())
}

fn parse_toml_into_client_config(content: &str, config: &mut ClientConfig) -> Result<(), ConfigError> {
    let mut current_section = String::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            continue;
        }

        // Key-value pair
        if let Some((key, value)) = parse_key_value(line) {
            apply_client_value(config, &current_section, &key, &value)?;
        }
    }

    Ok(())
}

fn parse_key_value(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() != 2 {
        return None;
    }

    let key = parts[0].trim().to_string();
    let mut value = parts[1].trim().to_string();

    // Remove quotes from string values
    if value.starts_with('"') && value.ends_with('"') {
        value = value[1..value.len() - 1].to_string();
    }

    Some((key, value))
}

fn apply_server_value(
    config: &mut ServerConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match section {
        "server" => match key {
            "listen_addr" => {
                config.listen_addr = parse_socket_addr(value)?;
            }
            "max_clients" => {
                config.max_clients = parse_u32(value)?;
            }
            _ => {}
        },
        "network" => apply_network_value(&mut config.network, key, value)?,
        "tunnel" => apply_tunnel_value(&mut config.tunnel, key, value)?,
        "reliability" => apply_reliability_value(&mut config.reliability, key, value)?,
        "session" => apply_session_value(&mut config.session, key, value)?,
        "security" => apply_security_value(&mut config.security, key, value)?,
        "ip_pool" => match key {
            "start" => {
                config.ip_pool.start = parse_ipv4(value)?;
            }
            "end" => {
                config.ip_pool.end = parse_ipv4(value)?;
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

fn apply_client_value(
    config: &mut ClientConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match section {
        "client" => match key {
            "server_addr" => {
                config.server_addr = parse_socket_addr(value)?;
            }
            "auto_reconnect" => {
                config.auto_reconnect = parse_bool(value)?;
            }
            "reconnect_delay_secs" => {
                config.reconnect_delay_secs = parse_u64(value)?;
            }
            "max_reconnect_attempts" => {
                config.max_reconnect_attempts = parse_u32(value)?;
            }
            _ => {}
        },
        "network" => apply_network_value(&mut config.network, key, value)?,
        "tunnel" => apply_tunnel_value(&mut config.tunnel, key, value)?,
        "reliability" => apply_reliability_value(&mut config.reliability, key, value)?,
        "session" => apply_session_value(&mut config.session, key, value)?,
        "security" => apply_security_value(&mut config.security, key, value)?,
        _ => {}
    }
    Ok(())
}

fn apply_network_value(config: &mut NetworkConfig, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "bind_addr" => {
            config.bind_addr = parse_ipv4(value)?;
        }
        "mtu" => {
            config.mtu = parse_u16(value)?;
        }
        "checksum_offload" => {
            config.checksum_offload = parse_bool(value)?;
        }
        _ => {}
    }
    Ok(())
}

fn apply_tunnel_value(config: &mut TunnelInterfaceConfig, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "name" => {
            config.name = value.to_string();
        }
        "address" => {
            config.address = parse_ipv4(value)?;
        }
        "prefix_len" => {
            config.prefix_len = parse_u8(value)?;
        }
        _ => {}
    }
    Ok(())
}

fn apply_reliability_value(config: &mut ReliabilityConfig, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "redundancy_multiplier" => {
            config.redundancy_multiplier = parse_u8(value)?;
        }
        "adaptive_redundancy" => {
            config.adaptive_redundancy = parse_bool(value)?;
        }
        "packets_per_second" => {
            config.packets_per_second = parse_u64(value)?;
        }
        "burst_size" => {
            config.burst_size = parse_usize(value)?;
        }
        _ => {}
    }
    Ok(())
}

fn apply_session_value(config: &mut SessionConfigParams, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "heartbeat_interval_secs" => {
            config.heartbeat_interval_secs = parse_u64(value)?;
        }
        "session_timeout_secs" => {
            config.session_timeout_secs = parse_u64(value)?;
        }
        "max_missed_heartbeats" => {
            config.max_missed_heartbeats = parse_u32(value)?;
        }
        "auth_timeout_secs" => {
            config.auth_timeout_secs = parse_u64(value)?;
        }
        _ => {}
    }
    Ok(())
}

fn apply_security_value(config: &mut SecurityConfig, key: &str, value: &str) -> Result<(), ConfigError> {
    match key {
        "psk" => {
            config.psk = value.to_string();
        }
        "encryption_enabled" => {
            config.encryption_enabled = parse_bool(value)?;
        }
        _ => {}
    }
    Ok(())
}

// === Value Parsers ===

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid IPv4 address: {}", value))
    })
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid socket address: {}", value))
    })
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value.to_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(ConfigError::ParseError(format!("Invalid boolean: {}", value))),
    }
}

fn parse_u8(value: &str) -> Result<u8, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid u8: {}", value))
    })
}

fn parse_u16(value: &str) -> Result<u16, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid u16: {}", value))
    })
}

fn parse_u32(value: &str) -> Result<u32, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid u32: {}", value))
    })
}

fn parse_u64(value: &str) -> Result<u64, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid u64: {}", value))
    })
}

fn parse_usize(value: &str) -> Result<usize, ConfigError> {
    value.parse().map_err(|_| {
        ConfigError::ParseError(format!("Invalid usize: {}", value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // === 5.1.1 Tests: Configuration Structure ===

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.bind_addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(config.mtu, 1400);
        assert!(!config.checksum_offload);
    }

    #[test]
    fn test_tunnel_interface_config_default() {
        let config = TunnelInterfaceConfig::default();
        assert_eq!(config.name, "tun0");
        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.prefix_len, 24);
    }

    #[test]
    fn test_reliability_config_default() {
        let config = ReliabilityConfig::default();
        assert_eq!(config.redundancy_multiplier, 2);
        assert!(config.adaptive_redundancy);
        assert_eq!(config.packets_per_second, 10000);
        assert_eq!(config.burst_size, 16);
    }

    #[test]
    fn test_session_config_params_default() {
        let config = SessionConfigParams::default();
        assert_eq!(config.heartbeat_interval_secs, 30);
        assert_eq!(config.session_timeout_secs, 300);
        assert_eq!(config.max_missed_heartbeats, 3);
        assert_eq!(config.auth_timeout_secs, 10);
    }

    #[test]
    fn test_security_config_default() {
        let config = SecurityConfig::default();
        assert!(config.psk.is_empty());
        assert!(config.encryption_enabled);
    }

    #[test]
    fn test_ip_pool_config_default() {
        let config = IpPoolConfig::default();
        assert_eq!(config.start, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(config.end, Ipv4Addr::new(10, 0, 0, 254));
    }

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.listen_addr.port(), 8443);
        assert_eq!(config.max_clients, 256);
    }

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();
        assert_eq!(config.server_addr.port(), 8443);
        assert!(config.auto_reconnect);
        assert_eq!(config.reconnect_delay_secs, 5);
        assert_eq!(config.max_reconnect_attempts, 0);
    }

    // === 5.1.2 Tests: TOML Parsing ===

    #[test]
    fn test_parse_server_config_toml() {
        let toml = format!(r#"
[server]
listen_addr = "0.0.0.0:9000"
max_clients = 100

[network]
bind_addr = "192.168.1.1"
mtu = 1500
checksum_offload = true

[tunnel]
name = "vpn0"
address = "10.1.0.1"
prefix_len = 16

[reliability]
redundancy_multiplier = 3
adaptive_redundancy = false
packets_per_second = 20000
burst_size = 32

[session]
heartbeat_interval_secs = 15
session_timeout_secs = 120
max_missed_heartbeats = 5
auth_timeout_secs = 5

[security]
psk = "{}"
encryption_enabled = true

[ip_pool]
start = "10.1.0.2"
end = "10.1.255.254"
"#, TEST_PSK);

        let config = ServerConfig::from_toml(&toml).unwrap();

        assert_eq!(config.listen_addr.port(), 9000);
        assert_eq!(config.max_clients, 100);
        assert_eq!(config.network.bind_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.network.mtu, 1500);
        assert!(config.network.checksum_offload);
        assert_eq!(config.tunnel.name, "vpn0");
        assert_eq!(config.tunnel.address, Ipv4Addr::new(10, 1, 0, 1));
        assert_eq!(config.tunnel.prefix_len, 16);
        assert_eq!(config.reliability.redundancy_multiplier, 3);
        assert!(!config.reliability.adaptive_redundancy);
        assert_eq!(config.reliability.packets_per_second, 20000);
        assert_eq!(config.reliability.burst_size, 32);
        assert_eq!(config.session.heartbeat_interval_secs, 15);
        assert_eq!(config.session.session_timeout_secs, 120);
        assert_eq!(config.session.max_missed_heartbeats, 5);
        assert_eq!(config.session.auth_timeout_secs, 5);
        assert_eq!(config.security.psk, TEST_PSK);
        assert_eq!(config.ip_pool.start, Ipv4Addr::new(10, 1, 0, 2));
        assert_eq!(config.ip_pool.end, Ipv4Addr::new(10, 1, 255, 254));
    }

    #[test]
    fn test_parse_client_config_toml() {
        let toml = format!(r#"
[client]
server_addr = "1.2.3.4:8443"
auto_reconnect = true
reconnect_delay_secs = 10
max_reconnect_attempts = 5

[network]
mtu = 1400

[tunnel]
name = "tun1"
address = "10.0.0.100"
prefix_len = 24

[security]
psk = "{}"
"#, TEST_PSK);

        let config = ClientConfig::from_toml(&toml).unwrap();

        assert_eq!(config.server_addr.to_string(), "1.2.3.4:8443");
        assert!(config.auto_reconnect);
        assert_eq!(config.reconnect_delay_secs, 10);
        assert_eq!(config.max_reconnect_attempts, 5);
        assert_eq!(config.tunnel.name, "tun1");
        assert_eq!(config.tunnel.address, Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(config.security.psk, TEST_PSK);
    }

    #[test]
    fn test_parse_toml_with_comments() {
        let toml = format!(r#"
# This is a comment
[security]
# PSK comment
psk = "{}"
"#, TEST_PSK);

        let config = ServerConfig::from_toml(&toml).unwrap();
        assert_eq!(config.security.psk, TEST_PSK);
    }

    #[test]
    fn test_parse_toml_with_quoted_strings() {
        let toml = format!(r#"
[tunnel]
name = "my-vpn-tunnel"

[security]
psk = "{}"
"#, TEST_PSK);

        let config = ServerConfig::from_toml(&toml).unwrap();
        assert_eq!(config.tunnel.name, "my-vpn-tunnel");
    }

    // === 5.1.3 Tests: Configuration Validation ===

    #[test]
    fn test_network_config_validate_mtu_too_small() {
        let mut config = NetworkConfig::default();
        config.mtu = 100;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_network_config_validate_mtu_too_large() {
        let mut config = NetworkConfig::default();
        config.mtu = 10000;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_tunnel_config_validate_empty_name() {
        let mut config = TunnelInterfaceConfig::default();
        config.name = String::new();
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_tunnel_config_validate_name_too_long() {
        let mut config = TunnelInterfaceConfig::default();
        config.name = "a".repeat(20);
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_tunnel_config_validate_invalid_prefix() {
        let mut config = TunnelInterfaceConfig::default();
        config.prefix_len = 33;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_reliability_config_validate_invalid_multiplier() {
        let mut config = ReliabilityConfig::default();
        config.redundancy_multiplier = 0;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));

        config.redundancy_multiplier = 11;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_reliability_config_validate_invalid_pps() {
        let mut config = ReliabilityConfig::default();
        config.packets_per_second = 50;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_session_config_validate_invalid_heartbeat() {
        let mut config = SessionConfigParams::default();
        config.heartbeat_interval_secs = 0;
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_security_config_validate_empty_psk() {
        let config = SecurityConfig::default();
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_security_config_validate_short_psk() {
        let mut config = SecurityConfig::default();
        config.psk = "0123456789abcdef".to_string(); // Only 16 chars
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_security_config_validate_invalid_hex_psk() {
        let mut config = SecurityConfig::default();
        config.psk = "ghijklmnopqrstuv0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_security_config_decode_psk() {
        let mut config = SecurityConfig::default();
        config.psk = TEST_PSK.to_string();

        let key = config.decode_psk().unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[2], 0x45);
    }

    #[test]
    fn test_ip_pool_config_validate_invalid_range() {
        let mut config = IpPoolConfig::default();
        config.start = Ipv4Addr::new(10, 0, 0, 100);
        config.end = Ipv4Addr::new(10, 0, 0, 50);
        let result = config.validate();
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_server_config_validate_invalid_max_clients() {
        let toml = format!(r#"
[server]
max_clients = 0

[security]
psk = "{}"
"#, TEST_PSK);

        let result = ServerConfig::from_toml(&toml);
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_client_config_validate_invalid_reconnect_delay() {
        let toml = format!(r#"
[client]
reconnect_delay_secs = 0

[security]
psk = "{}"
"#, TEST_PSK);

        let result = ClientConfig::from_toml(&toml);
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    // === 5.1.4 Tests: Additional Parsing Tests ===

    #[test]
    fn test_parse_minimal_server_config() {
        let toml = format!(r#"
[security]
psk = "{}"
"#, TEST_PSK);

        let config = ServerConfig::from_toml(&toml).unwrap();
        // Should use defaults for everything except PSK
        assert_eq!(config.listen_addr.port(), 8443);
        assert_eq!(config.network.mtu, 1400);
        assert_eq!(config.security.psk, TEST_PSK);
    }

    #[test]
    fn test_parse_minimal_client_config() {
        let toml = format!(r#"
[security]
psk = "{}"
"#, TEST_PSK);

        let config = ClientConfig::from_toml(&toml).unwrap();
        // Should use defaults for everything except PSK
        assert_eq!(config.server_addr.port(), 8443);
        assert!(config.auto_reconnect);
        assert_eq!(config.security.psk, TEST_PSK);
    }

    #[test]
    fn test_session_config_to_tunnel_session_config() {
        let params = SessionConfigParams {
            heartbeat_interval_secs: 15,
            session_timeout_secs: 120,
            max_missed_heartbeats: 5,
            auth_timeout_secs: 8,
        };

        let _session_config = params.to_session_config();
        // SessionConfig uses Duration internally, we just verify it doesn't panic
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::FileNotFound("/path/to/config.toml".to_string());
        assert!(err.to_string().contains("/path/to/config.toml"));

        let err = ConfigError::ParseError("invalid value".to_string());
        assert!(err.to_string().contains("invalid value"));

        let err = ConfigError::ValidationError("MTU too small".to_string());
        assert!(err.to_string().contains("MTU too small"));
    }

    #[test]
    fn test_parse_bool_variants() {
        assert!(parse_bool("true").unwrap());
        assert!(parse_bool("True").unwrap());
        assert!(parse_bool("TRUE").unwrap());
        assert!(parse_bool("yes").unwrap());
        assert!(parse_bool("1").unwrap());

        assert!(!parse_bool("false").unwrap());
        assert!(!parse_bool("False").unwrap());
        assert!(!parse_bool("no").unwrap());
        assert!(!parse_bool("0").unwrap());

        assert!(parse_bool("invalid").is_err());
    }
}
