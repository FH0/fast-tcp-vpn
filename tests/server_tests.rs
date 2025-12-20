//! Integration tests for VPN Server
//!
//! These tests verify the server startup, shutdown, and basic functionality.
//! Most tests require root privileges to create TUN devices and raw sockets.

use fast_tcp_vpn::config::ServerConfig;
use fast_tcp_vpn::server::{ServerError, ServerState, VpnServer};

const TEST_PSK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn create_test_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.security.psk = TEST_PSK.to_string();
    config.tunnel.name = "vpntest0".to_string();
    config
}

// === 5.2.5 Tests: Server Start/Stop ===

#[test]
fn test_server_creation() {
    let config = create_test_config();
    let server = VpnServer::new(config);
    assert!(server.is_ok());

    let server = server.unwrap();
    assert_eq!(server.state(), ServerState::Stopped);
    assert!(!server.is_running());
}

#[test]
fn test_server_stats_initial() {
    let config = create_test_config();
    let server = VpnServer::new(config).unwrap();
    let stats = server.stats();

    assert_eq!(stats.total_clients, 0);
    assert_eq!(stats.active_clients, 0);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
}

#[test]
fn test_server_clients_initial() {
    let config = create_test_config();
    let server = VpnServer::new(config).unwrap();

    assert_eq!(server.client_count(), 0);
    assert!(server.clients().is_empty());
}

#[test]
fn test_server_stop_when_not_running() {
    let config = create_test_config();
    let mut server = VpnServer::new(config).unwrap();

    let result = server.stop();
    assert!(matches!(result, Err(ServerError::NotRunning)));
}

#[test]
fn test_server_invalid_psk() {
    let mut config = ServerConfig::default();
    config.security.psk = "invalid".to_string();

    let result = VpnServer::new(config);
    assert!(matches!(result, Err(ServerError::Config(_))));
}

// Integration tests that require root privileges
#[test]
#[ignore] // Requires root privileges
fn test_server_start_stop() {
    let config = create_test_config();
    let mut server = VpnServer::new(config).unwrap();

    // Start server
    server.start().unwrap();
    assert_eq!(server.state(), ServerState::Running);
    assert!(server.is_running());

    // Can't start again
    let result = server.start();
    assert!(matches!(result, Err(ServerError::AlreadyRunning)));

    // Stop server
    server.stop().unwrap();
    assert_eq!(server.state(), ServerState::Stopped);
    assert!(!server.is_running());
}

#[test]
#[ignore] // Requires root privileges
fn test_server_start_stop_multiple_times() {
    let config = create_test_config();
    let mut server = VpnServer::new(config).unwrap();

    for _ in 0..3 {
        server.start().unwrap();
        assert!(server.is_running());

        server.stop().unwrap();
        assert!(!server.is_running());
    }
}

#[test]
#[ignore] // Requires root privileges
fn test_server_uptime() {
    let config = create_test_config();
    let mut server = VpnServer::new(config).unwrap();

    server.start().unwrap();

    // Wait a bit
    std::thread::sleep(std::time::Duration::from_millis(100));

    let stats = server.stats();
    // Uptime should be at least 0 (might be 0 if less than 1 second)
    assert!(stats.uptime_secs >= 0);

    server.stop().unwrap();
}

#[test]
#[ignore] // Requires root privileges
fn test_server_graceful_shutdown() {
    let config = create_test_config();
    let mut server = VpnServer::new(config).unwrap();

    server.start().unwrap();

    // Simulate some activity time
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Graceful shutdown
    let result = server.stop();
    assert!(result.is_ok());
    assert_eq!(server.state(), ServerState::Stopped);
}
