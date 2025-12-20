//! Integration tests for VPN Client
//!
//! Tests for 5.3.4: Client connection integration tests

use fast_tcp_vpn::client::{ClientError, ClientState, ClientStats, VpnClient};
use fast_tcp_vpn::config::ClientConfig;
use std::time::Duration;

const TEST_PSK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn create_test_config() -> ClientConfig {
    let mut config = ClientConfig::default();
    config.security.psk = TEST_PSK.to_string();
    config.tunnel.name = "vpnclient0".to_string();
    config.auto_reconnect = true;
    config.reconnect_delay_secs = 1;
    config.max_reconnect_attempts = 3;
    config
}

// === 5.3.4 Integration Tests: Client Connection ===

#[test]
fn test_client_creation_success() {
    let config = create_test_config();
    let client = VpnClient::new(config);
    assert!(client.is_ok());

    let client = client.unwrap();
    assert_eq!(client.state(), ClientState::Disconnected);
    assert!(!client.is_connected());
}

#[test]
fn test_client_creation_invalid_psk() {
    let mut config = ClientConfig::default();
    config.security.psk = "invalid_psk".to_string();

    let result = VpnClient::new(config);
    assert!(matches!(result, Err(ClientError::Config(_))));
}

#[test]
fn test_client_creation_short_psk() {
    let mut config = ClientConfig::default();
    config.security.psk = "0123456789abcdef".to_string(); // Too short

    let result = VpnClient::new(config);
    assert!(matches!(result, Err(ClientError::Config(_))));
}

#[test]
fn test_client_creation_ipv6_not_supported() {
    let mut config = ClientConfig::default();
    config.security.psk = TEST_PSK.to_string();
    config.server_addr = "[::1]:8443".parse().unwrap();

    let result = VpnClient::new(config);
    assert!(matches!(result, Err(ClientError::Config(_))));
}

#[test]
fn test_client_initial_state() {
    let config = create_test_config();
    let client = VpnClient::new(config).unwrap();

    assert_eq!(client.state(), ClientState::Disconnected);
    assert!(!client.is_connected());
    assert!(client.session_id().is_none());
}

#[test]
fn test_client_stats_initial() {
    let config = create_test_config();
    let client = VpnClient::new(config).unwrap();
    let stats = client.stats();

    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.uptime_secs, 0);
    assert_eq!(stats.reconnect_attempts, 0);
    assert_eq!(stats.heartbeats_sent, 0);
    assert_eq!(stats.heartbeats_received, 0);
}

#[test]
fn test_client_disconnect_when_not_connected() {
    let config = create_test_config();
    let mut client = VpnClient::new(config).unwrap();

    // Should succeed (already disconnected)
    let result = client.disconnect();
    assert!(result.is_ok());
    assert_eq!(client.state(), ClientState::Disconnected);
}

#[test]
fn test_client_config_auto_reconnect() {
    let config = create_test_config();
    assert!(config.auto_reconnect);
    assert_eq!(config.reconnect_delay_secs, 1);
    assert_eq!(config.max_reconnect_attempts, 3);
}

#[test]
fn test_client_config_default_values() {
    let config = ClientConfig::default();
    assert_eq!(config.server_addr.port(), 8443);
    assert!(config.auto_reconnect);
    assert_eq!(config.reconnect_delay_secs, 5);
    assert_eq!(config.max_reconnect_attempts, 0); // 0 = infinite
}

#[test]
fn test_client_error_display() {
    let errors = vec![
        ClientError::Config("test config error".to_string()),
        ClientError::AlreadyRunning,
        ClientError::NotRunning,
        ClientError::ConnectionFailed("connection test".to_string()),
        ClientError::AuthenticationFailed,
        ClientError::MaxReconnectAttempts,
        ClientError::ThreadError("thread error".to_string()),
    ];

    for error in errors {
        let display = format!("{}", error);
        assert!(!display.is_empty());
    }
}

#[test]
fn test_client_state_values() {
    // Test all state variants exist and are distinct
    let states = [ClientState::Disconnected,
        ClientState::Connecting,
        ClientState::Connected,
        ClientState::Reconnecting,
        ClientState::Disconnecting];

    for (i, state1) in states.iter().enumerate() {
        for (j, state2) in states.iter().enumerate() {
            if i == j {
                assert_eq!(state1, state2);
            } else {
                assert_ne!(state1, state2);
            }
        }
    }
}

#[test]
fn test_client_stats_clone() {
    let stats = ClientStats {
        bytes_sent: 100,
        bytes_received: 200,
        packets_sent: 10,
        packets_received: 20,
        uptime_secs: 60,
        reconnect_attempts: 2,
        heartbeats_sent: 5,
        heartbeats_received: 4,
    };

    let cloned = stats.clone();
    assert_eq!(cloned.bytes_sent, 100);
    assert_eq!(cloned.bytes_received, 200);
    assert_eq!(cloned.packets_sent, 10);
    assert_eq!(cloned.packets_received, 20);
    assert_eq!(cloned.uptime_secs, 60);
    assert_eq!(cloned.reconnect_attempts, 2);
    assert_eq!(cloned.heartbeats_sent, 5);
    assert_eq!(cloned.heartbeats_received, 4);
}

// === Integration tests requiring root privileges ===

#[test]
#[ignore] // Requires root privileges
fn test_client_connect_disconnect() {
    let config = create_test_config();
    let mut client = VpnClient::new(config).unwrap();

    // Connect
    client.connect().unwrap();
    assert_eq!(client.state(), ClientState::Connected);
    assert!(client.is_connected());
    assert!(client.session_id().is_some());

    // Can't connect again
    let result = client.connect();
    assert!(matches!(result, Err(ClientError::AlreadyRunning)));

    // Disconnect
    client.disconnect().unwrap();
    assert_eq!(client.state(), ClientState::Disconnected);
    assert!(!client.is_connected());
}

#[test]
#[ignore] // Requires root privileges
fn test_client_stats_after_connection() {
    let config = create_test_config();
    let mut client = VpnClient::new(config).unwrap();

    client.connect().unwrap();

    // Wait a bit for uptime
    std::thread::sleep(Duration::from_secs(1));

    let stats = client.stats();
    assert!(stats.uptime_secs >= 1);

    client.disconnect().unwrap();
}

#[test]
#[ignore] // Requires root privileges
fn test_client_session_id_after_connect() {
    let config = create_test_config();
    let mut client = VpnClient::new(config).unwrap();

    assert!(client.session_id().is_none());

    client.connect().unwrap();
    assert!(client.session_id().is_some());

    client.disconnect().unwrap();
}

#[test]
#[ignore] // Requires root privileges
fn test_client_multiple_connect_disconnect_cycles() {
    let config = create_test_config();
    let mut client = VpnClient::new(config).unwrap();

    for _ in 0..3 {
        client.connect().unwrap();
        assert!(client.is_connected());

        client.disconnect().unwrap();
        assert!(!client.is_connected());
    }
}

#[test]
#[ignore] // Requires root privileges
fn test_client_drop_disconnects() {
    let config = create_test_config();
    let mut client = VpnClient::new(config).unwrap();

    client.connect().unwrap();
    assert!(client.is_connected());

    // Drop should trigger disconnect
    drop(client);

    // If we get here without panic, the drop worked
}
