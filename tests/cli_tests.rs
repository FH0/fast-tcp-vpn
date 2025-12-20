//! CLI Integration Tests
//!
//! Tests for the command-line interface functionality.

use std::process::Command;
use std::fs;

const BINARY: &str = "./target/debug/fast-tcp-vpn";
const PID_FILE_SERVER: &str = "/var/run/fast-tcp-vpn-server.pid";
const PID_FILE_CLIENT: &str = "/var/run/fast-tcp-vpn-client.pid";

/// Helper to run CLI command and capture output
fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BINARY)
        .args(args)
        .output()
        .expect("Failed to execute command");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (exit_code, stdout, stderr)
}

/// Clean up PID files before tests
fn cleanup_pid_files() {
    let _ = fs::remove_file(PID_FILE_SERVER);
    let _ = fs::remove_file(PID_FILE_CLIENT);
}

// === 5.4.1 Tests: Server Commands ===

#[test]
fn test_cli_help() {
    let (exit_code, stdout, _) = run_cli(&["--help"]);

    assert_eq!(exit_code, 0);
    assert!(stdout.contains("Fast-TCP-VPN"));
    assert!(stdout.contains("USAGE:"));
    assert!(stdout.contains("COMMANDS:"));
    assert!(stdout.contains("server start"));
    assert!(stdout.contains("server stop"));
    assert!(stdout.contains("server status"));
    assert!(stdout.contains("client connect"));
    assert!(stdout.contains("client disconnect"));
}

#[test]
fn test_cli_version() {
    let (exit_code, stdout, _) = run_cli(&["--version"]);

    assert_eq!(exit_code, 0);
    assert!(stdout.contains("fast-tcp-vpn"));
    assert!(stdout.contains("0.1.0"));
}

#[test]
fn test_cli_no_args_shows_help() {
    let (exit_code, stdout, _) = run_cli(&[]);

    assert_eq!(exit_code, 0);
    assert!(stdout.contains("Fast-TCP-VPN"));
    assert!(stdout.contains("USAGE:"));
}

#[test]
fn test_cli_server_status_stopped() {
    cleanup_pid_files();

    let (exit_code, stdout, _) = run_cli(&["server", "status"]);

    assert_eq!(exit_code, 0);
    assert!(stdout.contains("STOPPED"));
}

#[test]
fn test_cli_server_stop_not_running() {
    cleanup_pid_files();

    let (exit_code, _, stderr) = run_cli(&["server", "stop"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("not running") || stderr.contains("no PID file"));
}

#[test]
fn test_cli_client_disconnect_not_connected() {
    cleanup_pid_files();

    let (exit_code, _, stderr) = run_cli(&["client", "disconnect"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("not connected") || stderr.contains("no PID file"));
}

#[test]
fn test_cli_unknown_command() {
    let (exit_code, _, stderr) = run_cli(&["unknown"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Unknown command"));
}

#[test]
fn test_cli_unknown_server_subcommand() {
    let (exit_code, _, stderr) = run_cli(&["server", "unknown"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Unknown server subcommand"));
}

#[test]
fn test_cli_unknown_client_subcommand() {
    let (exit_code, _, stderr) = run_cli(&["client", "unknown"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Unknown client subcommand"));
}

#[test]
fn test_cli_missing_server_subcommand() {
    let (exit_code, _, stderr) = run_cli(&["server"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Missing server subcommand"));
}

#[test]
fn test_cli_missing_client_subcommand() {
    let (exit_code, _, stderr) = run_cli(&["client"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Missing client subcommand"));
}

// === 5.4.3 Tests: Log Level Control ===

#[test]
fn test_cli_log_level_valid() {
    // Test that valid log levels are accepted
    for level in &["error", "warn", "info", "debug", "trace"] {
        let (exit_code, stdout, _) = run_cli(&["--log-level", level, "--help"]);
        assert_eq!(exit_code, 0, "Log level {} should be valid", level);
        assert!(stdout.contains("Fast-TCP-VPN"));
    }
}

#[test]
fn test_cli_log_level_invalid() {
    let (exit_code, _, stderr) = run_cli(&["--log-level", "invalid", "--help"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Invalid log level"));
}

#[test]
fn test_cli_log_level_missing_value() {
    let (exit_code, _, stderr) = run_cli(&["--log-level"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Missing log level"));
}

#[test]
fn test_cli_config_missing_path() {
    let (exit_code, _, stderr) = run_cli(&["server", "start", "--config"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Missing config path"));
}

#[test]
fn test_cli_config_file_not_found() {
    let (exit_code, _, stderr) = run_cli(&["server", "start", "--config", "/nonexistent/config.toml"]);

    assert_ne!(exit_code, 0);
    assert!(stderr.contains("Failed to load config") || stderr.contains("not found"));
}

#[test]
fn test_cli_short_options() {
    // Test -h for help
    let (exit_code, stdout, _) = run_cli(&["-h"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("Fast-TCP-VPN"));

    // Test -V for version
    let (exit_code, stdout, _) = run_cli(&["-V"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("fast-tcp-vpn"));

    // Test -l for log-level
    let (exit_code, stdout, _) = run_cli(&["-l", "debug", "-h"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("Fast-TCP-VPN"));
}

#[test]
fn test_cli_help_command() {
    let (exit_code, stdout, _) = run_cli(&["help"]);

    assert_eq!(exit_code, 0);
    assert!(stdout.contains("Fast-TCP-VPN"));
}

#[test]
fn test_cli_version_command() {
    let (exit_code, stdout, _) = run_cli(&["version"]);

    assert_eq!(exit_code, 0);
    assert!(stdout.contains("fast-tcp-vpn"));
}

// === Integration tests requiring root ===

#[test]
#[ignore] // Requires root privileges
fn test_cli_server_start_stop() {
    cleanup_pid_files();

    // Start server in background
    let mut child = Command::new(BINARY)
        .args(&["server", "start"])
        .spawn()
        .expect("Failed to start server");

    // Wait a bit for server to start
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Check status
    let (exit_code, stdout, _) = run_cli(&["server", "status"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("RUNNING"));

    // Stop server
    let (exit_code, _, _) = run_cli(&["server", "stop"]);
    assert_eq!(exit_code, 0);

    // Wait for child to exit
    let _ = child.wait();

    // Check status again
    let (exit_code, stdout, _) = run_cli(&["server", "status"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("STOPPED"));
}
