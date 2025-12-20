//! Fast-TCP-VPN CLI
//!
//! Command-line interface for the VPN server and client.
//!
//! ## Usage
//!
//! ### Server Commands
//! - `fast-tcp-vpn server start [--config <path>]` - Start the VPN server
//! - `fast-tcp-vpn server stop` - Stop the VPN server (sends signal)
//! - `fast-tcp-vpn server status` - Show server status
//!
//! ### Client Commands
//! - `fast-tcp-vpn client connect [--config <path>]` - Connect to VPN server
//! - `fast-tcp-vpn client disconnect` - Disconnect from VPN server
//!
//! ### Options
//! - `--log-level <level>` - Set log level (error, warn, info, debug, trace)
//! - `--help` - Show help message
//! - `--version` - Show version

mod infrastructure;

use std::env;
use std::fs;
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use fast_tcp_vpn::client::VpnClient;
use fast_tcp_vpn::config::{ClientConfig, ServerConfig};
use fast_tcp_vpn::server::VpnServer;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PID_FILE_SERVER: &str = "/var/run/fast-tcp-vpn-server.pid";
const PID_FILE_CLIENT: &str = "/var/run/fast-tcp-vpn-client.pid";

/// Log level for the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "error" => Some(LogLevel::Error),
            "warn" | "warning" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "trace" => Some(LogLevel::Trace),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Trace => "TRACE",
        }
    }
}

/// Global log level
static mut LOG_LEVEL: LogLevel = LogLevel::Info;

/// Set the global log level
fn set_log_level(level: LogLevel) {
    unsafe {
        LOG_LEVEL = level;
    }
}

/// Get the current log level
fn get_log_level() -> LogLevel {
    unsafe { LOG_LEVEL }
}

/// Log a message at the specified level
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        if $level as u8 <= get_log_level() as u8 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            eprintln!("[{}] [{}] {}",
                now.as_secs(),
                $level.as_str(),
                format!($($arg)*));
        }
    };
}

/// CLI command structure
#[derive(Debug)]
enum Command {
    ServerStart { config_path: Option<String> },
    ServerStop,
    ServerStatus,
    ClientConnect { config_path: Option<String> },
    ClientDisconnect,
    Help,
    Version,
}

/// Parse command line arguments
fn parse_args() -> Result<(Command, LogLevel), String> {
    let args: Vec<String> = env::args().collect();
    let mut log_level = LogLevel::Info;
    let mut i = 1;

    // Parse global options first
    while i < args.len() {
        match args[i].as_str() {
            "--log-level" | "-l" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing log level value".to_string());
                }
                log_level = LogLevel::from_str(&args[i])
                    .ok_or_else(|| format!("Invalid log level: {}", args[i]))?;
                i += 1;
            }
            "--help" | "-h" => return Ok((Command::Help, log_level)),
            "--version" | "-V" => return Ok((Command::Version, log_level)),
            _ => break,
        }
    }

    if i >= args.len() {
        return Ok((Command::Help, log_level));
    }

    let mode = &args[i];
    i += 1;

    match mode.as_str() {
        "server" => {
            if i >= args.len() {
                return Err("Missing server subcommand (start/stop/status)".to_string());
            }
            let subcommand = &args[i];
            i += 1;

            match subcommand.as_str() {
                "start" => {
                    let mut config_path = None;
                    while i < args.len() {
                        match args[i].as_str() {
                            "--config" | "-c" => {
                                i += 1;
                                if i >= args.len() {
                                    return Err("Missing config path".to_string());
                                }
                                config_path = Some(args[i].clone());
                                i += 1;
                            }
                            _ => {
                                return Err(format!("Unknown option: {}", args[i]));
                            }
                        }
                    }
                    Ok((Command::ServerStart { config_path }, log_level))
                }
                "stop" => Ok((Command::ServerStop, log_level)),
                "status" => Ok((Command::ServerStatus, log_level)),
                _ => Err(format!("Unknown server subcommand: {}", subcommand)),
            }
        }
        "client" => {
            if i >= args.len() {
                return Err("Missing client subcommand (connect/disconnect)".to_string());
            }
            let subcommand = &args[i];
            i += 1;

            match subcommand.as_str() {
                "connect" => {
                    let mut config_path = None;
                    while i < args.len() {
                        match args[i].as_str() {
                            "--config" | "-c" => {
                                i += 1;
                                if i >= args.len() {
                                    return Err("Missing config path".to_string());
                                }
                                config_path = Some(args[i].clone());
                                i += 1;
                            }
                            _ => {
                                return Err(format!("Unknown option: {}", args[i]));
                            }
                        }
                    }
                    Ok((Command::ClientConnect { config_path }, log_level))
                }
                "disconnect" => Ok((Command::ClientDisconnect, log_level)),
                _ => Err(format!("Unknown client subcommand: {}", subcommand)),
            }
        }
        "help" => Ok((Command::Help, log_level)),
        "version" => Ok((Command::Version, log_level)),
        _ => Err(format!("Unknown command: {}", mode)),
    }
}

/// Print help message
fn print_help() {
    println!(
        r#"Fast-TCP-VPN v{}

A high-performance VPN using raw TCP with multi-packet redundancy.

USAGE:
    fast-tcp-vpn [OPTIONS] <COMMAND>

COMMANDS:
    server start [--config <path>]    Start the VPN server
    server stop                       Stop the VPN server
    server status                     Show server status

    client connect [--config <path>]  Connect to VPN server
    client disconnect                 Disconnect from VPN server

OPTIONS:
    -l, --log-level <level>  Set log level (error, warn, info, debug, trace)
                             Default: info
    -h, --help               Show this help message
    -V, --version            Show version

EXAMPLES:
    # Start server with default config
    fast-tcp-vpn server start

    # Start server with custom config
    fast-tcp-vpn server start --config /etc/fast-tcp-vpn/server.toml

    # Connect client with debug logging
    fast-tcp-vpn --log-level debug client connect

    # Check server status
    fast-tcp-vpn server status
"#,
        VERSION
    );
}

/// Print version
fn print_version() {
    println!("fast-tcp-vpn {}", VERSION);
}

/// Write PID file
fn write_pid_file(path: &str) -> Result<(), String> {
    let pid = process::id();
    fs::write(path, pid.to_string())
        .map_err(|e| format!("Failed to write PID file {}: {}", path, e))
}

/// Read PID from file
fn read_pid_file(path: &str) -> Option<u32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Remove PID file
fn remove_pid_file(path: &str) {
    let _ = fs::remove_file(path);
}

/// Check if a process is running
fn is_process_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Send signal to process
fn send_signal(pid: u32, signal: i32) -> Result<(), String> {
    let result = unsafe { libc::kill(pid as i32, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!("Failed to send signal {} to PID {}", signal, pid))
    }
}

/// Server start command
fn cmd_server_start(config_path: Option<String>) -> Result<(), String> {
    // Check if already running
    if let Some(pid) = read_pid_file(PID_FILE_SERVER) {
        if is_process_running(pid) {
            return Err(format!("Server is already running (PID: {})", pid));
        }
        // Stale PID file, remove it
        remove_pid_file(PID_FILE_SERVER);
    }

    // Load configuration
    let config = match config_path {
        Some(path) => {
            log!(LogLevel::Info, "Loading config from: {}", path);
            ServerConfig::from_file(&path)
                .map_err(|e| format!("Failed to load config: {}", e))?
        }
        None => {
            log!(LogLevel::Info, "Using default configuration");
            // Create a default config with a generated PSK for demo
            let mut config = ServerConfig::default();
            // Use a fixed test PSK for now (in production, this should be configured)
            config.security.psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
            config
        }
    };

    // Write PID file
    write_pid_file(PID_FILE_SERVER)?;

    // Setup signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Note: In a real implementation, we'd use signal-hook crate
    // For now, we'll just run until interrupted
    ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    log!(LogLevel::Info, "Starting VPN server...");
    log!(LogLevel::Info, "Listen address: {}", config.listen_addr);
    log!(LogLevel::Info, "TUN interface: {}", config.tunnel.name);
    log!(LogLevel::Info, "Max clients: {}", config.max_clients);

    // Create and start server
    let mut server = VpnServer::new(config)
        .map_err(|e| format!("Failed to create server: {}", e))?;

    server.start()
        .map_err(|e| format!("Failed to start server: {}", e))?;

    log!(LogLevel::Info, "Server started successfully");

    // Main loop - wait for shutdown signal
    while running.load(Ordering::SeqCst) && server.is_running() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    log!(LogLevel::Info, "Shutting down server...");
    server.stop().map_err(|e| format!("Failed to stop server: {}", e))?;

    remove_pid_file(PID_FILE_SERVER);
    log!(LogLevel::Info, "Server stopped");

    Ok(())
}

/// Server stop command
fn cmd_server_stop() -> Result<(), String> {
    let pid = read_pid_file(PID_FILE_SERVER)
        .ok_or_else(|| "Server is not running (no PID file found)".to_string())?;

    if !is_process_running(pid) {
        remove_pid_file(PID_FILE_SERVER);
        return Err("Server is not running (stale PID file removed)".to_string());
    }

    log!(LogLevel::Info, "Sending SIGTERM to server (PID: {})", pid);
    send_signal(pid, libc::SIGTERM)?;

    // Wait for process to exit (with timeout)
    for _ in 0..50 {
        if !is_process_running(pid) {
            remove_pid_file(PID_FILE_SERVER);
            log!(LogLevel::Info, "Server stopped successfully");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Force kill if still running
    log!(LogLevel::Warn, "Server did not stop gracefully, sending SIGKILL");
    send_signal(pid, libc::SIGKILL)?;
    remove_pid_file(PID_FILE_SERVER);

    Ok(())
}

/// Server status command
fn cmd_server_status() -> Result<(), String> {
    match read_pid_file(PID_FILE_SERVER) {
        Some(pid) => {
            if is_process_running(pid) {
                println!("Server Status: RUNNING");
                println!("  PID: {}", pid);

                // Try to read /proc/pid/stat for more info
                if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) {
                    let parts: Vec<&str> = stat.split_whitespace().collect();
                    if parts.len() > 13 {
                        // utime + stime in jiffies (usually 100 per second)
                        let utime: u64 = parts[13].parse().unwrap_or(0);
                        let stime: u64 = parts[14].parse().unwrap_or(0);
                        let total_time = (utime + stime) / 100;
                        println!("  CPU Time: {}s", total_time);
                    }
                }

                // Try to read memory info
                if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid)) {
                    for line in status.lines() {
                        if line.starts_with("VmRSS:") {
                            println!("  Memory: {}", line.trim_start_matches("VmRSS:").trim());
                        }
                    }
                }

                Ok(())
            } else {
                remove_pid_file(PID_FILE_SERVER);
                println!("Server Status: STOPPED (stale PID file removed)");
                Ok(())
            }
        }
        None => {
            println!("Server Status: STOPPED");
            Ok(())
        }
    }
}

/// Client connect command
fn cmd_client_connect(config_path: Option<String>) -> Result<(), String> {
    // Check if already running
    if let Some(pid) = read_pid_file(PID_FILE_CLIENT) {
        if is_process_running(pid) {
            return Err(format!("Client is already connected (PID: {})", pid));
        }
        remove_pid_file(PID_FILE_CLIENT);
    }

    // Load configuration
    let config = match config_path {
        Some(path) => {
            log!(LogLevel::Info, "Loading config from: {}", path);
            ClientConfig::from_file(&path)
                .map_err(|e| format!("Failed to load config: {}", e))?
        }
        None => {
            log!(LogLevel::Info, "Using default configuration");
            let mut config = ClientConfig::default();
            config.security.psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
            config
        }
    };

    // Write PID file
    write_pid_file(PID_FILE_CLIENT)?;

    // Setup signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    log!(LogLevel::Info, "Connecting to VPN server...");
    log!(LogLevel::Info, "Server address: {}", config.server_addr);
    log!(LogLevel::Info, "TUN interface: {}", config.tunnel.name);
    log!(LogLevel::Info, "Auto-reconnect: {}", config.auto_reconnect);

    // Create client
    let mut client = VpnClient::new(config)
        .map_err(|e| format!("Failed to create client: {}", e))?;

    // Connect
    client.connect()
        .map_err(|e| format!("Failed to connect: {}", e))?;

    log!(LogLevel::Info, "Connected successfully");

    // Main loop - wait for shutdown signal
    while running.load(Ordering::SeqCst) && client.is_connected() {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    log!(LogLevel::Info, "Disconnecting...");
    client.disconnect().map_err(|e| format!("Failed to disconnect: {}", e))?;

    remove_pid_file(PID_FILE_CLIENT);
    log!(LogLevel::Info, "Disconnected");

    Ok(())
}

/// Client disconnect command
fn cmd_client_disconnect() -> Result<(), String> {
    let pid = read_pid_file(PID_FILE_CLIENT)
        .ok_or_else(|| "Client is not connected (no PID file found)".to_string())?;

    if !is_process_running(pid) {
        remove_pid_file(PID_FILE_CLIENT);
        return Err("Client is not connected (stale PID file removed)".to_string());
    }

    log!(LogLevel::Info, "Sending SIGTERM to client (PID: {})", pid);
    send_signal(pid, libc::SIGTERM)?;

    // Wait for process to exit
    for _ in 0..50 {
        if !is_process_running(pid) {
            remove_pid_file(PID_FILE_CLIENT);
            log!(LogLevel::Info, "Client disconnected successfully");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    log!(LogLevel::Warn, "Client did not stop gracefully, sending SIGKILL");
    send_signal(pid, libc::SIGKILL)?;
    remove_pid_file(PID_FILE_CLIENT);

    Ok(())
}

/// Simple Ctrl+C handler using libc
fn ctrlc_handler<F: Fn() + Send + 'static>(handler: F) {
    // Store handler in a static
    static mut HANDLER: Option<Box<dyn Fn() + Send>> = None;

    unsafe {
        HANDLER = Some(Box::new(handler));

        // Set up signal handler
        libc::signal(libc::SIGINT, signal_handler as usize);
        libc::signal(libc::SIGTERM, signal_handler as usize);
    }

    extern "C" fn signal_handler(_: libc::c_int) {
        unsafe {
            if let Some(ref handler) = HANDLER {
                handler();
            }
        }
    }
}

fn main() {
    let (command, log_level) = match parse_args() {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Run 'fast-tcp-vpn --help' for usage information.");
            process::exit(1);
        }
    };

    set_log_level(log_level);

    let result = match command {
        Command::ServerStart { config_path } => cmd_server_start(config_path),
        Command::ServerStop => cmd_server_stop(),
        Command::ServerStatus => cmd_server_status(),
        Command::ClientConnect { config_path } => cmd_client_connect(config_path),
        Command::ClientDisconnect => cmd_client_disconnect(),
        Command::Help => {
            print_help();
            Ok(())
        }
        Command::Version => {
            print_version();
            Ok(())
        }
    };

    if let Err(e) = result {
        log!(LogLevel::Error, "{}", e);
        process::exit(1);
    }
}
