//! VPN Client Implementation
//!
//! Implements the VPN client with:
//! - Connection logic to server
//! - Automatic reconnection
//! - Data forwarding between TUN and Raw Socket
//! - Graceful shutdown

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::ClientConfig;
use crate::infrastructure::crypto::{ChaCha20Poly1305, KEY_LEN};
use crate::infrastructure::packet::{IpPacket, TransportPacket};
use crate::infrastructure::socket::{LinuxRawSocket, PacketReceiver, PacketSender, SocketError};
use crate::infrastructure::tun::{LinuxTun, TunConfig, TunDevice, TunError};
use crate::tunnel::{Encapsulator, Session, SessionError, SessionId, SessionState};

/// Client error types
#[derive(Debug)]
pub enum ClientError {
    /// Configuration error
    Config(String),
    /// Socket error
    Socket(SocketError),
    /// TUN device error
    Tun(TunError),
    /// Session error
    Session(SessionError),
    /// Client is already running
    AlreadyRunning,
    /// Client is not running
    NotRunning,
    /// Connection failed
    ConnectionFailed(String),
    /// Authentication failed
    AuthenticationFailed,
    /// Thread error
    ThreadError(String),
    /// IO error
    Io(std::io::Error),
    /// Max reconnect attempts reached
    MaxReconnectAttempts,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Config(msg) => write!(f, "Config error: {}", msg),
            ClientError::Socket(e) => write!(f, "Socket error: {}", e),
            ClientError::Tun(e) => write!(f, "TUN error: {}", e),
            ClientError::Session(e) => write!(f, "Session error: {}", e),
            ClientError::AlreadyRunning => write!(f, "Client is already running"),
            ClientError::NotRunning => write!(f, "Client is not running"),
            ClientError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ClientError::AuthenticationFailed => write!(f, "Authentication failed"),
            ClientError::ThreadError(msg) => write!(f, "Thread error: {}", msg),
            ClientError::Io(e) => write!(f, "IO error: {}", e),
            ClientError::MaxReconnectAttempts => write!(f, "Max reconnect attempts reached"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<SocketError> for ClientError {
    fn from(e: SocketError) -> Self {
        ClientError::Socket(e)
    }
}

impl From<TunError> for ClientError {
    fn from(e: TunError) -> Self {
        ClientError::Tun(e)
    }
}

impl From<SessionError> for ClientError {
    fn from(e: SessionError) -> Self {
        ClientError::Session(e)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Client is disconnected
    Disconnected,
    /// Client is connecting
    Connecting,
    /// Client is connected and running
    Connected,
    /// Client is reconnecting
    Reconnecting,
    /// Client is disconnecting
    Disconnecting,
}

/// Client statistics
#[derive(Debug, Clone, Default)]
pub struct ClientStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Connection uptime in seconds
    pub uptime_secs: u64,
    /// Number of reconnection attempts
    pub reconnect_attempts: u32,
    /// Heartbeats sent
    pub heartbeats_sent: u64,
    /// Heartbeats received
    pub heartbeats_received: u64,
}

/// VPN Client
///
/// Main client structure that manages:
/// - TUN device for virtual network interface
/// - Raw socket for packet transmission
/// - Session for encryption and authentication
/// - Worker threads for data forwarding
/// - Automatic reconnection
pub struct VpnClient {
    /// Client configuration
    config: ClientConfig,
    /// Current client state
    state: Arc<RwLock<ClientState>>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// TUN device
    tun: Option<Arc<LinuxTun>>,
    /// Raw socket
    socket: Option<Arc<LinuxRawSocket>>,
    /// Session for encryption
    session: Arc<RwLock<Option<Session>>>,
    /// Pre-shared key for authentication
    psk: [u8; KEY_LEN],
    /// Connection start time
    connect_time: Option<Instant>,
    /// Worker thread handles
    worker_handles: Vec<JoinHandle<()>>,
    /// Statistics
    stats: Arc<RwLock<ClientStats>>,
    /// Reconnect attempt counter
    reconnect_count: Arc<AtomicU32>,
    /// Server IP address
    server_ip: Ipv4Addr,
}

impl VpnClient {
    /// Create a new VPN client with the given configuration
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        // Decode PSK
        let psk = config.security.decode_psk().map_err(|e| {
            ClientError::Config(format!("Failed to decode PSK: {}", e))
        })?;

        // Extract server IP
        let server_ip = match config.server_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => {
                return Err(ClientError::Config("IPv6 not supported".to_string()));
            }
        };

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(ClientState::Disconnected)),
            shutdown: Arc::new(AtomicBool::new(false)),
            tun: None,
            socket: None,
            session: Arc::new(RwLock::new(None)),
            psk,
            connect_time: None,
            worker_handles: Vec::new(),
            stats: Arc::new(RwLock::new(ClientStats::default())),
            reconnect_count: Arc::new(AtomicU32::new(0)),
            server_ip,
        })
    }

    /// Get the current client state
    pub fn state(&self) -> ClientState {
        *self.state.read().unwrap()
    }

    /// Check if client is connected
    pub fn is_connected(&self) -> bool {
        self.state() == ClientState::Connected
    }

    /// Get client statistics
    pub fn stats(&self) -> ClientStats {
        let mut stats = self.stats.read().unwrap().clone();
        if let Some(connect_time) = self.connect_time {
            stats.uptime_secs = connect_time.elapsed().as_secs();
        }
        stats
    }

    /// Get the session ID if connected
    pub fn session_id(&self) -> Option<SessionId> {
        self.session.read().unwrap().as_ref().map(|s| s.id())
    }

    /// Connect to the VPN server
    pub fn connect(&mut self) -> Result<(), ClientError> {
        // Check current state
        {
            let mut state = self.state.write().unwrap();
            if *state != ClientState::Disconnected {
                return Err(ClientError::AlreadyRunning);
            }
            *state = ClientState::Connecting;
        }

        self.shutdown.store(false, Ordering::SeqCst);
        self.reconnect_count.store(0, Ordering::SeqCst);

        // Perform connection
        match self.do_connect() {
            Ok(()) => {
                let mut state = self.state.write().unwrap();
                *state = ClientState::Connected;
                Ok(())
            }
            Err(e) => {
                let mut state = self.state.write().unwrap();
                *state = ClientState::Disconnected;
                Err(e)
            }
        }
    }

    /// Internal connection logic
    fn do_connect(&mut self) -> Result<(), ClientError> {
        // Create TUN device
        let tun_config = TunConfig::new(&self.config.tunnel.name)
            .with_address(self.config.tunnel.address)
            .with_netmask(prefix_to_netmask(self.config.tunnel.prefix_len))
            .with_mtu(self.config.network.mtu);

        let tun = LinuxTun::new(tun_config)?;
        let tun = Arc::new(tun);
        self.tun = Some(tun.clone());

        // Create raw socket
        let mut socket = LinuxRawSocket::new()?;
        if self.config.network.bind_addr != Ipv4Addr::new(0, 0, 0, 0) {
            socket.bind(self.config.network.bind_addr)?;
        }
        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());

        // Create and authenticate session
        let session_config = self.config.session.to_session_config();
        let mut session = Session::new(session_config);

        session.start_auth(&self.psk)?;
        session.complete_auth()?;

        {
            let mut session_guard = self.session.write().unwrap();
            *session_guard = Some(session);
        }

        self.connect_time = Some(Instant::now());

        // Start worker threads
        self.start_workers(tun, socket)?;

        Ok(())
    }

    /// Disconnect from the VPN server
    pub fn disconnect(&mut self) -> Result<(), ClientError> {
        // Check current state
        {
            let mut state = self.state.write().unwrap();
            match *state {
                ClientState::Connected | ClientState::Reconnecting => {
                    *state = ClientState::Disconnecting;
                }
                ClientState::Disconnected => {
                    return Ok(()); // Already disconnected
                }
                _ => {
                    return Err(ClientError::NotRunning);
                }
            }
        }

        self.do_disconnect();

        // Update state
        {
            let mut state = self.state.write().unwrap();
            *state = ClientState::Disconnected;
        }

        Ok(())
    }

    /// Internal disconnect logic
    fn do_disconnect(&mut self) {
        // Signal shutdown
        self.shutdown.store(true, Ordering::SeqCst);

        // Wait for worker threads to finish
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }

        // Close session
        {
            let mut session_guard = self.session.write().unwrap();
            if let Some(ref mut session) = *session_guard {
                if session.state() == SessionState::Established {
                    let _ = session.close();
                    let _ = session.complete_close();
                } else {
                    session.force_close();
                }
            }
            *session_guard = None;
        }

        // Clear resources
        self.tun = None;
        self.socket = None;
        self.connect_time = None;
    }

    /// Attempt to reconnect to the server
    fn try_reconnect(&mut self) -> Result<(), ClientError> {
        let max_attempts = self.config.max_reconnect_attempts;
        let current_attempts = self.reconnect_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Check if we've exceeded max attempts (0 = infinite)
        if max_attempts > 0 && current_attempts > max_attempts {
            return Err(ClientError::MaxReconnectAttempts);
        }

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.reconnect_attempts = current_attempts;
        }

        // Clean up old connection
        self.do_disconnect();

        // Wait before reconnecting
        thread::sleep(Duration::from_secs(self.config.reconnect_delay_secs));

        // Check if we should still reconnect
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(ClientError::NotRunning);
        }

        // Try to connect again
        self.do_connect()
    }

    /// Start worker threads for data forwarding
    fn start_workers(
        &mut self,
        tun: Arc<LinuxTun>,
        socket: Arc<LinuxRawSocket>,
    ) -> Result<(), ClientError> {
        // TUN -> Socket worker (outbound traffic)
        let tun_reader = tun.clone();
        let socket_sender = socket.clone();
        let shutdown = self.shutdown.clone();
        let stats = self.stats.clone();
        let server_ip = self.server_ip;
        let psk = self.psk;
        let local_vip = self.config.tunnel.address;

        let tun_to_socket_handle = thread::spawn(move || {
            Self::tun_to_socket_worker(
                tun_reader,
                socket_sender,
                shutdown,
                stats,
                server_ip,
                psk,
                local_vip,
            );
        });
        self.worker_handles.push(tun_to_socket_handle);

        // Socket -> TUN worker (inbound traffic)
        let tun_writer = tun.clone();
        let socket_receiver = socket.clone();
        let shutdown = self.shutdown.clone();
        let stats = self.stats.clone();
        let psk = self.psk;

        let socket_to_tun_handle = thread::spawn(move || {
            Self::socket_to_tun_worker(
                socket_receiver,
                tun_writer,
                shutdown,
                stats,
                psk,
            );
        });
        self.worker_handles.push(socket_to_tun_handle);

        // Heartbeat worker
        let session = self.session.clone();
        let shutdown = self.shutdown.clone();
        let stats = self.stats.clone();
        let heartbeat_interval = Duration::from_secs(self.config.session.heartbeat_interval_secs);

        let heartbeat_handle = thread::spawn(move || {
            Self::heartbeat_worker(session, shutdown, stats, heartbeat_interval);
        });
        self.worker_handles.push(heartbeat_handle);

        Ok(())
    }

    /// Worker: Read from TUN, encapsulate and encrypt entire IP packet, send via socket
    ///
    /// 支持所有 IP 协议（TCP/UDP/ICMP 等）
    fn tun_to_socket_worker(
        tun: Arc<LinuxTun>,
        socket: Arc<LinuxRawSocket>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<RwLock<ClientStats>>,
        server_ip: Ipv4Addr,
        psk: [u8; KEY_LEN],
        local_vip: Ipv4Addr,
    ) {
        let mut buffer = [0u8; 65535];

        // 创建封装器
        let encryptor = match ChaCha20Poly1305::new(&psk) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to create encryptor: {}", e);
                return;
            }
        };
        let encapsulator = Encapsulator::new(encryptor);

        while !shutdown.load(Ordering::Relaxed) {
            // Read from TUN with timeout
            let len = match tun.read_with_timeout(&mut buffer, Duration::from_millis(100)) {
                Ok(len) => len,
                Err(TunError::Timeout) => continue,
                Err(e) => {
                    eprintln!("TUN read error: {}", e);
                    continue;
                }
            };

            if len < 20 {
                continue; // Too short for IP header
            }

            // 验证是 IPv4 包
            if (buffer[0] >> 4) != 4 {
                continue; // Not IPv4
            }

            // 解析 IP 包（支持任意协议）
            let _ip_packet = match IpPacket::parse(&buffer[..len]) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // 封装 + 加密整个 IP 包
            let encrypted_payload = match encapsulator.encapsulate(&buffer[..len]) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Encapsulation error: {}", e);
                    continue;
                }
            };

            // 构造传输 TCP 包
            let transport = TransportPacket::new(
                local_vip,
                server_ip,
                8443, // VPN port
                8443,
                encrypted_payload,
            );

            let packet_bytes = transport.to_bytes();

            // Send via raw socket to server
            if let Err(e) = socket.send_raw(&packet_bytes, server_ip) {
                eprintln!("Socket send error: {}", e);
                continue;
            }

            // Update stats
            {
                let mut stats = stats.write().unwrap();
                stats.bytes_sent += packet_bytes.len() as u64;
                stats.packets_sent += 1;
            }
        }
    }

    /// Worker: Receive from socket, decapsulate and decrypt, write to TUN
    ///
    /// 支持所有 IP 协议（TCP/UDP/ICMP 等）
    fn socket_to_tun_worker(
        socket: Arc<LinuxRawSocket>,
        tun: Arc<LinuxTun>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<RwLock<ClientStats>>,
        psk: [u8; KEY_LEN],
    ) {
        let mut buffer = [0u8; 65535];

        // 创建解封装器
        let encryptor = match ChaCha20Poly1305::new(&psk) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to create encryptor: {}", e);
                return;
            }
        };
        let encapsulator = Encapsulator::new(encryptor);

        while !shutdown.load(Ordering::Relaxed) {
            // Receive from socket with timeout
            let len = match socket.receive_raw(&mut buffer, Some(Duration::from_millis(100))) {
                Ok(len) => len,
                Err(SocketError::Timeout) => continue,
                Err(e) => {
                    eprintln!("Socket receive error: {}", e);
                    continue;
                }
            };

            if len < 40 {
                continue; // Too short for IP + TCP header
            }

            // 解析传输包（外层 TCP 包）
            let transport = match TransportPacket::parse(&buffer[..len]) {
                Ok(t) => t,
                Err(_) => continue, // Not a valid transport packet
            };

            // 验证是 VPN 包（检查端口）
            if transport.dst_port() != 8443 && transport.src_port() != 8443 {
                continue; // Not a VPN packet
            }

            // 如果 payload 为空，跳过
            if transport.encrypted_payload.is_empty() {
                continue;
            }

            // 解封装 + 解密
            let original_ip_packet = match encapsulator.decapsulate(&transport.encrypted_payload) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Decapsulation error: {}", e);
                    continue;
                }
            };

            // 验证解密后的数据是有效的 IP 包
            if original_ip_packet.len() < 20 || (original_ip_packet[0] >> 4) != 4 {
                continue; // Not a valid IPv4 packet
            }

            // 将原始 IP 包写入 TUN
            if let Err(e) = tun.write(&original_ip_packet) {
                eprintln!("TUN write error: {}", e);
                continue;
            }

            // Update stats
            {
                let mut stats = stats.write().unwrap();
                stats.bytes_received += len as u64;
                stats.packets_received += 1;
            }
        }
    }

    /// Worker: Send periodic heartbeats
    fn heartbeat_worker(
        session: Arc<RwLock<Option<Session>>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<RwLock<ClientStats>>,
        interval: Duration,
    ) {
        let mut last_heartbeat = Instant::now();

        while !shutdown.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));

            if last_heartbeat.elapsed() < interval {
                continue;
            }

            // Send heartbeat
            {
                let mut session_guard = session.write().unwrap();
                if let Some(ref mut s) = *session_guard {
                    if s.state() == SessionState::Established && s.needs_heartbeat() {
                        match s.send_heartbeat() {
                            Ok(_hb) => {
                                let mut stats = stats.write().unwrap();
                                stats.heartbeats_sent += 1;
                                last_heartbeat = Instant::now();
                            }
                            Err(e) => {
                                eprintln!("Heartbeat error: {}", e);
                            }
                        }
                    }

                    // Check for session timeout
                    if s.check_heartbeat().is_err() || s.is_timed_out() {
                        eprintln!("Session timeout detected");
                    }
                }
            }
        }
    }

    /// Run the client with automatic reconnection
    ///
    /// This method blocks until the client is disconnected or shutdown.
    /// It handles automatic reconnection if enabled in the configuration.
    pub fn run(&mut self) -> Result<(), ClientError> {
        // Initial connection
        self.connect()?;

        // Main loop - monitor connection and handle reconnection
        while !self.shutdown.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            // Check session health
            let needs_reconnect = {
                let session_guard = self.session.read().unwrap();
                match session_guard.as_ref() {
                    Some(s) => s.is_timed_out() || s.has_heartbeat_timeout(),
                    None => true,
                }
            };

            if needs_reconnect && self.config.auto_reconnect {
                {
                    let mut state = self.state.write().unwrap();
                    *state = ClientState::Reconnecting;
                }

                match self.try_reconnect() {
                    Ok(()) => {
                        let mut state = self.state.write().unwrap();
                        *state = ClientState::Connected;
                        self.reconnect_count.store(0, Ordering::SeqCst);
                    }
                    Err(ClientError::MaxReconnectAttempts) => {
                        return Err(ClientError::MaxReconnectAttempts);
                    }
                    Err(e) => {
                        eprintln!("Reconnection failed: {}", e);
                        // Will retry on next iteration
                    }
                }
            } else if needs_reconnect {
                // Auto-reconnect disabled, just disconnect
                break;
            }
        }

        self.disconnect()?;
        Ok(())
    }
}

impl Drop for VpnClient {
    fn drop(&mut self) {
        if self.is_connected() {
            let _ = self.disconnect();
        }
    }
}

/// Convert prefix length to netmask
fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    if prefix >= 32 {
        return Ipv4Addr::new(255, 255, 255, 255);
    }
    let mask: u32 = !0u32 << (32 - prefix);
    Ipv4Addr::from(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // === 5.3.1 Tests: Connection Logic ===

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_client_creation() {
        let config = create_test_config();
        let client = VpnClient::new(config);
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.state(), ClientState::Disconnected);
        assert!(!client.is_connected());
    }

    #[test]
    fn test_client_stats_default() {
        let config = create_test_config();
        let client = VpnClient::new(config).unwrap();
        let stats = client.stats();

        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.reconnect_attempts, 0);
    }

    #[test]
    fn test_client_state_initial() {
        let config = create_test_config();
        let client = VpnClient::new(config).unwrap();

        assert_eq!(client.state(), ClientState::Disconnected);
        assert!(!client.is_connected());
        assert!(client.session_id().is_none());
    }

    #[test]
    fn test_disconnect_when_not_connected() {
        let config = create_test_config();
        let mut client = VpnClient::new(config).unwrap();

        // Should succeed (already disconnected)
        let result = client.disconnect();
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_config_validation() {
        let mut config = ClientConfig::default();
        config.security.psk = "invalid".to_string(); // Invalid PSK

        let result = VpnClient::new(config);
        assert!(matches!(result, Err(ClientError::Config(_))));
    }

    #[test]
    fn test_client_ipv6_not_supported() {
        let mut config = ClientConfig::default();
        config.security.psk = TEST_PSK.to_string();
        config.server_addr = "[::1]:8443".parse().unwrap();

        let result = VpnClient::new(config);
        assert!(matches!(result, Err(ClientError::Config(_))));
    }

    // === 5.3.2 Tests: Auto-reconnect ===

    #[test]
    fn test_reconnect_config() {
        let config = create_test_config();
        assert!(config.auto_reconnect);
        assert_eq!(config.reconnect_delay_secs, 1);
        assert_eq!(config.max_reconnect_attempts, 3);
    }

    #[test]
    fn test_reconnect_counter() {
        let config = create_test_config();
        let client = VpnClient::new(config).unwrap();

        assert_eq!(client.reconnect_count.load(Ordering::Relaxed), 0);
    }

    // === 5.3.3 Tests: Data Forwarding ===

    #[test]
    fn test_client_error_display() {
        let errors = vec![
            ClientError::Config("test".to_string()),
            ClientError::AlreadyRunning,
            ClientError::NotRunning,
            ClientError::ConnectionFailed("test".to_string()),
            ClientError::AuthenticationFailed,
            ClientError::MaxReconnectAttempts,
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_client_state_display() {
        let states = vec![
            ClientState::Disconnected,
            ClientState::Connecting,
            ClientState::Connected,
            ClientState::Reconnecting,
            ClientState::Disconnecting,
        ];

        for state in states {
            assert!(format!("{:?}", state).len() > 0);
        }
    }

    // Integration tests that require root privileges
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
}
