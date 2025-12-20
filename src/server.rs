//! VPN Server Implementation
//!
//! Implements the VPN server with:
//! - Listen loop for incoming connections
//! - Multi-client management
//! - Data forwarding between TUN and Raw Socket
//! - Graceful shutdown

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::ServerConfig;
use crate::infrastructure::socket::{LinuxRawSocket, PacketReceiver, PacketSender, SocketError};
use crate::infrastructure::tun::{LinuxTun, TunConfig, TunDevice, TunError};
use crate::tunnel::{
    IpPool, SessionId, Tunnel, TunnelConfig, TunnelError, VirtualIP,
};

/// Server error types
#[derive(Debug)]
pub enum ServerError {
    /// Configuration error
    Config(String),
    /// Socket error
    Socket(SocketError),
    /// TUN device error
    Tun(TunError),
    /// Tunnel error
    Tunnel(TunnelError),
    /// Server is already running
    AlreadyRunning,
    /// Server is not running
    NotRunning,
    /// Thread error
    ThreadError(String),
    /// IO error
    Io(std::io::Error),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Config(msg) => write!(f, "Config error: {}", msg),
            ServerError::Socket(e) => write!(f, "Socket error: {}", e),
            ServerError::Tun(e) => write!(f, "TUN error: {}", e),
            ServerError::Tunnel(e) => write!(f, "Tunnel error: {}", e),
            ServerError::AlreadyRunning => write!(f, "Server is already running"),
            ServerError::NotRunning => write!(f, "Server is not running"),
            ServerError::ThreadError(msg) => write!(f, "Thread error: {}", msg),
            ServerError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<SocketError> for ServerError {
    fn from(e: SocketError) -> Self {
        ServerError::Socket(e)
    }
}

impl From<TunError> for ServerError {
    fn from(e: TunError) -> Self {
        ServerError::Tun(e)
    }
}

impl From<TunnelError> for ServerError {
    fn from(e: TunnelError) -> Self {
        ServerError::Tunnel(e)
    }
}

impl From<crate::tunnel::IpPoolError> for ServerError {
    fn from(e: crate::tunnel::IpPoolError) -> Self {
        ServerError::Tunnel(TunnelError::IpPool(e))
    }
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError::Io(e)
    }
}

/// Server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Server is stopped
    Stopped,
    /// Server is starting
    Starting,
    /// Server is running
    Running,
    /// Server is stopping
    Stopping,
}

/// Server statistics
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    /// Total clients connected
    pub total_clients: u64,
    /// Currently connected clients
    pub active_clients: usize,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Server uptime in seconds
    pub uptime_secs: u64,
}

/// Client information
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Session ID
    pub session_id: SessionId,
    /// Assigned virtual IP
    pub virtual_ip: VirtualIP,
    /// Client's real IP address
    pub real_addr: Option<SocketAddr>,
    /// Connection time
    pub connected_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Bytes sent to client
    pub bytes_sent: u64,
    /// Bytes received from client
    pub bytes_received: u64,
}

impl ClientInfo {
    fn new(session_id: SessionId, virtual_ip: VirtualIP) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            virtual_ip,
            real_addr: None,
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// VPN Server
///
/// Main server structure that manages:
/// - TUN device for virtual network interface
/// - Raw socket for packet transmission
/// - Tunnel for session and IP management
/// - Worker threads for data forwarding
pub struct VpnServer {
    /// Server configuration
    config: ServerConfig,
    /// Current server state
    state: Arc<RwLock<ServerState>>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// TUN device
    tun: Option<Arc<LinuxTun>>,
    /// Raw socket
    socket: Option<Arc<LinuxRawSocket>>,
    /// Tunnel manager
    tunnel: Arc<RwLock<Option<Tunnel>>>,
    /// Client information map (session_id -> ClientInfo)
    clients: Arc<RwLock<HashMap<u64, ClientInfo>>>,
    /// Pre-shared key for authentication
    psk: [u8; 32],
    /// Server start time
    start_time: Option<Instant>,
    /// Worker thread handles
    worker_handles: Vec<JoinHandle<()>>,
    /// Statistics
    stats: Arc<RwLock<ServerStats>>,
}

impl VpnServer {
    /// Create a new VPN server with the given configuration
    pub fn new(config: ServerConfig) -> Result<Self, ServerError> {
        // Decode PSK
        let psk = config.security.decode_psk().map_err(|e| {
            ServerError::Config(format!("Failed to decode PSK: {}", e))
        })?;

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(ServerState::Stopped)),
            shutdown: Arc::new(AtomicBool::new(false)),
            tun: None,
            socket: None,
            tunnel: Arc::new(RwLock::new(None)),
            clients: Arc::new(RwLock::new(HashMap::new())),
            psk,
            start_time: None,
            worker_handles: Vec::new(),
            stats: Arc::new(RwLock::new(ServerStats::default())),
        })
    }

    /// Get the current server state
    pub fn state(&self) -> ServerState {
        *self.state.read().unwrap()
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.state() == ServerState::Running
    }

    /// Get server statistics
    pub fn stats(&self) -> ServerStats {
        let mut stats = self.stats.read().unwrap().clone();
        if let Some(start_time) = self.start_time {
            stats.uptime_secs = start_time.elapsed().as_secs();
        }
        stats
    }

    /// Get list of connected clients
    pub fn clients(&self) -> Vec<ClientInfo> {
        self.clients.read().unwrap().values().cloned().collect()
    }

    /// Get number of connected clients
    pub fn client_count(&self) -> usize {
        self.clients.read().unwrap().len()
    }

    /// Start the VPN server
    pub fn start(&mut self) -> Result<(), ServerError> {
        // Check current state
        {
            let mut state = self.state.write().unwrap();
            if *state != ServerState::Stopped {
                return Err(ServerError::AlreadyRunning);
            }
            *state = ServerState::Starting;
        }

        self.shutdown.store(false, Ordering::SeqCst);

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

        // Create tunnel with IP pool
        let ip_pool = IpPool::new(
            VirtualIP::new(self.config.ip_pool.start),
            VirtualIP::new(self.config.ip_pool.end),
        )?;

        let session_config = self.config.session.to_session_config();
        let tunnel_config = TunnelConfig::default()
            .with_interface_name(self.config.tunnel.name.clone())
            .with_server_ip(VirtualIP::new(self.config.tunnel.address))
            .with_session_config(session_config);

        let mut tunnel = Tunnel::new(tunnel_config, ip_pool)?;
        tunnel.start()?;

        {
            let mut tunnel_guard = self.tunnel.write().unwrap();
            *tunnel_guard = Some(tunnel);
        }

        self.start_time = Some(Instant::now());

        // Start worker threads
        self.start_workers(tun, socket)?;

        // Update state to running
        {
            let mut state = self.state.write().unwrap();
            *state = ServerState::Running;
        }

        Ok(())
    }

    /// Stop the VPN server gracefully
    pub fn stop(&mut self) -> Result<(), ServerError> {
        // Check current state
        {
            let mut state = self.state.write().unwrap();
            if *state != ServerState::Running {
                return Err(ServerError::NotRunning);
            }
            *state = ServerState::Stopping;
        }

        // Signal shutdown
        self.shutdown.store(true, Ordering::SeqCst);

        // Wait for worker threads to finish
        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }

        // Stop tunnel
        {
            let mut tunnel_guard = self.tunnel.write().unwrap();
            if let Some(ref mut tunnel) = *tunnel_guard {
                let _ = tunnel.stop();
            }
            *tunnel_guard = None;
        }

        // Clear clients
        {
            let mut clients = self.clients.write().unwrap();
            clients.clear();
        }

        // Clear resources
        self.tun = None;
        self.socket = None;
        self.start_time = None;

        // Update state
        {
            let mut state = self.state.write().unwrap();
            *state = ServerState::Stopped;
        }

        Ok(())
    }

    /// Start worker threads for data forwarding
    fn start_workers(
        &mut self,
        tun: Arc<LinuxTun>,
        socket: Arc<LinuxRawSocket>,
    ) -> Result<(), ServerError> {
        // TUN -> Socket worker (outbound traffic)
        let tun_reader = tun.clone();
        let socket_sender = socket.clone();
        let tunnel = self.tunnel.clone();
        let clients = self.clients.clone();
        let shutdown = self.shutdown.clone();
        let stats = self.stats.clone();
        let psk = self.psk;

        let tun_to_socket_handle = thread::spawn(move || {
            Self::tun_to_socket_worker(
                tun_reader,
                socket_sender,
                tunnel,
                clients,
                shutdown,
                stats,
                psk,
            );
        });
        self.worker_handles.push(tun_to_socket_handle);

        // Socket -> TUN worker (inbound traffic)
        let tun_writer = tun.clone();
        let socket_receiver = socket.clone();
        let tunnel = self.tunnel.clone();
        let clients = self.clients.clone();
        let shutdown = self.shutdown.clone();
        let stats = self.stats.clone();
        let psk = self.psk;
        let max_clients = self.config.max_clients;

        let socket_to_tun_handle = thread::spawn(move || {
            Self::socket_to_tun_worker(
                socket_receiver,
                tun_writer,
                tunnel,
                clients,
                shutdown,
                stats,
                psk,
                max_clients,
            );
        });
        self.worker_handles.push(socket_to_tun_handle);

        // Heartbeat/maintenance worker
        let tunnel = self.tunnel.clone();
        let clients = self.clients.clone();
        let shutdown = self.shutdown.clone();
        let stats = self.stats.clone();

        let maintenance_handle = thread::spawn(move || {
            Self::maintenance_worker(tunnel, clients, shutdown, stats);
        });
        self.worker_handles.push(maintenance_handle);

        Ok(())
    }

    /// Worker: Read from TUN, encrypt, send via socket
    fn tun_to_socket_worker(
        tun: Arc<LinuxTun>,
        socket: Arc<LinuxRawSocket>,
        tunnel: Arc<RwLock<Option<Tunnel>>>,
        clients: Arc<RwLock<HashMap<u64, ClientInfo>>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<RwLock<ServerStats>>,
        _psk: [u8; 32],
    ) {
        let mut buffer = [0u8; 65535];

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

            // Extract destination IP from IP header
            let dst_ip = Ipv4Addr::new(buffer[16], buffer[17], buffer[18], buffer[19]);

            // Find session for this destination
            let tunnel_guard = tunnel.read().unwrap();
            let tunnel_ref = match tunnel_guard.as_ref() {
                Some(t) => t,
                None => continue,
            };

            let session = match tunnel_ref.get_session_by_ip(VirtualIP::new(dst_ip)) {
                Some(s) => s,
                None => continue, // No session for this IP
            };

            let session_id = session.id();
            drop(tunnel_guard);

            // Encrypt the packet
            let mut tunnel_guard = tunnel.write().unwrap();
            let tunnel_ref = match tunnel_guard.as_mut() {
                Some(t) => t,
                None => continue,
            };

            let encrypted = match tunnel_ref.encrypt(session_id, &buffer[..len]) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Encryption error: {}", e);
                    continue;
                }
            };
            drop(tunnel_guard);

            // Send via raw socket
            if let Err(e) = socket.send_raw(&encrypted, dst_ip) {
                eprintln!("Socket send error: {}", e);
                continue;
            }

            // Update stats
            {
                let mut stats = stats.write().unwrap();
                stats.bytes_sent += encrypted.len() as u64;
                stats.packets_sent += 1;
            }

            // Update client stats
            {
                let mut clients = clients.write().unwrap();
                if let Some(client) = clients.get_mut(&session_id.raw()) {
                    client.bytes_sent += encrypted.len() as u64;
                    client.last_activity = Instant::now();
                }
            }
        }
    }

    /// Worker: Receive from socket, decrypt, write to TUN
    fn socket_to_tun_worker(
        socket: Arc<LinuxRawSocket>,
        tun: Arc<LinuxTun>,
        tunnel: Arc<RwLock<Option<Tunnel>>>,
        clients: Arc<RwLock<HashMap<u64, ClientInfo>>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<RwLock<ServerStats>>,
        psk: [u8; 32],
        max_clients: u32,
    ) {
        let mut buffer = [0u8; 65535];

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

            if len < 20 {
                continue; // Too short for IP header
            }

            // Extract source IP from IP header
            let src_ip = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);

            // Check if this is from a known client
            let tunnel_guard = tunnel.read().unwrap();
            let tunnel_ref = match tunnel_guard.as_ref() {
                Some(t) => t,
                None => continue,
            };

            let session_opt = tunnel_ref.get_session_by_ip(VirtualIP::new(src_ip));
            let session_id = session_opt.map(|s| s.id());
            drop(tunnel_guard);

            let session_id = match session_id {
                Some(id) => id,
                None => {
                    // New client - try to create session
                    let mut tunnel_guard = tunnel.write().unwrap();
                    let tunnel_ref = match tunnel_guard.as_mut() {
                        Some(t) => t,
                        None => continue,
                    };

                    // Check max clients
                    if tunnel_ref.active_session_count() >= max_clients as usize {
                        continue;
                    }

                    match tunnel_ref.create_session() {
                        Ok((id, ip)) => {
                            // Authenticate session
                            if tunnel_ref.authenticate_session(id, &psk).is_err() {
                                let _ = tunnel_ref.close_session(id);
                                continue;
                            }

                            // Add to clients map
                            let client_info = ClientInfo::new(id, ip);
                            {
                                let mut clients = clients.write().unwrap();
                                clients.insert(id.raw(), client_info);
                            }

                            // Update stats
                            {
                                let mut stats = stats.write().unwrap();
                                stats.total_clients += 1;
                                stats.active_clients = tunnel_ref.active_session_count();
                            }

                            id
                        }
                        Err(e) => {
                            eprintln!("Failed to create session: {}", e);
                            continue;
                        }
                    }
                }
            };

            // Decrypt the packet
            let mut tunnel_guard = tunnel.write().unwrap();
            let tunnel_ref = match tunnel_guard.as_mut() {
                Some(t) => t,
                None => continue,
            };

            let decrypted = match tunnel_ref.decrypt(session_id, &buffer[..len]) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Decryption error: {}", e);
                    continue;
                }
            };
            drop(tunnel_guard);

            // Write to TUN
            if let Err(e) = tun.write(&decrypted) {
                eprintln!("TUN write error: {}", e);
                continue;
            }

            // Update stats
            {
                let mut stats = stats.write().unwrap();
                stats.bytes_received += len as u64;
                stats.packets_received += 1;
            }

            // Update client stats
            {
                let mut clients = clients.write().unwrap();
                if let Some(client) = clients.get_mut(&session_id.raw()) {
                    client.bytes_received += len as u64;
                    client.last_activity = Instant::now();
                }
            }
        }
    }

    /// Worker: Maintenance tasks (heartbeat, session cleanup)
    fn maintenance_worker(
        tunnel: Arc<RwLock<Option<Tunnel>>>,
        clients: Arc<RwLock<HashMap<u64, ClientInfo>>>,
        shutdown: Arc<AtomicBool>,
        stats: Arc<RwLock<ServerStats>>,
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            // Check for expired sessions
            let expired: Vec<SessionId>;
            {
                let mut tunnel_guard = tunnel.write().unwrap();
                if let Some(ref mut tunnel_ref) = *tunnel_guard {
                    expired = tunnel_ref.check_sessions();
                } else {
                    continue;
                }
            }

            // Remove expired clients
            if !expired.is_empty() {
                let mut clients = clients.write().unwrap();
                for session_id in &expired {
                    clients.remove(&session_id.raw());
                }

                // Update stats
                let mut stats = stats.write().unwrap();
                let tunnel_guard = tunnel.read().unwrap();
                if let Some(ref tunnel_ref) = *tunnel_guard {
                    stats.active_clients = tunnel_ref.active_session_count();
                }
            }
        }
    }

    /// Disconnect a specific client
    pub fn disconnect_client(&self, session_id: SessionId) -> Result<(), ServerError> {
        let mut tunnel_guard = self.tunnel.write().unwrap();
        let tunnel_ref = tunnel_guard.as_mut().ok_or(ServerError::NotRunning)?;

        tunnel_ref.close_session(session_id)?;

        // Remove from clients map
        {
            let mut clients = self.clients.write().unwrap();
            clients.remove(&session_id.raw());
        }

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.active_clients = tunnel_ref.active_session_count();
        }

        Ok(())
    }
}

impl Drop for VpnServer {
    fn drop(&mut self) {
        if self.is_running() {
            let _ = self.stop();
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

    fn create_test_config() -> ServerConfig {
        let mut config = ServerConfig::default();
        config.security.psk = TEST_PSK.to_string();
        config.tunnel.name = "vpntest0".to_string();
        config
    }

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

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
    fn test_server_stats_default() {
        let config = create_test_config();
        let server = VpnServer::new(config).unwrap();
        let stats = server.stats();

        assert_eq!(stats.total_clients, 0);
        assert_eq!(stats.active_clients, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_client_info_creation() {
        let session_id = SessionId::new(12345);
        let virtual_ip = VirtualIP::from_octets(10, 0, 0, 100);
        let client = ClientInfo::new(session_id, virtual_ip);

        assert_eq!(client.session_id, session_id);
        assert_eq!(client.virtual_ip, virtual_ip);
        assert_eq!(client.bytes_sent, 0);
        assert_eq!(client.bytes_received, 0);
    }

    #[test]
    fn test_server_state_transitions() {
        let config = create_test_config();
        let server = VpnServer::new(config).unwrap();

        assert_eq!(server.state(), ServerState::Stopped);
        assert!(!server.is_running());
    }

    #[test]
    fn test_stop_not_running() {
        let config = create_test_config();
        let mut server = VpnServer::new(config).unwrap();

        let result = server.stop();
        assert!(matches!(result, Err(ServerError::NotRunning)));
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
    fn test_server_client_management() {
        let config = create_test_config();
        let mut server = VpnServer::new(config).unwrap();

        server.start().unwrap();

        // Initially no clients
        assert_eq!(server.client_count(), 0);
        assert!(server.clients().is_empty());

        server.stop().unwrap();
    }
}
