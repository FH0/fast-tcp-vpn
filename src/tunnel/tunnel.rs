//! Tunnel Aggregate Root
//!
//! The Tunnel is the aggregate root that integrates:
//! - Session management (authentication, encryption, heartbeat)
//! - Virtual IP management (IP pool allocation)
//! - Routing management (route table)
//!
//! It provides a unified interface for VPN tunnel operations.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::routing::{Route, RoutingError, RoutingTable};
use super::session::{Session, SessionConfig, SessionError, SessionId, SessionState};
use super::virtual_ip::{IpAssignmentManager, IpPool, IpPoolError, VirtualIP};

/// Tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Session configuration
    pub session_config: SessionConfig,
    /// Tunnel interface name
    pub interface_name: String,
    /// Server virtual IP (gateway)
    pub server_ip: VirtualIP,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            session_config: SessionConfig::default(),
            interface_name: "tun0".to_string(),
            server_ip: VirtualIP::from_octets(10, 0, 0, 1),
        }
    }
}

impl TunnelConfig {
    /// Create a new tunnel config with custom interface name
    pub fn with_interface_name(mut self, name: String) -> Self {
        self.interface_name = name;
        self
    }

    /// Create a new tunnel config with custom server IP
    pub fn with_server_ip(mut self, ip: VirtualIP) -> Self {
        self.server_ip = ip;
        self
    }

    /// Create a new tunnel config with custom session config
    pub fn with_session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }
}

/// Tunnel error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelError {
    /// Session-related error
    Session(SessionError),
    /// IP pool error
    IpPool(IpPoolError),
    /// Routing error
    Routing(RoutingError),
    /// Session not found
    SessionNotFound(SessionId),
    /// Tunnel is not running
    NotRunning,
    /// Tunnel is already running
    AlreadyRunning,
    /// Invalid configuration
    InvalidConfig(String),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::Session(e) => write!(f, "Session error: {}", e),
            TunnelError::IpPool(e) => write!(f, "IP pool error: {}", e),
            TunnelError::Routing(e) => write!(f, "Routing error: {}", e),
            TunnelError::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            TunnelError::NotRunning => write!(f, "Tunnel is not running"),
            TunnelError::AlreadyRunning => write!(f, "Tunnel is already running"),
            TunnelError::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
        }
    }
}

impl std::error::Error for TunnelError {}

impl From<SessionError> for TunnelError {
    fn from(e: SessionError) -> Self {
        TunnelError::Session(e)
    }
}

impl From<IpPoolError> for TunnelError {
    fn from(e: IpPoolError) -> Self {
        TunnelError::IpPool(e)
    }
}

impl From<RoutingError> for TunnelError {
    fn from(e: RoutingError) -> Self {
        TunnelError::Routing(e)
    }
}

/// Tunnel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Tunnel is stopped
    Stopped,
    /// Tunnel is starting
    Starting,
    /// Tunnel is running
    Running,
    /// Tunnel is stopping
    Stopping,
}

/// Tunnel statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    /// Total sessions created
    pub sessions_created: u64,
    /// Total sessions closed
    pub sessions_closed: u64,
    /// Currently active sessions
    pub active_sessions: usize,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
}

/// Tunnel Aggregate Root
///
/// Manages the complete VPN tunnel lifecycle including:
/// - Multiple client sessions
/// - Virtual IP allocation
/// - Routing table
#[derive(Debug)]
pub struct Tunnel {
    /// Tunnel configuration
    config: TunnelConfig,
    /// Current tunnel state
    state: TunnelState,
    /// Active sessions indexed by session ID
    sessions: HashMap<u64, Session>,
    /// IP pool for client address allocation
    ip_pool: IpPool,
    /// IP assignment manager (session <-> IP mapping)
    ip_assignments: IpAssignmentManager,
    /// Routing table
    routing_table: RoutingTable,
    /// Tunnel statistics
    stats: TunnelStats,
}

impl Tunnel {
    /// Create a new tunnel with the given configuration and IP pool
    pub fn new(config: TunnelConfig, ip_pool: IpPool) -> Result<Self, TunnelError> {
        let mut tunnel = Self {
            config,
            state: TunnelState::Stopped,
            sessions: HashMap::new(),
            ip_pool,
            ip_assignments: IpAssignmentManager::new(),
            routing_table: RoutingTable::new(),
            stats: TunnelStats::default(),
        };

        // Reserve server IP from the pool
        if tunnel.ip_pool.is_in_range(tunnel.config.server_ip) {
            tunnel.ip_pool.reserve(tunnel.config.server_ip)?;
        }

        Ok(tunnel)
    }

    /// Create a new tunnel with default configuration
    pub fn with_defaults(network: Ipv4Addr, prefix_len: u8) -> Result<Self, TunnelError> {
        let ip_pool = IpPool::from_cidr(network, prefix_len)?;
        let config = TunnelConfig::default();
        Self::new(config, ip_pool)
    }

    // === State Management ===

    /// Get the current tunnel state
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Check if tunnel is running
    pub fn is_running(&self) -> bool {
        self.state == TunnelState::Running
    }

    /// Start the tunnel
    pub fn start(&mut self) -> Result<(), TunnelError> {
        match self.state {
            TunnelState::Stopped => {
                self.state = TunnelState::Starting;
                // Add default route through tunnel
                let default_route = Route::default_route(
                    self.config.server_ip.addr(),
                    self.config.interface_name.clone(),
                );
                self.routing_table.add_or_update(default_route);
                self.state = TunnelState::Running;
                Ok(())
            }
            TunnelState::Running => Err(TunnelError::AlreadyRunning),
            _ => Err(TunnelError::InvalidConfig("Invalid state for start".to_string())),
        }
    }

    /// Stop the tunnel
    pub fn stop(&mut self) -> Result<(), TunnelError> {
        match self.state {
            TunnelState::Running => {
                self.state = TunnelState::Stopping;
                // Close all sessions
                let session_ids: Vec<u64> = self.sessions.keys().copied().collect();
                for session_id in session_ids {
                    let _ = self.close_session(SessionId::new(session_id));
                }
                self.routing_table.clear();
                self.state = TunnelState::Stopped;
                Ok(())
            }
            TunnelState::Stopped => Ok(()), // Already stopped
            _ => Err(TunnelError::InvalidConfig("Invalid state for stop".to_string())),
        }
    }

    // === Session Management ===

    /// Create a new session and allocate an IP
    pub fn create_session(&mut self) -> Result<(SessionId, VirtualIP), TunnelError> {
        if !self.is_running() {
            return Err(TunnelError::NotRunning);
        }

        // Allocate IP first
        let ip = self.ip_pool.allocate()?;

        // Create session
        let session = Session::new(self.config.session_config.clone());
        let session_id = session.id();

        // Track assignment
        self.ip_assignments.assign(session_id.raw(), ip);
        self.sessions.insert(session_id.raw(), session);

        // Add route for this client
        let client_route = Route::new(
            ip.addr(),
            32,
            None,
            0,
            self.config.interface_name.clone(),
        )?;
        self.routing_table.add_or_update(client_route);

        self.stats.sessions_created += 1;
        self.stats.active_sessions = self.sessions.len();

        Ok((session_id, ip))
    }

    /// Authenticate a session with pre-shared key
    pub fn authenticate_session(&mut self, session_id: SessionId, psk: &[u8]) -> Result<(), TunnelError> {
        let session = self.sessions.get_mut(&session_id.raw())
            .ok_or(TunnelError::SessionNotFound(session_id))?;

        session.start_auth(psk)?;
        session.complete_auth()?;

        Ok(())
    }

    /// Close a session and release its IP
    pub fn close_session(&mut self, session_id: SessionId) -> Result<(), TunnelError> {
        let session = self.sessions.get_mut(&session_id.raw())
            .ok_or(TunnelError::SessionNotFound(session_id))?;

        // Try graceful close
        if session.state() == SessionState::Established {
            let _ = session.close();
            let _ = session.complete_close();
        } else {
            session.force_close();
        }

        // Release IP
        if let Some(ip) = self.ip_assignments.remove_by_session(session_id.raw()) {
            let _ = self.ip_pool.release(ip);
            // Remove client route
            let _ = self.routing_table.remove(ip.addr(), 32);
        }

        self.sessions.remove(&session_id.raw());
        self.stats.sessions_closed += 1;
        self.stats.active_sessions = self.sessions.len();

        Ok(())
    }

    /// Get a session by ID
    pub fn get_session(&self, session_id: SessionId) -> Option<&Session> {
        self.sessions.get(&session_id.raw())
    }

    /// Get a mutable session by ID
    pub fn get_session_mut(&mut self, session_id: SessionId) -> Option<&mut Session> {
        self.sessions.get_mut(&session_id.raw())
    }

    /// Get session by virtual IP
    pub fn get_session_by_ip(&self, ip: VirtualIP) -> Option<&Session> {
        self.ip_assignments.get_session(ip)
            .and_then(|id| self.sessions.get(&id))
    }

    /// Get the IP assigned to a session
    pub fn get_session_ip(&self, session_id: SessionId) -> Option<VirtualIP> {
        self.ip_assignments.get_ip(session_id.raw())
    }

    /// Check all sessions for timeouts and expire them
    pub fn check_sessions(&mut self) -> Vec<SessionId> {
        let mut expired = Vec::new();

        for (id, session) in self.sessions.iter_mut() {
            if session.check_heartbeat().is_err() || session.is_timed_out() {
                expired.push(SessionId::new(*id));
            }
        }

        // Close expired sessions
        for session_id in &expired {
            let _ = self.close_session(*session_id);
        }

        expired
    }

    // === Routing Management ===

    /// Add a route to the routing table
    pub fn add_route(&mut self, route: Route) -> Result<(), TunnelError> {
        self.routing_table.add(route)?;
        Ok(())
    }

    /// Remove a route from the routing table
    pub fn remove_route(&mut self, network: Ipv4Addr, prefix_len: u8) -> Result<Route, TunnelError> {
        Ok(self.routing_table.remove(network, prefix_len)?)
    }

    /// Lookup the best route for a destination
    pub fn lookup_route(&self, dest: Ipv4Addr) -> Option<&Route> {
        self.routing_table.lookup(dest)
    }

    /// Get the routing table
    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }

    // === IP Management ===

    /// Get the IP pool
    pub fn ip_pool(&self) -> &IpPool {
        &self.ip_pool
    }

    /// Get the number of available IPs
    pub fn available_ips(&self) -> u32 {
        self.ip_pool.available()
    }

    // === Statistics ===

    /// Get tunnel statistics
    pub fn stats(&self) -> &TunnelStats {
        &self.stats
    }

    /// Get the tunnel configuration
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    /// Get the number of active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all active sessions
    pub fn sessions(&self) -> impl Iterator<Item = (&u64, &Session)> {
        self.sessions.iter()
    }

    // === Data Transfer ===

    /// Encrypt data for a session
    pub fn encrypt(&mut self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let session = self.sessions.get_mut(&session_id.raw())
            .ok_or(TunnelError::SessionNotFound(session_id))?;

        let encrypted = session.encrypt(data)?;

        self.stats.bytes_sent += data.len() as u64;
        self.stats.packets_sent += 1;

        Ok(encrypted)
    }

    /// Decrypt data for a session
    pub fn decrypt(&mut self, session_id: SessionId, data: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let session = self.sessions.get_mut(&session_id.raw())
            .ok_or(TunnelError::SessionNotFound(session_id))?;

        let decrypted = session.decrypt(data)?;

        self.stats.bytes_received += decrypted.len() as u64;
        self.stats.packets_received += 1;

        Ok(decrypted)
    }

    /// Send heartbeat for a session
    pub fn send_heartbeat(&mut self, session_id: SessionId) -> Result<Vec<u8>, TunnelError> {
        let session = self.sessions.get_mut(&session_id.raw())
            .ok_or(TunnelError::SessionNotFound(session_id))?;

        Ok(session.send_heartbeat()?)
    }

    /// Receive heartbeat for a session
    pub fn recv_heartbeat(&mut self, session_id: SessionId, data: &[u8]) -> Result<(), TunnelError> {
        let session = self.sessions.get_mut(&session_id.raw())
            .ok_or(TunnelError::SessionNotFound(session_id))?;

        session.recv_heartbeat(data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::crypto::KEY_LEN;

    fn test_psk() -> [u8; KEY_LEN] {
        [0x42u8; KEY_LEN]
    }

    fn create_test_tunnel() -> Tunnel {
        let ip_pool = IpPool::from_cidr(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
        let config = TunnelConfig::default()
            .with_server_ip(VirtualIP::from_octets(10, 0, 0, 1));
        Tunnel::new(config, ip_pool).unwrap()
    }

    // === 4.4.1 Tests: Tunnel Aggregate Root ===

    #[test]
    fn test_tunnel_creation() {
        let tunnel = create_test_tunnel();
        assert_eq!(tunnel.state(), TunnelState::Stopped);
        assert_eq!(tunnel.active_session_count(), 0);
    }

    #[test]
    fn test_tunnel_with_defaults() {
        let tunnel = Tunnel::with_defaults(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
        assert_eq!(tunnel.state(), TunnelState::Stopped);
    }

    #[test]
    fn test_tunnel_start_stop() {
        let mut tunnel = create_test_tunnel();

        // Start
        tunnel.start().unwrap();
        assert_eq!(tunnel.state(), TunnelState::Running);
        assert!(tunnel.is_running());

        // Can't start again
        assert!(matches!(tunnel.start(), Err(TunnelError::AlreadyRunning)));

        // Stop
        tunnel.stop().unwrap();
        assert_eq!(tunnel.state(), TunnelState::Stopped);
        assert!(!tunnel.is_running());
    }

    #[test]
    fn test_tunnel_config() {
        let config = TunnelConfig::default()
            .with_interface_name("vpn0".to_string())
            .with_server_ip(VirtualIP::from_octets(192, 168, 1, 1));

        assert_eq!(config.interface_name, "vpn0");
        assert_eq!(config.server_ip, VirtualIP::from_octets(192, 168, 1, 1));
    }

    // === 4.4.2 Tests: Integration of Session + IP + Routing ===

    #[test]
    fn test_create_session_allocates_ip() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, ip) = tunnel.create_session().unwrap();

        // Session should exist
        assert!(tunnel.get_session(session_id).is_some());

        // IP should be allocated
        assert!(tunnel.ip_pool().is_allocated(ip));

        // IP assignment should be tracked
        assert_eq!(tunnel.get_session_ip(session_id), Some(ip));

        // Route should be added
        assert!(tunnel.routing_table().contains(ip.addr(), 32));
    }

    #[test]
    fn test_create_session_requires_running() {
        let mut tunnel = create_test_tunnel();

        let result = tunnel.create_session();
        assert!(matches!(result, Err(TunnelError::NotRunning)));
    }

    #[test]
    fn test_authenticate_session() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, _ip) = tunnel.create_session().unwrap();
        tunnel.authenticate_session(session_id, &test_psk()).unwrap();

        let session = tunnel.get_session(session_id).unwrap();
        assert_eq!(session.state(), SessionState::Established);
    }

    #[test]
    fn test_close_session_releases_ip() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, ip) = tunnel.create_session().unwrap();
        let initial_available = tunnel.available_ips();

        tunnel.close_session(session_id).unwrap();

        // Session should be removed
        assert!(tunnel.get_session(session_id).is_none());

        // IP should be released
        assert!(!tunnel.ip_pool().is_allocated(ip));
        assert_eq!(tunnel.available_ips(), initial_available + 1);

        // Route should be removed
        assert!(!tunnel.routing_table().contains(ip.addr(), 32));
    }

    #[test]
    fn test_get_session_by_ip() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, ip) = tunnel.create_session().unwrap();

        let session = tunnel.get_session_by_ip(ip).unwrap();
        assert_eq!(session.id(), session_id);
    }

    #[test]
    fn test_multiple_sessions() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (id1, ip1) = tunnel.create_session().unwrap();
        let (id2, ip2) = tunnel.create_session().unwrap();
        let (id3, ip3) = tunnel.create_session().unwrap();

        // All IPs should be different
        assert_ne!(ip1, ip2);
        assert_ne!(ip2, ip3);
        assert_ne!(ip1, ip3);

        // All sessions should exist
        assert_eq!(tunnel.active_session_count(), 3);

        // Close one session
        tunnel.close_session(id2).unwrap();
        assert_eq!(tunnel.active_session_count(), 2);
        assert!(tunnel.get_session(id1).is_some());
        assert!(tunnel.get_session(id2).is_none());
        assert!(tunnel.get_session(id3).is_some());
    }

    #[test]
    fn test_routing_integration() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        // Add custom route
        let route = Route::new(
            Ipv4Addr::new(192, 168, 1, 0),
            24,
            Some(Ipv4Addr::new(10, 0, 0, 100)),
            100,
            "tun0".to_string(),
        ).unwrap();
        tunnel.add_route(route).unwrap();

        // Lookup should find the route
        let found = tunnel.lookup_route(Ipv4Addr::new(192, 168, 1, 50)).unwrap();
        assert_eq!(found.prefix_len(), 24);

        // Remove route
        tunnel.remove_route(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert!(!tunnel.routing_table().contains(Ipv4Addr::new(192, 168, 1, 0), 24));
    }

    #[test]
    fn test_data_transfer() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, _ip) = tunnel.create_session().unwrap();
        tunnel.authenticate_session(session_id, &test_psk()).unwrap();

        let plaintext = b"Hello, VPN tunnel!";
        let encrypted = tunnel.encrypt(session_id, plaintext).unwrap();
        let decrypted = tunnel.decrypt(session_id, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);

        // Stats should be updated
        assert!(tunnel.stats().bytes_sent > 0);
        assert!(tunnel.stats().packets_sent > 0);
    }

    #[test]
    fn test_heartbeat() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, _ip) = tunnel.create_session().unwrap();
        tunnel.authenticate_session(session_id, &test_psk()).unwrap();

        let hb = tunnel.send_heartbeat(session_id).unwrap();
        tunnel.recv_heartbeat(session_id, &hb).unwrap();

        let session = tunnel.get_session(session_id).unwrap();
        assert_eq!(session.stats().heartbeats_sent, 1);
        assert_eq!(session.stats().heartbeats_received, 1);
    }

    #[test]
    fn test_tunnel_stats() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let (session_id, _) = tunnel.create_session().unwrap();
        assert_eq!(tunnel.stats().sessions_created, 1);
        assert_eq!(tunnel.stats().active_sessions, 1);

        tunnel.close_session(session_id).unwrap();
        assert_eq!(tunnel.stats().sessions_closed, 1);
        assert_eq!(tunnel.stats().active_sessions, 0);
    }

    #[test]
    fn test_stop_closes_all_sessions() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        tunnel.create_session().unwrap();
        tunnel.create_session().unwrap();
        tunnel.create_session().unwrap();

        assert_eq!(tunnel.active_session_count(), 3);

        tunnel.stop().unwrap();

        assert_eq!(tunnel.active_session_count(), 0);
        assert!(tunnel.routing_table().is_empty());
    }

    // === 4.4.3 Tests: Tunnel Establishment Flow ===

    #[test]
    fn test_full_tunnel_establishment_flow() {
        // 1. Create tunnel with IP pool
        let ip_pool = IpPool::from_cidr(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();
        let config = TunnelConfig::default()
            .with_interface_name("vpn0".to_string())
            .with_server_ip(VirtualIP::from_octets(10, 0, 0, 1));
        let mut tunnel = Tunnel::new(config, ip_pool).unwrap();

        // 2. Start tunnel
        tunnel.start().unwrap();
        assert!(tunnel.is_running());

        // 3. Client connects - create session
        let (session_id, client_ip) = tunnel.create_session().unwrap();
        assert!(client_ip.addr() != Ipv4Addr::new(10, 0, 0, 1)); // Not server IP

        // 4. Authenticate session
        tunnel.authenticate_session(session_id, &test_psk()).unwrap();

        // 5. Verify routing is set up
        let route = tunnel.lookup_route(client_ip.addr()).unwrap();
        assert_eq!(route.prefix_len(), 32); // Host route

        // 6. Data transfer
        let data = b"VPN tunnel data";
        let encrypted = tunnel.encrypt(session_id, data).unwrap();
        let decrypted = tunnel.decrypt(session_id, &encrypted).unwrap();
        assert_eq!(decrypted, data);

        // 7. Heartbeat
        let hb = tunnel.send_heartbeat(session_id).unwrap();
        tunnel.recv_heartbeat(session_id, &hb).unwrap();

        // 8. Close session
        tunnel.close_session(session_id).unwrap();
        assert!(tunnel.get_session(session_id).is_none());

        // 9. Stop tunnel
        tunnel.stop().unwrap();
        assert!(!tunnel.is_running());
    }

    #[test]
    fn test_multiple_clients_tunnel_flow() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        // Simulate multiple clients connecting
        let mut clients = Vec::new();
        for _ in 0..5 {
            let (session_id, ip) = tunnel.create_session().unwrap();
            tunnel.authenticate_session(session_id, &test_psk()).unwrap();
            clients.push((session_id, ip));
        }

        assert_eq!(tunnel.active_session_count(), 5);

        // All clients can send/receive data
        for (session_id, _ip) in &clients {
            let data = format!("Data for session {}", session_id);
            let encrypted = tunnel.encrypt(*session_id, data.as_bytes()).unwrap();
            let decrypted = tunnel.decrypt(*session_id, &encrypted).unwrap();
            assert_eq!(decrypted, data.as_bytes());
        }

        // Close some clients
        tunnel.close_session(clients[0].0).unwrap();
        tunnel.close_session(clients[2].0).unwrap();

        assert_eq!(tunnel.active_session_count(), 3);

        // Remaining clients still work
        let data = b"Still working";
        let encrypted = tunnel.encrypt(clients[1].0, data).unwrap();
        let decrypted = tunnel.decrypt(clients[1].0, &encrypted).unwrap();
        assert_eq!(decrypted, data);

        tunnel.stop().unwrap();
    }

    #[test]
    fn test_ip_pool_exhaustion_handling() {
        // Create tunnel with very small IP pool
        let ip_pool = IpPool::new(
            VirtualIP::from_octets(10, 0, 0, 2),
            VirtualIP::from_octets(10, 0, 0, 4),
        ).unwrap();
        let config = TunnelConfig::default()
            .with_server_ip(VirtualIP::from_octets(10, 0, 0, 1));
        let mut tunnel = Tunnel::new(config, ip_pool).unwrap();
        tunnel.start().unwrap();

        // Create sessions until pool is exhausted
        tunnel.create_session().unwrap();
        tunnel.create_session().unwrap();
        tunnel.create_session().unwrap();

        // Next session should fail
        let result = tunnel.create_session();
        assert!(matches!(result, Err(TunnelError::IpPool(IpPoolError::PoolExhausted))));
    }

    #[test]
    fn test_session_not_found_errors() {
        let mut tunnel = create_test_tunnel();
        tunnel.start().unwrap();

        let fake_id = SessionId::new(99999);

        assert!(matches!(
            tunnel.authenticate_session(fake_id, &test_psk()),
            Err(TunnelError::SessionNotFound(_))
        ));

        assert!(matches!(
            tunnel.close_session(fake_id),
            Err(TunnelError::SessionNotFound(_))
        ));

        assert!(matches!(
            tunnel.encrypt(fake_id, b"data"),
            Err(TunnelError::SessionNotFound(_))
        ));
    }
}
