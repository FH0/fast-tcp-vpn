//! Session Management for VPN Tunnel
//!
//! Implements session entity with lifecycle management, authentication,
//! and heartbeat keepalive functionality.

use std::time::{Duration, Instant};

use crate::infrastructure::crypto::{ChaCha20Poly1305, CryptoError, Encryptor, KEY_LEN, NONCE_LEN};

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new session ID from a u64 value
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Generate a random session ID
    pub fn random() -> Self {
        use std::time::SystemTime;
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Simple pseudo-random using time and a multiplier
        Self(seed.wrapping_mul(6364136223846793005).wrapping_add(1))
    }

    /// Get the raw u64 value
    pub fn raw(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being created, not yet authenticated
    Pending,
    /// Session is authenticating
    Authenticating,
    /// Session is fully established and active
    Established,
    /// Session is being closed gracefully
    Closing,
    /// Session has been closed
    Closed,
    /// Session has expired due to timeout
    Expired,
}

impl SessionState {
    /// Check if session is active (can send/receive data)
    pub fn is_active(&self) -> bool {
        matches!(self, SessionState::Established)
    }

    /// Check if session is terminated
    pub fn is_terminated(&self) -> bool {
        matches!(self, SessionState::Closed | SessionState::Expired)
    }
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Session timeout (no activity)
    pub session_timeout: Duration,
    /// Maximum missed heartbeats before session expires
    pub max_missed_heartbeats: u32,
    /// Authentication timeout
    pub auth_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(30),
            session_timeout: Duration::from_secs(300),
            max_missed_heartbeats: 3,
            auth_timeout: Duration::from_secs(10),
        }
    }
}

impl SessionConfig {
    /// Create a new session config with custom heartbeat interval
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Create a new session config with custom session timeout
    pub fn with_session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Create a new session config with custom max missed heartbeats
    pub fn with_max_missed_heartbeats(mut self, max: u32) -> Self {
        self.max_missed_heartbeats = max;
        self
    }

    /// Create a new session config with custom auth timeout
    pub fn with_auth_timeout(mut self, timeout: Duration) -> Self {
        self.auth_timeout = timeout;
        self
    }
}

/// Session statistics
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Heartbeats sent
    pub heartbeats_sent: u64,
    /// Heartbeats received
    pub heartbeats_received: u64,
    /// Missed heartbeats (consecutive)
    pub missed_heartbeats: u32,
}

/// Session error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session is not in the expected state
    InvalidState { expected: SessionState, actual: SessionState },
    /// Authentication failed
    AuthenticationFailed,
    /// Session has expired
    SessionExpired,
    /// Session is already closed
    AlreadyClosed,
    /// Invalid pre-shared key
    InvalidKey,
    /// Crypto operation failed
    CryptoError(String),
    /// Session not found
    NotFound,
    /// Heartbeat timeout
    HeartbeatTimeout,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::InvalidState { expected, actual } => {
                write!(f, "Invalid state: expected {:?}, got {:?}", expected, actual)
            }
            SessionError::AuthenticationFailed => write!(f, "Authentication failed"),
            SessionError::SessionExpired => write!(f, "Session expired"),
            SessionError::AlreadyClosed => write!(f, "Session already closed"),
            SessionError::InvalidKey => write!(f, "Invalid pre-shared key"),
            SessionError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::HeartbeatTimeout => write!(f, "Heartbeat timeout"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<CryptoError> for SessionError {
    fn from(e: CryptoError) -> Self {
        SessionError::CryptoError(e.to_string())
    }
}

/// VPN Session Entity
///
/// Represents a single VPN session with:
/// - Unique session ID
/// - Authentication state
/// - Encryption context
/// - Heartbeat management
/// - Session statistics
#[derive(Debug)]
pub struct Session {
    /// Unique session identifier
    id: SessionId,
    /// Current session state
    state: SessionState,
    /// Session configuration
    config: SessionConfig,
    /// Encryptor for this session
    encryptor: Option<ChaCha20Poly1305>,
    /// Session creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Last heartbeat sent time
    last_heartbeat_sent: Option<Instant>,
    /// Last heartbeat received time
    last_heartbeat_received: Option<Instant>,
    /// Nonce counter for encryption
    nonce_counter: u64,
    /// Session statistics
    stats: SessionStats,
}

impl Session {
    /// Create a new session in Pending state
    pub fn new(config: SessionConfig) -> Self {
        let now = Instant::now();
        Self {
            id: SessionId::random(),
            state: SessionState::Pending,
            config,
            encryptor: None,
            created_at: now,
            last_activity: now,
            last_heartbeat_sent: None,
            last_heartbeat_received: None,
            nonce_counter: 0,
            stats: SessionStats::default(),
        }
    }

    /// Create a new session with a specific ID
    pub fn with_id(id: SessionId, config: SessionConfig) -> Self {
        let now = Instant::now();
        Self {
            id,
            state: SessionState::Pending,
            config,
            encryptor: None,
            created_at: now,
            last_activity: now,
            last_heartbeat_sent: None,
            last_heartbeat_received: None,
            nonce_counter: 0,
            stats: SessionStats::default(),
        }
    }

    /// Get the session ID
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Get the current session state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get session statistics
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Check if session needs a heartbeat
    pub fn needs_heartbeat(&self) -> bool {
        if self.state != SessionState::Established {
            return false;
        }
        match self.last_heartbeat_sent {
            Some(last) => last.elapsed() >= self.config.heartbeat_interval,
            None => true,
        }
    }

    /// Check if session has timed out
    pub fn is_timed_out(&self) -> bool {
        match self.state {
            SessionState::Pending | SessionState::Authenticating => {
                self.created_at.elapsed() > self.config.auth_timeout
            }
            SessionState::Established => {
                self.last_activity.elapsed() > self.config.session_timeout
            }
            _ => false,
        }
    }

    /// Check if too many heartbeats have been missed
    pub fn has_heartbeat_timeout(&self) -> bool {
        self.stats.missed_heartbeats >= self.config.max_missed_heartbeats
    }

    // === State Transition Methods ===

    /// Start authentication with a pre-shared key
    ///
    /// Transitions: Pending -> Authenticating
    pub fn start_auth(&mut self, psk: &[u8]) -> Result<(), SessionError> {
        if self.state != SessionState::Pending {
            return Err(SessionError::InvalidState {
                expected: SessionState::Pending,
                actual: self.state,
            });
        }

        // Validate key length
        if psk.len() != KEY_LEN {
            return Err(SessionError::InvalidKey);
        }

        // Create encryptor with the PSK
        let encryptor = ChaCha20Poly1305::new(psk)?;
        self.encryptor = Some(encryptor);
        self.state = SessionState::Authenticating;
        self.touch();

        Ok(())
    }

    /// Complete authentication and establish session
    ///
    /// Transitions: Authenticating -> Established
    pub fn complete_auth(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Authenticating {
            return Err(SessionError::InvalidState {
                expected: SessionState::Authenticating,
                actual: self.state,
            });
        }

        self.state = SessionState::Established;
        self.last_heartbeat_received = Some(Instant::now());
        self.touch();

        Ok(())
    }

    /// Fail authentication
    ///
    /// Transitions: Authenticating -> Closed
    pub fn fail_auth(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Authenticating {
            return Err(SessionError::InvalidState {
                expected: SessionState::Authenticating,
                actual: self.state,
            });
        }

        self.state = SessionState::Closed;
        self.encryptor = None;

        Err(SessionError::AuthenticationFailed)
    }

    /// Initiate graceful close
    ///
    /// Transitions: Established -> Closing
    pub fn close(&mut self) -> Result<(), SessionError> {
        match self.state {
            SessionState::Established => {
                self.state = SessionState::Closing;
                self.touch();
                Ok(())
            }
            SessionState::Closed | SessionState::Expired => {
                Err(SessionError::AlreadyClosed)
            }
            _ => Err(SessionError::InvalidState {
                expected: SessionState::Established,
                actual: self.state,
            }),
        }
    }

    /// Complete close
    ///
    /// Transitions: Closing -> Closed
    pub fn complete_close(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Closing {
            return Err(SessionError::InvalidState {
                expected: SessionState::Closing,
                actual: self.state,
            });
        }

        self.state = SessionState::Closed;
        self.encryptor = None;

        Ok(())
    }

    /// Force close (for error conditions)
    pub fn force_close(&mut self) {
        self.state = SessionState::Closed;
        self.encryptor = None;
    }

    /// Mark session as expired
    pub fn expire(&mut self) {
        self.state = SessionState::Expired;
        self.encryptor = None;
    }

    /// Destroy session and clear all sensitive data
    pub fn destroy(&mut self) {
        self.state = SessionState::Closed;
        self.encryptor = None;
        self.nonce_counter = 0;
        // Stats are kept for logging purposes
    }

    // === Heartbeat Methods ===

    /// Send a heartbeat
    pub fn send_heartbeat(&mut self) -> Result<Vec<u8>, SessionError> {
        if self.state != SessionState::Established {
            return Err(SessionError::InvalidState {
                expected: SessionState::Established,
                actual: self.state,
            });
        }

        let heartbeat_data = self.create_heartbeat_payload();
        let encrypted = self.encrypt(&heartbeat_data)?;

        self.last_heartbeat_sent = Some(Instant::now());
        self.stats.heartbeats_sent += 1;
        self.stats.missed_heartbeats += 1; // Will be reset when we receive response

        Ok(encrypted)
    }

    /// Receive a heartbeat
    pub fn recv_heartbeat(&mut self, data: &[u8]) -> Result<(), SessionError> {
        if self.state != SessionState::Established {
            return Err(SessionError::InvalidState {
                expected: SessionState::Established,
                actual: self.state,
            });
        }

        // Decrypt and validate heartbeat
        let _decrypted = self.decrypt(data)?;

        self.last_heartbeat_received = Some(Instant::now());
        self.stats.heartbeats_received += 1;
        self.stats.missed_heartbeats = 0; // Reset missed counter
        self.touch();

        Ok(())
    }

    /// Check heartbeat status and expire if needed
    pub fn check_heartbeat(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Established {
            return Ok(());
        }

        if self.has_heartbeat_timeout() {
            self.expire();
            return Err(SessionError::HeartbeatTimeout);
        }

        if self.is_timed_out() {
            self.expire();
            return Err(SessionError::SessionExpired);
        }

        Ok(())
    }

    // === Data Transfer Methods ===

    /// Encrypt data for sending
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if self.encryptor.is_none() {
            return Err(SessionError::InvalidState {
                expected: SessionState::Established,
                actual: self.state,
            });
        }

        let nonce = self.next_nonce();
        let mut result = nonce.to_vec();
        let ciphertext = self.encryptor.as_ref().unwrap().encrypt(&nonce, plaintext)?;
        result.extend(ciphertext);

        self.stats.bytes_sent += plaintext.len() as u64;
        self.stats.packets_sent += 1;
        self.touch();

        Ok(result)
    }

    /// Decrypt received data
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let encryptor = self.encryptor.as_ref().ok_or(SessionError::InvalidState {
            expected: SessionState::Established,
            actual: self.state,
        })?;

        if ciphertext.len() < NONCE_LEN {
            return Err(SessionError::CryptoError("Data too short".to_string()));
        }

        let (nonce, ct) = ciphertext.split_at(NONCE_LEN);
        let plaintext = encryptor.decrypt(nonce, ct)?;

        self.stats.bytes_received += plaintext.len() as u64;
        self.stats.packets_received += 1;
        self.touch();

        Ok(plaintext)
    }

    // === Private Helper Methods ===

    /// Update last activity timestamp
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Generate next nonce
    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        let counter_bytes = self.nonce_counter.to_le_bytes();
        nonce[..8].copy_from_slice(&counter_bytes);
        // Add session ID to make nonce unique across sessions
        let id_bytes = (self.id.0 as u32).to_le_bytes();
        nonce[8..12].copy_from_slice(&id_bytes);
        self.nonce_counter += 1;
        nonce
    }

    /// Create heartbeat payload
    fn create_heartbeat_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(16);
        // Magic bytes for heartbeat
        payload.extend_from_slice(b"HBEAT");
        // Session ID
        payload.extend_from_slice(&self.id.0.to_le_bytes());
        // Timestamp
        let ts = self.created_at.elapsed().as_millis() as u32;
        payload.extend_from_slice(&ts.to_le_bytes());
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> [u8; KEY_LEN] {
        [0x42u8; KEY_LEN]
    }

    // === 4.1.1 Tests: Session Entity Definition ===

    #[test]
    fn test_session_id_creation() {
        let id1 = SessionId::new(12345);
        assert_eq!(id1.raw(), 12345);

        let id2 = SessionId::random();
        let id3 = SessionId::random();
        // Random IDs should be different (with very high probability)
        // Note: This could theoretically fail but is extremely unlikely
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_session_id_display() {
        let id = SessionId::new(0x123456789ABCDEF0);
        assert_eq!(format!("{}", id), "123456789abcdef0");
    }

    #[test]
    fn test_session_state_checks() {
        assert!(SessionState::Established.is_active());
        assert!(!SessionState::Pending.is_active());
        assert!(!SessionState::Closed.is_active());

        assert!(SessionState::Closed.is_terminated());
        assert!(SessionState::Expired.is_terminated());
        assert!(!SessionState::Established.is_terminated());
    }

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.session_timeout, Duration::from_secs(300));
        assert_eq!(config.max_missed_heartbeats, 3);
        assert_eq!(config.auth_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_session_config_builder() {
        let config = SessionConfig::default()
            .with_heartbeat_interval(Duration::from_secs(10))
            .with_session_timeout(Duration::from_secs(60))
            .with_max_missed_heartbeats(5)
            .with_auth_timeout(Duration::from_secs(5));

        assert_eq!(config.heartbeat_interval, Duration::from_secs(10));
        assert_eq!(config.session_timeout, Duration::from_secs(60));
        assert_eq!(config.max_missed_heartbeats, 5);
        assert_eq!(config.auth_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_session_new() {
        let session = Session::new(SessionConfig::default());
        assert_eq!(session.state(), SessionState::Pending);
        assert!(session.age() < Duration::from_secs(1));
        assert!(session.idle_time() < Duration::from_secs(1));
    }

    #[test]
    fn test_session_with_id() {
        let id = SessionId::new(999);
        let session = Session::with_id(id, SessionConfig::default());
        assert_eq!(session.id(), id);
        assert_eq!(session.state(), SessionState::Pending);
    }

    // === 4.1.2 Tests: Session Creation/Destruction ===

    #[test]
    fn test_session_lifecycle_create_destroy() {
        let mut session = Session::new(SessionConfig::default());
        assert_eq!(session.state(), SessionState::Pending);

        // Start auth
        session.start_auth(&test_psk()).unwrap();
        assert_eq!(session.state(), SessionState::Authenticating);

        // Complete auth
        session.complete_auth().unwrap();
        assert_eq!(session.state(), SessionState::Established);

        // Close
        session.close().unwrap();
        assert_eq!(session.state(), SessionState::Closing);

        // Complete close
        session.complete_close().unwrap();
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_destroy() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        session.destroy();
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_force_close() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        session.force_close();
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_expire() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        session.expire();
        assert_eq!(session.state(), SessionState::Expired);
        assert!(session.state().is_terminated());
    }

    // === 4.1.3 Tests: Session Authentication ===

    #[test]
    fn test_auth_success() {
        let mut session = Session::new(SessionConfig::default());

        session.start_auth(&test_psk()).unwrap();
        assert_eq!(session.state(), SessionState::Authenticating);

        session.complete_auth().unwrap();
        assert_eq!(session.state(), SessionState::Established);
    }

    #[test]
    fn test_auth_invalid_key_length() {
        let mut session = Session::new(SessionConfig::default());
        let short_key = [0u8; 16]; // Too short

        let result = session.start_auth(&short_key);
        assert!(matches!(result, Err(SessionError::InvalidKey)));
    }

    #[test]
    fn test_auth_fail() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();

        let result = session.fail_auth();
        assert!(matches!(result, Err(SessionError::AuthenticationFailed)));
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_auth_wrong_state() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        // Try to start auth again
        let result = session.start_auth(&test_psk());
        assert!(matches!(result, Err(SessionError::InvalidState { .. })));
    }

    #[test]
    fn test_complete_auth_wrong_state() {
        let mut session = Session::new(SessionConfig::default());

        // Try to complete auth without starting
        let result = session.complete_auth();
        assert!(matches!(result, Err(SessionError::InvalidState { .. })));
    }

    // === 4.1.4 Tests: Heartbeat ===

    #[test]
    fn test_heartbeat_send_recv() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        // Send heartbeat
        let heartbeat = session.send_heartbeat().unwrap();
        assert!(!heartbeat.is_empty());
        assert_eq!(session.stats().heartbeats_sent, 1);
        assert_eq!(session.stats().missed_heartbeats, 1);

        // Receive heartbeat (simulate echo)
        session.recv_heartbeat(&heartbeat).unwrap();
        assert_eq!(session.stats().heartbeats_received, 1);
        assert_eq!(session.stats().missed_heartbeats, 0);
    }

    #[test]
    fn test_heartbeat_not_established() {
        let mut session = Session::new(SessionConfig::default());

        let result = session.send_heartbeat();
        assert!(matches!(result, Err(SessionError::InvalidState { .. })));
    }

    #[test]
    fn test_needs_heartbeat() {
        let config = SessionConfig::default()
            .with_heartbeat_interval(Duration::from_millis(10));
        let mut session = Session::new(config);
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        // Initially needs heartbeat (never sent)
        assert!(session.needs_heartbeat());

        // After sending, doesn't need immediately
        session.send_heartbeat().unwrap();
        assert!(!session.needs_heartbeat());

        // After interval, needs again
        std::thread::sleep(Duration::from_millis(15));
        assert!(session.needs_heartbeat());
    }

    #[test]
    fn test_heartbeat_timeout() {
        let config = SessionConfig::default()
            .with_max_missed_heartbeats(2);
        let mut session = Session::new(config);
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        // Miss heartbeats
        session.send_heartbeat().unwrap();
        session.send_heartbeat().unwrap();

        assert!(session.has_heartbeat_timeout());

        let result = session.check_heartbeat();
        assert!(matches!(result, Err(SessionError::HeartbeatTimeout)));
        assert_eq!(session.state(), SessionState::Expired);
    }

    // === 4.1.5 Tests: Session Lifecycle ===

    #[test]
    fn test_full_session_lifecycle() {
        let mut session = Session::new(SessionConfig::default());

        // 1. Pending state
        assert_eq!(session.state(), SessionState::Pending);
        assert!(!session.state().is_active());

        // 2. Start authentication
        session.start_auth(&test_psk()).unwrap();
        assert_eq!(session.state(), SessionState::Authenticating);

        // 3. Complete authentication
        session.complete_auth().unwrap();
        assert_eq!(session.state(), SessionState::Established);
        assert!(session.state().is_active());

        // 4. Data transfer
        let plaintext = b"Hello, VPN!";
        let encrypted = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // 5. Heartbeat
        let hb = session.send_heartbeat().unwrap();
        session.recv_heartbeat(&hb).unwrap();

        // 6. Close
        session.close().unwrap();
        assert_eq!(session.state(), SessionState::Closing);

        // 7. Complete close
        session.complete_close().unwrap();
        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.state().is_terminated());
    }

    #[test]
    fn test_session_stats() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        // Initial stats
        assert_eq!(session.stats().bytes_sent, 0);
        assert_eq!(session.stats().packets_sent, 0);

        // Send data
        let data = b"test data";
        session.encrypt(data).unwrap();

        assert_eq!(session.stats().bytes_sent, data.len() as u64);
        assert_eq!(session.stats().packets_sent, 1);
    }

    // === 4.1.6 Tests: Authentication Failure Handling ===

    #[test]
    fn test_auth_failure_closes_session() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();

        let result = session.fail_auth();
        assert!(result.is_err());
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_close_already_closed() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();
        session.close().unwrap();
        session.complete_close().unwrap();

        let result = session.close();
        assert!(matches!(result, Err(SessionError::AlreadyClosed)));
    }

    #[test]
    fn test_encrypt_without_auth() {
        let mut session = Session::new(SessionConfig::default());

        let result = session.encrypt(b"test");
        assert!(matches!(result, Err(SessionError::InvalidState { .. })));
    }

    #[test]
    fn test_decrypt_without_auth() {
        let mut session = Session::new(SessionConfig::default());

        let result = session.decrypt(b"test");
        assert!(matches!(result, Err(SessionError::InvalidState { .. })));
    }

    #[test]
    fn test_decrypt_too_short() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        let result = session.decrypt(&[0u8; 5]); // Too short for nonce
        assert!(matches!(result, Err(SessionError::CryptoError(_))));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut session = Session::new(SessionConfig::default());
        session.start_auth(&test_psk()).unwrap();
        session.complete_auth().unwrap();

        let plaintext = b"Secret VPN data that needs encryption";
        let encrypted = session.encrypt(plaintext).unwrap();

        // Encrypted should be different from plaintext
        assert_ne!(&encrypted[..plaintext.len()], plaintext);

        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_sessions_different_ciphertext() {
        let mut session1 = Session::with_id(SessionId::new(1), SessionConfig::default());
        let mut session2 = Session::with_id(SessionId::new(2), SessionConfig::default());

        session1.start_auth(&test_psk()).unwrap();
        session1.complete_auth().unwrap();
        session2.start_auth(&test_psk()).unwrap();
        session2.complete_auth().unwrap();

        let plaintext = b"Same plaintext";
        let ct1 = session1.encrypt(plaintext).unwrap();
        let ct2 = session2.encrypt(plaintext).unwrap();

        // Different sessions should produce different ciphertext
        assert_ne!(ct1, ct2);
    }
}
