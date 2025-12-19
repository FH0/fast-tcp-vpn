//! TCP Connection Entity
//!
//! Implements the Connection entity that combines state machine, sequence numbers,
//! and peer information for managing TCP connections.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use super::sequence::{IsnGenerator, SeqNum};
use super::state::{ConnectionState, StateTransitionError, TcpAction, TcpEvent};

/// Connection endpoint information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub addr: Ipv4Addr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(addr: Ipv4Addr, port: u16) -> Self {
        Self { addr, port }
    }

    pub fn to_socket_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.addr, self.port)
    }
}

impl From<SocketAddrV4> for Endpoint {
    fn from(addr: SocketAddrV4) -> Self {
        Self {
            addr: *addr.ip(),
            port: addr.port(),
        }
    }
}

/// Connection identifier (4-tuple)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    pub local: Endpoint,
    pub remote: Endpoint,
}

impl ConnectionId {
    pub fn new(local: Endpoint, remote: Endpoint) -> Self {
        Self { local, remote }
    }

    /// Create a reversed connection ID (swap local and remote)
    pub fn reversed(&self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
        }
    }
}

/// Send sequence space variables
#[derive(Debug, Clone)]
pub struct SendSequence {
    /// Send unacknowledged (oldest unacknowledged sequence number)
    pub una: SeqNum,
    /// Send next (next sequence number to send)
    pub nxt: SeqNum,
    /// Send window
    pub wnd: u32,
    /// Initial send sequence number
    pub iss: SeqNum,
}

impl SendSequence {
    pub fn new(iss: SeqNum) -> Self {
        Self {
            una: iss,
            nxt: iss,
            wnd: 65535,
            iss,
        }
    }

    /// Get the number of bytes in flight (sent but not acknowledged)
    pub fn bytes_in_flight(&self) -> u32 {
        self.nxt.raw().wrapping_sub(self.una.raw())
    }

    /// Check if we can send more data
    pub fn can_send(&self, len: u32) -> bool {
        self.bytes_in_flight() + len <= self.wnd
    }

    /// Advance the next sequence number after sending data
    pub fn advance(&mut self, len: u32) {
        self.nxt = self.nxt + len;
    }

    /// Acknowledge data up to the given sequence number
    pub fn acknowledge(&mut self, ack: SeqNum) {
        if ack.is_after(self.una) && ack.is_before_or_eq(self.nxt) {
            self.una = ack;
        }
    }
}

/// Receive sequence space variables
#[derive(Debug, Clone)]
pub struct RecvSequence {
    /// Receive next (next expected sequence number)
    pub nxt: SeqNum,
    /// Receive window
    pub wnd: u32,
    /// Initial receive sequence number
    pub irs: SeqNum,
}

impl RecvSequence {
    pub fn new(irs: SeqNum) -> Self {
        Self {
            nxt: irs + 1, // After receiving SYN, expect irs + 1
            wnd: 65535,
            irs,
        }
    }

    /// Check if a sequence number is within the receive window
    pub fn in_window(&self, seq: SeqNum, len: u32) -> bool {
        if len == 0 {
            // Zero-length segment
            if self.wnd == 0 {
                seq == self.nxt
            } else {
                seq.in_range(self.nxt, self.nxt + self.wnd)
            }
        } else {
            // Non-zero length segment
            if self.wnd == 0 {
                false
            } else {
                let seg_end = seq + len - 1;
                seq.in_range(self.nxt, self.nxt + self.wnd)
                    || seg_end.in_range(self.nxt, self.nxt + self.wnd)
            }
        }
    }

    /// Advance the next expected sequence number after receiving data
    pub fn advance(&mut self, len: u32) {
        self.nxt = self.nxt + len;
    }
}

/// Connection error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// Invalid state transition
    InvalidTransition(StateTransitionError),
    /// Connection is not established
    NotEstablished,
    /// Connection is closed
    Closed,
    /// Connection was reset
    Reset,
    /// Send buffer full
    SendBufferFull,
    /// Invalid sequence number
    InvalidSequence,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::InvalidTransition(e) => write!(f, "Invalid transition: {}", e),
            ConnectionError::NotEstablished => write!(f, "Connection not established"),
            ConnectionError::Closed => write!(f, "Connection closed"),
            ConnectionError::Reset => write!(f, "Connection reset"),
            ConnectionError::SendBufferFull => write!(f, "Send buffer full"),
            ConnectionError::InvalidSequence => write!(f, "Invalid sequence number"),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<StateTransitionError> for ConnectionError {
    fn from(e: StateTransitionError) -> Self {
        ConnectionError::InvalidTransition(e)
    }
}

/// Result of a connection operation
#[derive(Debug, Clone)]
pub struct ConnectionResult {
    /// Action to take
    pub action: TcpAction,
    /// Sequence number to use (for SYN, FIN, or data)
    pub seq: Option<SeqNum>,
    /// Acknowledgment number to use
    pub ack: Option<SeqNum>,
}

impl ConnectionResult {
    pub fn new(action: TcpAction) -> Self {
        Self {
            action,
            seq: None,
            ack: None,
        }
    }

    pub fn with_seq(mut self, seq: SeqNum) -> Self {
        self.seq = Some(seq);
        self
    }

    pub fn with_ack(mut self, ack: SeqNum) -> Self {
        self.ack = Some(ack);
        self
    }
}

/// TCP Connection Entity
///
/// Manages the complete state of a TCP connection including:
/// - Connection state (from state machine)
/// - Send and receive sequence numbers
/// - Peer information (local and remote endpoints)
/// - Timing information
#[derive(Debug, Clone)]
pub struct Connection {
    /// Connection identifier (4-tuple)
    pub id: ConnectionId,
    /// Current connection state
    state: ConnectionState,
    /// Send sequence space
    send: Option<SendSequence>,
    /// Receive sequence space
    recv: Option<RecvSequence>,
    /// Time when connection was created
    created_at: Instant,
    /// Time of last activity
    last_activity: Instant,
}

impl Connection {
    /// Create a new connection in CLOSED state
    pub fn new(id: ConnectionId) -> Self {
        let now = Instant::now();
        Self {
            id,
            state: ConnectionState::Closed,
            send: None,
            recv: None,
            created_at: now,
            last_activity: now,
        }
    }

    /// Get the current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get the send sequence space (if initialized)
    pub fn send_seq(&self) -> Option<&SendSequence> {
        self.send.as_ref()
    }

    /// Get the receive sequence space (if initialized)
    pub fn recv_seq(&self) -> Option<&RecvSequence> {
        self.recv.as_ref()
    }

    /// Get the time since connection was created
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get the time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Update the last activity timestamp
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    // === Connection Establishment Methods ===

    /// Initiate an active open (client-side connection)
    ///
    /// Transitions: CLOSED -> SYN-SENT
    /// Action: Send SYN with ISN
    pub fn active_open(&mut self, isn_gen: &mut IsnGenerator) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::ActiveOpen)?;
        self.state = transition.new_state;
        self.touch();

        // Generate ISN and initialize send sequence space
        let iss = isn_gen.generate(
            u32::from(self.id.local.addr),
            u32::from(self.id.remote.addr),
            self.id.local.port,
            self.id.remote.port,
        );
        self.send = Some(SendSequence::new(iss));

        // SYN consumes one sequence number
        if let Some(ref mut send) = self.send {
            send.nxt = send.nxt + 1;
        }

        Ok(ConnectionResult::new(transition.action).with_seq(iss))
    }

    /// Initiate a passive open (server-side listening)
    ///
    /// Transitions: CLOSED -> LISTEN
    pub fn passive_open(&mut self) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::PassiveOpen)?;
        self.state = transition.new_state;
        self.touch();

        Ok(ConnectionResult::new(transition.action))
    }

    /// Handle receiving a SYN segment (server-side)
    ///
    /// Transitions: LISTEN -> SYN-RECEIVED
    /// Action: Send SYN+ACK
    pub fn recv_syn(
        &mut self,
        isn_gen: &mut IsnGenerator,
        remote_seq: SeqNum,
    ) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::RecvSyn)?;
        self.state = transition.new_state;
        self.touch();

        // Initialize receive sequence space with remote's ISN
        self.recv = Some(RecvSequence::new(remote_seq));

        // Generate our ISN and initialize send sequence space
        let iss = isn_gen.generate(
            u32::from(self.id.local.addr),
            u32::from(self.id.remote.addr),
            self.id.local.port,
            self.id.remote.port,
        );
        self.send = Some(SendSequence::new(iss));

        // SYN consumes one sequence number
        if let Some(ref mut send) = self.send {
            send.nxt = send.nxt + 1;
        }

        let ack = self.recv.as_ref().map(|r| r.nxt).unwrap();
        Ok(ConnectionResult::new(transition.action)
            .with_seq(iss)
            .with_ack(ack))
    }

    /// Handle receiving a SYN+ACK segment (client-side)
    ///
    /// Transitions: SYN-SENT -> ESTABLISHED
    /// Action: Send ACK
    pub fn recv_syn_ack(
        &mut self,
        remote_seq: SeqNum,
        ack_num: SeqNum,
    ) -> Result<ConnectionResult, ConnectionError> {
        // Validate the ACK
        if let Some(ref send) = self.send {
            if ack_num != send.nxt {
                return Err(ConnectionError::InvalidSequence);
            }
            // ACK is valid, update una
        }

        let transition = self.state.transition(TcpEvent::RecvSynAck)?;
        self.state = transition.new_state;
        self.touch();

        // Initialize receive sequence space
        self.recv = Some(RecvSequence::new(remote_seq));

        // Update send sequence - our SYN has been acknowledged
        if let Some(ref mut send) = self.send {
            send.una = ack_num;
        }

        let ack = self.recv.as_ref().map(|r| r.nxt).unwrap();
        Ok(ConnectionResult::new(transition.action).with_ack(ack))
    }

    /// Handle receiving an ACK segment (completing handshake on server-side)
    ///
    /// Transitions: SYN-RECEIVED -> ESTABLISHED
    pub fn recv_ack(&mut self, ack_num: SeqNum) -> Result<ConnectionResult, ConnectionError> {
        // Validate the ACK
        if let Some(ref send) = self.send {
            if ack_num != send.nxt {
                return Err(ConnectionError::InvalidSequence);
            }
        }

        let transition = self.state.transition(TcpEvent::RecvAck)?;
        self.state = transition.new_state;
        self.touch();

        // Update send sequence - our SYN has been acknowledged
        if let Some(ref mut send) = self.send {
            send.una = ack_num;
        }

        Ok(ConnectionResult::new(transition.action))
    }

    // === Data Transfer Methods ===

    /// Send data on the connection
    ///
    /// Returns the sequence number to use for the data segment
    pub fn send_data(&mut self, len: u32) -> Result<ConnectionResult, ConnectionError> {
        if !self.state.can_send() {
            return Err(ConnectionError::NotEstablished);
        }

        let send = self.send.as_mut().ok_or(ConnectionError::NotEstablished)?;

        if !send.can_send(len) {
            return Err(ConnectionError::SendBufferFull);
        }

        let seq = send.nxt;
        send.advance(len);
        self.touch();

        let ack = self.recv.as_ref().map(|r| r.nxt);
        let mut result = ConnectionResult::new(TcpAction::None).with_seq(seq);
        if let Some(ack) = ack {
            result = result.with_ack(ack);
        }
        Ok(result)
    }

    /// Receive data on the connection
    ///
    /// Updates the receive sequence space
    pub fn recv_data(&mut self, seq: SeqNum, len: u32, ack_num: Option<SeqNum>) -> Result<ConnectionResult, ConnectionError> {
        if !self.state.can_receive() {
            return Err(ConnectionError::NotEstablished);
        }

        let recv = self.recv.as_mut().ok_or(ConnectionError::NotEstablished)?;

        // Check if segment is in window
        if !recv.in_window(seq, len) {
            return Err(ConnectionError::InvalidSequence);
        }

        // For simplicity, only accept in-order data
        if seq == recv.nxt {
            recv.advance(len);
        }

        // Process ACK if present
        if let Some(ack) = ack_num {
            if let Some(ref mut send) = self.send {
                send.acknowledge(ack);
            }
        }

        self.touch();

        let ack = self.recv.as_ref().map(|r| r.nxt).unwrap();
        Ok(ConnectionResult::new(TcpAction::SendAck).with_ack(ack))
    }

    // === Connection Termination Methods ===

    /// Initiate connection close
    ///
    /// Transitions depend on current state:
    /// - ESTABLISHED -> FIN-WAIT-1
    /// - CLOSE-WAIT -> LAST-ACK
    pub fn close(&mut self) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::Close)?;
        self.state = transition.new_state;
        self.touch();

        // FIN consumes one sequence number
        let seq = if let Some(ref mut send) = self.send {
            let seq = send.nxt;
            send.nxt = send.nxt + 1;
            Some(seq)
        } else {
            None
        };

        let mut result = ConnectionResult::new(transition.action);
        if let Some(seq) = seq {
            result = result.with_seq(seq);
        }
        if let Some(ref recv) = self.recv {
            result = result.with_ack(recv.nxt);
        }
        Ok(result)
    }

    /// Handle receiving a FIN segment
    ///
    /// Transitions depend on current state:
    /// - ESTABLISHED -> CLOSE-WAIT
    /// - FIN-WAIT-1 -> CLOSING
    /// - FIN-WAIT-2 -> TIME-WAIT
    pub fn recv_fin(&mut self) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::RecvFin)?;
        self.state = transition.new_state;
        self.touch();

        // FIN consumes one sequence number in receive space
        if let Some(ref mut recv) = self.recv {
            recv.nxt = recv.nxt + 1;
        }

        let ack = self.recv.as_ref().map(|r| r.nxt);
        let mut result = ConnectionResult::new(transition.action);
        if let Some(ack) = ack {
            result = result.with_ack(ack);
        }
        Ok(result)
    }

    /// Handle receiving a FIN+ACK segment
    pub fn recv_fin_ack(&mut self, ack_num: SeqNum) -> Result<ConnectionResult, ConnectionError> {
        // Process ACK
        if let Some(ref mut send) = self.send {
            send.acknowledge(ack_num);
        }

        let transition = self.state.transition(TcpEvent::RecvFinAck)?;
        self.state = transition.new_state;
        self.touch();

        // FIN consumes one sequence number in receive space
        if let Some(ref mut recv) = self.recv {
            recv.nxt = recv.nxt + 1;
        }

        let ack = self.recv.as_ref().map(|r| r.nxt);
        let mut result = ConnectionResult::new(transition.action);
        if let Some(ack) = ack {
            result = result.with_ack(ack);
        }
        Ok(result)
    }

    /// Handle TIME-WAIT timeout
    pub fn timeout(&mut self) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::Timeout)?;
        self.state = transition.new_state;
        self.touch();

        Ok(ConnectionResult::new(transition.action))
    }

    /// Handle receiving a RST segment
    pub fn recv_rst(&mut self) -> Result<ConnectionResult, ConnectionError> {
        let transition = self.state.transition(TcpEvent::RecvRst)?;
        self.state = transition.new_state;
        self.touch();

        // Clear sequence spaces
        self.send = None;
        self.recv = None;

        Ok(ConnectionResult::new(transition.action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection_id() -> ConnectionId {
        ConnectionId::new(
            Endpoint::new(Ipv4Addr::new(192, 168, 1, 1), 12345),
            Endpoint::new(Ipv4Addr::new(192, 168, 1, 2), 80),
        )
    }

    // === 2.3.1 Tests: Connection Entity Definition ===

    #[test]
    fn test_connection_new() {
        let id = test_connection_id();
        let conn = Connection::new(id);

        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(conn.send_seq().is_none());
        assert!(conn.recv_seq().is_none());
    }

    #[test]
    fn test_endpoint_creation() {
        let ep = Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 8080);
        assert_eq!(ep.addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ep.port, 8080);

        let socket_addr = ep.to_socket_addr();
        assert_eq!(*socket_addr.ip(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(socket_addr.port(), 8080);
    }

    #[test]
    fn test_connection_id_reversed() {
        let id = test_connection_id();
        let reversed = id.reversed();

        assert_eq!(reversed.local, id.remote);
        assert_eq!(reversed.remote, id.local);
    }

    #[test]
    fn test_send_sequence() {
        let iss = SeqNum::new(1000);
        let mut send = SendSequence::new(iss);

        assert_eq!(send.una, iss);
        assert_eq!(send.nxt, iss);
        assert_eq!(send.iss, iss);
        assert_eq!(send.bytes_in_flight(), 0);
        assert!(send.can_send(100));

        send.advance(100);
        assert_eq!(send.nxt, iss + 100);
        assert_eq!(send.bytes_in_flight(), 100);

        send.acknowledge(iss + 50);
        assert_eq!(send.una, iss + 50);
        assert_eq!(send.bytes_in_flight(), 50);
    }

    #[test]
    fn test_recv_sequence() {
        let irs = SeqNum::new(2000);
        let recv = RecvSequence::new(irs);

        assert_eq!(recv.irs, irs);
        assert_eq!(recv.nxt, irs + 1);

        // Test in_window
        assert!(recv.in_window(recv.nxt, 100));
        // irs with len 100 overlaps window (segment ends at irs+99 which includes nxt=irs+1)
        assert!(recv.in_window(irs, 100));
        // Segment completely before window
        assert!(!recv.in_window(irs - 100, 50));
    }

    // === 2.3.2 Tests: Connection Establishment ===

    #[test]
    fn test_active_open() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        let result = conn.active_open(&mut isn_gen).unwrap();

        assert_eq!(conn.state(), ConnectionState::SynSent);
        assert_eq!(result.action, TcpAction::SendSyn);
        assert!(result.seq.is_some());
        assert!(conn.send_seq().is_some());
    }

    #[test]
    fn test_passive_open() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);

        let result = conn.passive_open().unwrap();

        assert_eq!(conn.state(), ConnectionState::Listen);
        assert_eq!(result.action, TcpAction::None);
    }

    #[test]
    fn test_client_handshake() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Active open
        let result = conn.active_open(&mut isn_gen).unwrap();
        assert_eq!(conn.state(), ConnectionState::SynSent);
        let client_iss = result.seq.unwrap();

        // Receive SYN+ACK
        let server_iss = SeqNum::new(5000);
        let result = conn.recv_syn_ack(server_iss, client_iss + 1).unwrap();

        assert_eq!(conn.state(), ConnectionState::Established);
        assert_eq!(result.action, TcpAction::SendAck);
        assert!(conn.recv_seq().is_some());
    }

    #[test]
    fn test_server_handshake() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Passive open
        conn.passive_open().unwrap();
        assert_eq!(conn.state(), ConnectionState::Listen);

        // Receive SYN
        let client_iss = SeqNum::new(1000);
        let result = conn.recv_syn(&mut isn_gen, client_iss).unwrap();

        assert_eq!(conn.state(), ConnectionState::SynReceived);
        assert_eq!(result.action, TcpAction::SendSynAck);
        let server_iss = result.seq.unwrap();

        // Receive ACK
        let result = conn.recv_ack(server_iss + 1).unwrap();

        assert_eq!(conn.state(), ConnectionState::Established);
    }

    // === 2.3.3 Tests: Data Transfer ===

    #[test]
    fn test_send_data() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Establish connection
        conn.active_open(&mut isn_gen).unwrap();
        let client_iss = conn.send_seq().unwrap().iss;
        conn.recv_syn_ack(SeqNum::new(5000), client_iss + 1).unwrap();

        assert_eq!(conn.state(), ConnectionState::Established);

        // Send data
        let result = conn.send_data(100).unwrap();
        assert!(result.seq.is_some());

        let send = conn.send_seq().unwrap();
        assert_eq!(send.bytes_in_flight(), 100);
    }

    #[test]
    fn test_recv_data() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Establish connection (server side)
        conn.passive_open().unwrap();
        let client_iss = SeqNum::new(1000);
        conn.recv_syn(&mut isn_gen, client_iss).unwrap();
        let server_iss = conn.send_seq().unwrap().iss;
        conn.recv_ack(server_iss + 1).unwrap();

        assert_eq!(conn.state(), ConnectionState::Established);

        // Receive data
        let recv_nxt = conn.recv_seq().unwrap().nxt;
        let result = conn.recv_data(recv_nxt, 100, None).unwrap();

        assert_eq!(result.action, TcpAction::SendAck);
        assert_eq!(conn.recv_seq().unwrap().nxt, recv_nxt + 100);
    }

    #[test]
    fn test_send_data_not_established() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);

        let result = conn.send_data(100);
        assert!(matches!(result, Err(ConnectionError::NotEstablished)));
    }

    // === 2.3.4 Tests: Connection Close ===

    #[test]
    fn test_active_close() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Establish connection
        conn.active_open(&mut isn_gen).unwrap();
        let client_iss = conn.send_seq().unwrap().iss;
        conn.recv_syn_ack(SeqNum::new(5000), client_iss + 1).unwrap();

        // Close
        let result = conn.close().unwrap();
        assert_eq!(conn.state(), ConnectionState::FinWait1);
        assert_eq!(result.action, TcpAction::SendFin);
    }

    #[test]
    fn test_passive_close() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Establish connection
        conn.active_open(&mut isn_gen).unwrap();
        let client_iss = conn.send_seq().unwrap().iss;
        conn.recv_syn_ack(SeqNum::new(5000), client_iss + 1).unwrap();

        // Receive FIN
        let result = conn.recv_fin().unwrap();
        assert_eq!(conn.state(), ConnectionState::CloseWait);
        assert_eq!(result.action, TcpAction::SendAck);

        // Close
        let result = conn.close().unwrap();
        assert_eq!(conn.state(), ConnectionState::LastAck);
        assert_eq!(result.action, TcpAction::SendFin);
    }

    #[test]
    fn test_recv_rst() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Establish connection
        conn.active_open(&mut isn_gen).unwrap();
        let client_iss = conn.send_seq().unwrap().iss;
        conn.recv_syn_ack(SeqNum::new(5000), client_iss + 1).unwrap();

        // Receive RST
        let result = conn.recv_rst().unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
        assert!(conn.send_seq().is_none());
        assert!(conn.recv_seq().is_none());
    }

    // === 2.3.5 Tests: Complete Connection Lifecycle ===

    #[test]
    fn test_complete_lifecycle_client() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // 1. CLOSED -> SYN-SENT (active open)
        conn.active_open(&mut isn_gen).unwrap();
        assert_eq!(conn.state(), ConnectionState::SynSent);
        let client_iss = conn.send_seq().unwrap().iss;

        // 2. SYN-SENT -> ESTABLISHED (recv SYN+ACK)
        let server_iss = SeqNum::new(5000);
        conn.recv_syn_ack(server_iss, client_iss + 1).unwrap();
        assert_eq!(conn.state(), ConnectionState::Established);

        // 3. Data transfer
        conn.send_data(100).unwrap();
        let recv_nxt = conn.recv_seq().unwrap().nxt;
        conn.recv_data(recv_nxt, 50, Some(client_iss + 1 + 100)).unwrap();

        // 4. ESTABLISHED -> FIN-WAIT-1 (close)
        conn.close().unwrap();
        assert_eq!(conn.state(), ConnectionState::FinWait1);

        // 5. FIN-WAIT-1 -> FIN-WAIT-2 (recv ACK)
        let fin_seq = conn.send_seq().unwrap().nxt;
        conn.recv_ack(fin_seq).unwrap();
        assert_eq!(conn.state(), ConnectionState::FinWait2);

        // 6. FIN-WAIT-2 -> TIME-WAIT (recv FIN)
        conn.recv_fin().unwrap();
        assert_eq!(conn.state(), ConnectionState::TimeWait);

        // 7. TIME-WAIT -> CLOSED (timeout)
        conn.timeout().unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn test_complete_lifecycle_server() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // 1. CLOSED -> LISTEN (passive open)
        conn.passive_open().unwrap();
        assert_eq!(conn.state(), ConnectionState::Listen);

        // 2. LISTEN -> SYN-RECEIVED (recv SYN)
        let client_iss = SeqNum::new(1000);
        conn.recv_syn(&mut isn_gen, client_iss).unwrap();
        assert_eq!(conn.state(), ConnectionState::SynReceived);
        let server_iss = conn.send_seq().unwrap().iss;

        // 3. SYN-RECEIVED -> ESTABLISHED (recv ACK)
        conn.recv_ack(server_iss + 1).unwrap();
        assert_eq!(conn.state(), ConnectionState::Established);

        // 4. Data transfer
        let recv_nxt = conn.recv_seq().unwrap().nxt;
        conn.recv_data(recv_nxt, 100, None).unwrap();
        conn.send_data(50).unwrap();

        // 5. ESTABLISHED -> CLOSE-WAIT (recv FIN)
        conn.recv_fin().unwrap();
        assert_eq!(conn.state(), ConnectionState::CloseWait);

        // 6. CLOSE-WAIT -> LAST-ACK (close)
        conn.close().unwrap();
        assert_eq!(conn.state(), ConnectionState::LastAck);

        // 7. LAST-ACK -> CLOSED (recv ACK)
        let fin_seq = conn.send_seq().unwrap().nxt;
        conn.recv_ack(fin_seq).unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn test_simultaneous_close() {
        let id = test_connection_id();
        let mut conn = Connection::new(id);
        let mut isn_gen = IsnGenerator::with_secret([0u8; 16]);

        // Establish connection
        conn.active_open(&mut isn_gen).unwrap();
        let client_iss = conn.send_seq().unwrap().iss;
        conn.recv_syn_ack(SeqNum::new(5000), client_iss + 1).unwrap();

        // Both sides close simultaneously
        // Local close
        conn.close().unwrap();
        assert_eq!(conn.state(), ConnectionState::FinWait1);

        // Receive FIN before our FIN is ACKed
        conn.recv_fin().unwrap();
        assert_eq!(conn.state(), ConnectionState::Closing);

        // Receive ACK for our FIN
        let fin_seq = conn.send_seq().unwrap().nxt;
        conn.recv_ack(fin_seq).unwrap();
        assert_eq!(conn.state(), ConnectionState::TimeWait);

        // Timeout
        conn.timeout().unwrap();
        assert_eq!(conn.state(), ConnectionState::Closed);
    }

    #[test]
    fn test_connection_timing() {
        let id = test_connection_id();
        let conn = Connection::new(id);

        // Age and idle time should be very small initially
        assert!(conn.age() < std::time::Duration::from_secs(1));
        assert!(conn.idle_time() < std::time::Duration::from_secs(1));
    }
}
