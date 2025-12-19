//! TCP Connection State Machine
//!
//! Implements the TCP state machine as a pure function with no side effects.
//! Based on RFC 793 TCP state diagram.

use std::fmt;

/// TCP connection states as defined in RFC 793
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// No connection state at all
    Closed,
    /// Waiting for a matching connection request after having sent a connection request
    SynSent,
    /// Waiting for a confirming connection request acknowledgment after having both
    /// received and sent a connection request
    SynReceived,
    /// Open connection, data received can be delivered to the user
    Established,
    /// Waiting for a connection termination request from the remote TCP,
    /// or an acknowledgment of the connection termination request previously sent
    FinWait1,
    /// Waiting for a connection termination request from the remote TCP
    FinWait2,
    /// Waiting for a connection termination request from the local user
    CloseWait,
    /// Waiting for a connection termination request acknowledgment from the remote TCP
    Closing,
    /// Waiting for an acknowledgment of the connection termination request previously
    /// sent to the remote TCP
    LastAck,
    /// Waiting for enough time to pass to be sure the remote TCP received the
    /// acknowledgment of its connection termination request
    TimeWait,
    /// Waiting for a connection request from any remote TCP and port (server listening)
    Listen,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Closed
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Closed => write!(f, "CLOSED"),
            ConnectionState::SynSent => write!(f, "SYN-SENT"),
            ConnectionState::SynReceived => write!(f, "SYN-RECEIVED"),
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::FinWait1 => write!(f, "FIN-WAIT-1"),
            ConnectionState::FinWait2 => write!(f, "FIN-WAIT-2"),
            ConnectionState::CloseWait => write!(f, "CLOSE-WAIT"),
            ConnectionState::Closing => write!(f, "CLOSING"),
            ConnectionState::LastAck => write!(f, "LAST-ACK"),
            ConnectionState::TimeWait => write!(f, "TIME-WAIT"),
            ConnectionState::Listen => write!(f, "LISTEN"),
        }
    }
}

/// Events that can trigger state transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpEvent {
    // Application events (from local user)
    /// Application initiates passive open (server)
    PassiveOpen,
    /// Application initiates active open (client)
    ActiveOpen,
    /// Application sends data
    Send,
    /// Application initiates close
    Close,
    /// Timeout expired (e.g., TIME_WAIT timeout)
    Timeout,

    // Network events (from remote TCP)
    /// Received SYN segment
    RecvSyn,
    /// Received SYN+ACK segment
    RecvSynAck,
    /// Received ACK segment
    RecvAck,
    /// Received FIN segment
    RecvFin,
    /// Received FIN+ACK segment
    RecvFinAck,
    /// Received RST segment
    RecvRst,
}

impl fmt::Display for TcpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpEvent::PassiveOpen => write!(f, "passive OPEN"),
            TcpEvent::ActiveOpen => write!(f, "active OPEN"),
            TcpEvent::Send => write!(f, "SEND"),
            TcpEvent::Close => write!(f, "CLOSE"),
            TcpEvent::Timeout => write!(f, "TIMEOUT"),
            TcpEvent::RecvSyn => write!(f, "rcv SYN"),
            TcpEvent::RecvSynAck => write!(f, "rcv SYN,ACK"),
            TcpEvent::RecvAck => write!(f, "rcv ACK"),
            TcpEvent::RecvFin => write!(f, "rcv FIN"),
            TcpEvent::RecvFinAck => write!(f, "rcv FIN,ACK"),
            TcpEvent::RecvRst => write!(f, "rcv RST"),
        }
    }
}

/// Actions to be taken as a result of a state transition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAction {
    /// Send SYN segment
    SendSyn,
    /// Send SYN+ACK segment
    SendSynAck,
    /// Send ACK segment
    SendAck,
    /// Send FIN segment
    SendFin,
    /// Send FIN+ACK segment
    SendFinAck,
    /// Send RST segment
    SendRst,
    /// Delete the TCB (Transmission Control Block)
    DeleteTcb,
    /// No action required
    None,
}

/// Error type for invalid state transitions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransitionError {
    pub current_state: ConnectionState,
    pub event: TcpEvent,
    pub message: String,
}

impl fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid state transition: {} + {} -> {}",
            self.current_state, self.event, self.message
        )
    }
}

impl std::error::Error for StateTransitionError {}

/// Result of a successful state transition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    pub new_state: ConnectionState,
    pub action: TcpAction,
}

impl ConnectionState {
    /// Attempt to transition to a new state based on an event.
    /// This is a pure function with no side effects.
    ///
    /// Returns the new state and any action that should be taken,
    /// or an error if the transition is invalid.
    pub fn transition(self, event: TcpEvent) -> Result<StateTransition, StateTransitionError> {
        use ConnectionState::*;
        use TcpAction::*;
        use TcpEvent::*;

        let result = match (self, event) {
            // === CLOSED state transitions ===
            (Closed, PassiveOpen) => StateTransition {
                new_state: Listen,
                action: None,
            },
            (Closed, ActiveOpen) => StateTransition {
                new_state: SynSent,
                action: SendSyn,
            },

            // === LISTEN state transitions ===
            (Listen, RecvSyn) => StateTransition {
                new_state: SynReceived,
                action: SendSynAck,
            },
            (Listen, Close) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },
            // Active open from Listen (simultaneous open scenario)
            (Listen, Send) | (Listen, ActiveOpen) => StateTransition {
                new_state: SynSent,
                action: SendSyn,
            },

            // === SYN-SENT state transitions ===
            (SynSent, RecvSynAck) => StateTransition {
                new_state: Established,
                action: SendAck,
            },
            // Simultaneous open: receive SYN without ACK
            (SynSent, RecvSyn) => StateTransition {
                new_state: SynReceived,
                action: SendSynAck,
            },
            (SynSent, Close) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },
            (SynSent, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // === SYN-RECEIVED state transitions ===
            (SynReceived, RecvAck) => StateTransition {
                new_state: Established,
                action: None,
            },
            (SynReceived, Close) => StateTransition {
                new_state: FinWait1,
                action: SendFin,
            },
            (SynReceived, RecvRst) => StateTransition {
                new_state: Listen,
                action: None,
            },

            // === ESTABLISHED state transitions ===
            (Established, Close) => StateTransition {
                new_state: FinWait1,
                action: SendFin,
            },
            (Established, RecvFin) => StateTransition {
                new_state: CloseWait,
                action: SendAck,
            },
            (Established, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },
            // Data transfer in ESTABLISHED (no state change)
            (Established, Send) | (Established, RecvAck) => StateTransition {
                new_state: Established,
                action: None,
            },

            // === FIN-WAIT-1 state transitions ===
            (FinWait1, RecvAck) => StateTransition {
                new_state: FinWait2,
                action: None,
            },
            (FinWait1, RecvFin) => StateTransition {
                new_state: Closing,
                action: SendAck,
            },
            // Simultaneous close: receive FIN+ACK
            (FinWait1, RecvFinAck) => StateTransition {
                new_state: TimeWait,
                action: SendAck,
            },
            (FinWait1, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // === FIN-WAIT-2 state transitions ===
            (FinWait2, RecvFin) => StateTransition {
                new_state: TimeWait,
                action: SendAck,
            },
            (FinWait2, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // === CLOSE-WAIT state transitions ===
            (CloseWait, Close) => StateTransition {
                new_state: LastAck,
                action: SendFin,
            },
            (CloseWait, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // === CLOSING state transitions ===
            (Closing, RecvAck) => StateTransition {
                new_state: TimeWait,
                action: None,
            },
            (Closing, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // === LAST-ACK state transitions ===
            (LastAck, RecvAck) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },
            (LastAck, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // === TIME-WAIT state transitions ===
            (TimeWait, Timeout) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },
            (TimeWait, RecvRst) => StateTransition {
                new_state: Closed,
                action: DeleteTcb,
            },

            // Invalid transitions
            (state, event) => {
                return Err(StateTransitionError {
                    current_state: state,
                    event,
                    message: format!("No valid transition from {} on {}", state, event),
                });
            }
        };

        Ok(result)
    }

    /// Check if the connection is in a state where it can send data
    pub fn can_send(&self) -> bool {
        matches!(self, ConnectionState::Established | ConnectionState::CloseWait)
    }

    /// Check if the connection is in a state where it can receive data
    pub fn can_receive(&self) -> bool {
        matches!(
            self,
            ConnectionState::Established
                | ConnectionState::FinWait1
                | ConnectionState::FinWait2
        )
    }

    /// Check if the connection is fully closed
    pub fn is_closed(&self) -> bool {
        matches!(self, ConnectionState::Closed)
    }

    /// Check if the connection is established
    pub fn is_established(&self) -> bool {
        matches!(self, ConnectionState::Established)
    }

    /// Check if the connection is in a closing state
    pub fn is_closing(&self) -> bool {
        matches!(
            self,
            ConnectionState::FinWait1
                | ConnectionState::FinWait2
                | ConnectionState::Closing
                | ConnectionState::TimeWait
                | ConnectionState::CloseWait
                | ConnectionState::LastAck
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === 2.1.3 单元测试: 正常握手流程 ===

    #[test]
    fn test_client_active_open_handshake() {
        // Client: CLOSED -> SYN-SENT -> ESTABLISHED
        let state = ConnectionState::Closed;

        // Step 1: Active open, send SYN
        let result = state.transition(TcpEvent::ActiveOpen).unwrap();
        assert_eq!(result.new_state, ConnectionState::SynSent);
        assert_eq!(result.action, TcpAction::SendSyn);

        // Step 2: Receive SYN+ACK, send ACK
        let result = result.new_state.transition(TcpEvent::RecvSynAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::Established);
        assert_eq!(result.action, TcpAction::SendAck);
    }

    #[test]
    fn test_server_passive_open_handshake() {
        // Server: CLOSED -> LISTEN -> SYN-RECEIVED -> ESTABLISHED
        let state = ConnectionState::Closed;

        // Step 1: Passive open
        let result = state.transition(TcpEvent::PassiveOpen).unwrap();
        assert_eq!(result.new_state, ConnectionState::Listen);
        assert_eq!(result.action, TcpAction::None);

        // Step 2: Receive SYN, send SYN+ACK
        let result = result.new_state.transition(TcpEvent::RecvSyn).unwrap();
        assert_eq!(result.new_state, ConnectionState::SynReceived);
        assert_eq!(result.action, TcpAction::SendSynAck);

        // Step 3: Receive ACK
        let result = result.new_state.transition(TcpEvent::RecvAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::Established);
        assert_eq!(result.action, TcpAction::None);
    }

    #[test]
    fn test_simultaneous_open() {
        // Both sides send SYN at the same time
        // CLOSED -> SYN-SENT -> SYN-RECEIVED -> ESTABLISHED
        let state = ConnectionState::Closed;

        // Active open
        let result = state.transition(TcpEvent::ActiveOpen).unwrap();
        assert_eq!(result.new_state, ConnectionState::SynSent);

        // Receive SYN (without ACK) - simultaneous open
        let result = result.new_state.transition(TcpEvent::RecvSyn).unwrap();
        assert_eq!(result.new_state, ConnectionState::SynReceived);
        assert_eq!(result.action, TcpAction::SendSynAck);

        // Receive ACK
        let result = result.new_state.transition(TcpEvent::RecvAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::Established);
    }

    #[test]
    fn test_normal_close_client_initiated() {
        // Client initiates close
        // ESTABLISHED -> FIN-WAIT-1 -> FIN-WAIT-2 -> TIME-WAIT -> CLOSED
        let state = ConnectionState::Established;

        // Close
        let result = state.transition(TcpEvent::Close).unwrap();
        assert_eq!(result.new_state, ConnectionState::FinWait1);
        assert_eq!(result.action, TcpAction::SendFin);

        // Receive ACK
        let result = result.new_state.transition(TcpEvent::RecvAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::FinWait2);

        // Receive FIN
        let result = result.new_state.transition(TcpEvent::RecvFin).unwrap();
        assert_eq!(result.new_state, ConnectionState::TimeWait);
        assert_eq!(result.action, TcpAction::SendAck);

        // Timeout
        let result = result.new_state.transition(TcpEvent::Timeout).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
    }

    #[test]
    fn test_normal_close_server_initiated() {
        // Server receives FIN first
        // ESTABLISHED -> CLOSE-WAIT -> LAST-ACK -> CLOSED
        let state = ConnectionState::Established;

        // Receive FIN
        let result = state.transition(TcpEvent::RecvFin).unwrap();
        assert_eq!(result.new_state, ConnectionState::CloseWait);
        assert_eq!(result.action, TcpAction::SendAck);

        // Application close
        let result = result.new_state.transition(TcpEvent::Close).unwrap();
        assert_eq!(result.new_state, ConnectionState::LastAck);
        assert_eq!(result.action, TcpAction::SendFin);

        // Receive ACK
        let result = result.new_state.transition(TcpEvent::RecvAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
    }

    #[test]
    fn test_simultaneous_close() {
        // Both sides close at the same time
        // ESTABLISHED -> FIN-WAIT-1 -> CLOSING -> TIME-WAIT -> CLOSED
        let state = ConnectionState::Established;

        // Close
        let result = state.transition(TcpEvent::Close).unwrap();
        assert_eq!(result.new_state, ConnectionState::FinWait1);

        // Receive FIN (before our FIN is ACKed)
        let result = result.new_state.transition(TcpEvent::RecvFin).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closing);
        assert_eq!(result.action, TcpAction::SendAck);

        // Receive ACK
        let result = result.new_state.transition(TcpEvent::RecvAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::TimeWait);

        // Timeout
        let result = result.new_state.transition(TcpEvent::Timeout).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
    }

    #[test]
    fn test_fin_wait_1_recv_fin_ack() {
        // Receive FIN+ACK in FIN-WAIT-1 (fast path)
        let state = ConnectionState::FinWait1;

        let result = state.transition(TcpEvent::RecvFinAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::TimeWait);
        assert_eq!(result.action, TcpAction::SendAck);
    }

    // === 2.1.4 单元测试: 异常状态处理 ===

    #[test]
    fn test_rst_in_established() {
        let state = ConnectionState::Established;

        let result = state.transition(TcpEvent::RecvRst).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
    }

    #[test]
    fn test_rst_in_syn_sent() {
        let state = ConnectionState::SynSent;

        let result = state.transition(TcpEvent::RecvRst).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
    }

    #[test]
    fn test_rst_in_syn_received_returns_to_listen() {
        // RST in SYN-RECEIVED returns to LISTEN (for server)
        let state = ConnectionState::SynReceived;

        let result = state.transition(TcpEvent::RecvRst).unwrap();
        assert_eq!(result.new_state, ConnectionState::Listen);
    }

    #[test]
    fn test_rst_in_closing_states() {
        let closing_states = [
            ConnectionState::FinWait1,
            ConnectionState::FinWait2,
            ConnectionState::CloseWait,
            ConnectionState::Closing,
            ConnectionState::LastAck,
            ConnectionState::TimeWait,
        ];

        for state in closing_states {
            let result = state.transition(TcpEvent::RecvRst).unwrap();
            assert_eq!(
                result.new_state,
                ConnectionState::Closed,
                "RST in {} should go to CLOSED",
                state
            );
            assert_eq!(result.action, TcpAction::DeleteTcb);
        }
    }

    #[test]
    fn test_invalid_transition_closed_recv_ack() {
        let state = ConnectionState::Closed;

        let result = state.transition(TcpEvent::RecvAck);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.current_state, ConnectionState::Closed);
        assert_eq!(err.event, TcpEvent::RecvAck);
    }

    #[test]
    fn test_invalid_transition_listen_recv_ack() {
        let state = ConnectionState::Listen;

        let result = state.transition(TcpEvent::RecvAck);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_time_wait_close() {
        let state = ConnectionState::TimeWait;

        let result = state.transition(TcpEvent::Close);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_fin_wait2_close() {
        let state = ConnectionState::FinWait2;

        let result = state.transition(TcpEvent::Close);
        assert!(result.is_err());
    }

    #[test]
    fn test_close_from_listen() {
        let state = ConnectionState::Listen;

        let result = state.transition(TcpEvent::Close).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
    }

    #[test]
    fn test_close_from_syn_sent() {
        let state = ConnectionState::SynSent;

        let result = state.transition(TcpEvent::Close).unwrap();
        assert_eq!(result.new_state, ConnectionState::Closed);
        assert_eq!(result.action, TcpAction::DeleteTcb);
    }

    #[test]
    fn test_close_from_syn_received() {
        let state = ConnectionState::SynReceived;

        let result = state.transition(TcpEvent::Close).unwrap();
        assert_eq!(result.new_state, ConnectionState::FinWait1);
        assert_eq!(result.action, TcpAction::SendFin);
    }

    // === Helper method tests ===

    #[test]
    fn test_can_send() {
        assert!(ConnectionState::Established.can_send());
        assert!(ConnectionState::CloseWait.can_send());
        assert!(!ConnectionState::Closed.can_send());
        assert!(!ConnectionState::Listen.can_send());
        assert!(!ConnectionState::FinWait1.can_send());
    }

    #[test]
    fn test_can_receive() {
        assert!(ConnectionState::Established.can_receive());
        assert!(ConnectionState::FinWait1.can_receive());
        assert!(ConnectionState::FinWait2.can_receive());
        assert!(!ConnectionState::Closed.can_receive());
        assert!(!ConnectionState::CloseWait.can_receive());
    }

    #[test]
    fn test_is_closed() {
        assert!(ConnectionState::Closed.is_closed());
        assert!(!ConnectionState::Established.is_closed());
    }

    #[test]
    fn test_is_established() {
        assert!(ConnectionState::Established.is_established());
        assert!(!ConnectionState::Closed.is_established());
    }

    #[test]
    fn test_is_closing() {
        assert!(ConnectionState::FinWait1.is_closing());
        assert!(ConnectionState::FinWait2.is_closing());
        assert!(ConnectionState::Closing.is_closing());
        assert!(ConnectionState::TimeWait.is_closing());
        assert!(ConnectionState::CloseWait.is_closing());
        assert!(ConnectionState::LastAck.is_closing());
        assert!(!ConnectionState::Established.is_closing());
        assert!(!ConnectionState::Closed.is_closing());
    }

    #[test]
    fn test_default_state() {
        let state: ConnectionState = Default::default();
        assert_eq!(state, ConnectionState::Closed);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ConnectionState::Closed), "CLOSED");
        assert_eq!(format!("{}", ConnectionState::SynSent), "SYN-SENT");
        assert_eq!(format!("{}", ConnectionState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", TcpEvent::ActiveOpen), "active OPEN");
        assert_eq!(format!("{}", TcpEvent::RecvSynAck), "rcv SYN,ACK");
    }

    #[test]
    fn test_data_transfer_in_established() {
        let state = ConnectionState::Established;

        // Send data - stays in ESTABLISHED
        let result = state.transition(TcpEvent::Send).unwrap();
        assert_eq!(result.new_state, ConnectionState::Established);

        // Receive ACK - stays in ESTABLISHED
        let result = state.transition(TcpEvent::RecvAck).unwrap();
        assert_eq!(result.new_state, ConnectionState::Established);
    }
}
