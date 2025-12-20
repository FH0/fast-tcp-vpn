use std::io;
use thiserror::Error;

/// Socket 操作错误
#[derive(Debug, Error)]
pub enum SocketError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Failed to send packet: {reason}")]
    SendFailed { reason: String },

    #[error("Failed to receive packet: {reason}")]
    ReceiveFailed { reason: String },

    #[error("Permission denied: raw sockets require root/admin privileges")]
    PermissionDenied,

    #[error("Invalid packet data")]
    InvalidPacket,

    #[error("Timeout")]
    Timeout,

    #[error("iptables error: {0}")]
    IptablesError(String),
}
