use std::io;
use thiserror::Error;

/// TUN 设备操作错误
#[derive(Debug, Error)]
pub enum TunError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Failed to create TUN device: {reason}")]
    CreateFailed { reason: String },

    #[error("Failed to configure TUN device: {reason}")]
    ConfigFailed { reason: String },

    #[error("Failed to read from TUN device: {reason}")]
    ReadFailed { reason: String },

    #[error("Failed to write to TUN device: {reason}")]
    WriteFailed { reason: String },

    #[error("TUN device not initialized")]
    NotInitialized,

    #[error("Permission denied: TUN device requires root/admin privileges")]
    PermissionDenied,

    #[error("Invalid IP packet")]
    InvalidPacket,

    #[error("Timeout")]
    Timeout,

    #[error("Device not found: {name}")]
    DeviceNotFound { name: String },

    #[error("Platform not supported")]
    PlatformNotSupported,
}
