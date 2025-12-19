use thiserror::Error;

/// 数据包处理错误
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PacketError {
    #[error("Packet too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("Not a TCP packet: protocol {protocol}")]
    NotTcp { protocol: u8 },

    #[error("Invalid IP version: {version}")]
    InvalidIpVersion { version: u8 },

    #[error("Invalid IP header length: {ihl}")]
    InvalidIpHeaderLength { ihl: u8 },

    #[error("Invalid TCP header length: {data_offset}")]
    InvalidTcpHeaderLength { data_offset: u8 },

    #[error("Invalid IP checksum")]
    InvalidIpChecksum,

    #[error("Invalid TCP checksum")]
    InvalidTcpChecksum,
}
