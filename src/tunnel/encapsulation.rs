//! 数据包封装/解封装服务
//!
//! 负责将原始 IP 数据包封装为 VPN 传输格式，以及反向解封装

use thiserror::Error;

/// 封装协议头
///
/// 格式:
/// - [0-1]   Magic: 0xFD 0xFD
/// - [2]     Version: 0x01
/// - [3]     Flags: 保留
/// - [4-5]   Original Length: 原始 IP 包长度 (big-endian)
/// - [6-7]   Checksum: 头部校验 (big-endian)
/// - [8..]   Encrypted Original IP Packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncapsulationHeader {
    /// 魔数
    pub magic: [u8; 2],
    /// 版本号
    pub version: u8,
    /// 标志位（保留）
    pub flags: u8,
    /// 原始包长度
    pub original_len: u16,
    /// 头部校验和
    pub checksum: u16,
}

impl EncapsulationHeader {
    /// 头部大小
    pub const SIZE: usize = 8;
    /// 魔数
    pub const MAGIC: [u8; 2] = [0xFD, 0xFD];
    /// 当前版本
    pub const VERSION: u8 = 0x01;

    /// 创建新的封装头
    pub fn new(original_len: u16) -> Self {
        let mut header = Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            flags: 0,
            original_len,
            checksum: 0,
        };
        header.checksum = header.compute_checksum();
        header
    }

    /// 从字节解析
    pub fn parse(data: &[u8]) -> Result<Self, EncapsulationError> {
        if data.len() < Self::SIZE {
            return Err(EncapsulationError::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
            });
        }

        let magic = [data[0], data[1]];
        if magic != Self::MAGIC {
            return Err(EncapsulationError::InvalidMagic { magic });
        }

        let version = data[2];
        if version != Self::VERSION {
            return Err(EncapsulationError::UnsupportedVersion { version });
        }

        let flags = data[3];
        let original_len = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        let header = Self {
            magic,
            version,
            flags,
            original_len,
            checksum,
        };

        // 验证校验和
        if header.compute_checksum() != checksum {
            return Err(EncapsulationError::InvalidChecksum);
        }

        Ok(header)
    }

    /// 序列化为字节
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.magic[0];
        bytes[1] = self.magic[1];
        bytes[2] = self.version;
        bytes[3] = self.flags;
        bytes[4..6].copy_from_slice(&self.original_len.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        bytes
    }

    /// 计算头部校验和（不包括 checksum 字段本身）
    fn compute_checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        sum += u16::from_be_bytes(self.magic) as u32;
        sum += ((self.version as u16) << 8 | self.flags as u16) as u32;
        sum += self.original_len as u32;

        // 折叠进位
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}

/// 封装错误
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EncapsulationError {
    #[error("Data too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("Invalid magic number: {magic:02X?}")]
    InvalidMagic { magic: [u8; 2] },

    #[error("Unsupported version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("Invalid header checksum")]
    InvalidChecksum,

    #[error("Payload length mismatch: expected {expected}, got {actual}")]
    PayloadLengthMismatch { expected: usize, actual: usize },

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

/// 封装数据（头部 + payload）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapsulatedData {
    /// 封装头
    pub header: EncapsulationHeader,
    /// 加密后的原始 IP 包
    pub encrypted_payload: Vec<u8>,
}

impl EncapsulatedData {
    /// 创建封装数据
    pub fn new(original_len: u16, encrypted_payload: Vec<u8>) -> Self {
        Self {
            header: EncapsulationHeader::new(original_len),
            encrypted_payload,
        }
    }

    /// 从字节解析
    pub fn parse(data: &[u8]) -> Result<Self, EncapsulationError> {
        let header = EncapsulationHeader::parse(data)?;
        let encrypted_payload = data[EncapsulationHeader::SIZE..].to_vec();

        Ok(Self {
            header,
            encrypted_payload,
        })
    }

    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(EncapsulationHeader::SIZE + self.encrypted_payload.len());
        result.extend_from_slice(&self.header.to_bytes());
        result.extend_from_slice(&self.encrypted_payload);
        result
    }

    /// 获取原始包长度
    pub fn original_len(&self) -> usize {
        self.header.original_len as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encapsulation_header_roundtrip() {
        let header = EncapsulationHeader::new(1500);

        let bytes = header.to_bytes();
        let parsed = EncapsulationHeader::parse(&bytes).expect("Failed to parse header");

        assert_eq!(parsed.magic, EncapsulationHeader::MAGIC);
        assert_eq!(parsed.version, EncapsulationHeader::VERSION);
        assert_eq!(parsed.original_len, 1500);
        assert_eq!(parsed.checksum, header.checksum);
    }

    #[test]
    fn test_encapsulation_header_invalid_magic() {
        let mut bytes = EncapsulationHeader::new(100).to_bytes();
        bytes[0] = 0x00; // 破坏魔数

        let result = EncapsulationHeader::parse(&bytes);
        assert!(matches!(result, Err(EncapsulationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_encapsulation_header_invalid_version() {
        let mut bytes = EncapsulationHeader::new(100).to_bytes();
        bytes[2] = 0xFF; // 无效版本

        let result = EncapsulationHeader::parse(&bytes);
        assert!(matches!(result, Err(EncapsulationError::UnsupportedVersion { .. })));
    }

    #[test]
    fn test_encapsulation_header_invalid_checksum() {
        let mut bytes = EncapsulationHeader::new(100).to_bytes();
        bytes[6] ^= 0xFF; // 破坏校验和

        let result = EncapsulationHeader::parse(&bytes);
        assert!(matches!(result, Err(EncapsulationError::InvalidChecksum)));
    }

    #[test]
    fn test_encapsulated_data_roundtrip() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let data = EncapsulatedData::new(100, payload.clone());

        let bytes = data.to_bytes();
        let parsed = EncapsulatedData::parse(&bytes).expect("Failed to parse encapsulated data");

        assert_eq!(parsed.header.original_len, 100);
        assert_eq!(parsed.encrypted_payload, payload);
    }

    #[test]
    fn test_encapsulated_data_empty_payload() {
        let data = EncapsulatedData::new(0, Vec::new());

        let bytes = data.to_bytes();
        let parsed = EncapsulatedData::parse(&bytes).expect("Failed to parse encapsulated data");

        assert_eq!(parsed.header.original_len, 0);
        assert!(parsed.encrypted_payload.is_empty());
    }

    #[test]
    fn test_encapsulated_data_large_payload() {
        let payload = vec![0xAB; 1400];
        let data = EncapsulatedData::new(1400, payload.clone());

        let bytes = data.to_bytes();
        let parsed = EncapsulatedData::parse(&bytes).expect("Failed to parse encapsulated data");

        assert_eq!(parsed.header.original_len, 1400);
        assert_eq!(parsed.encrypted_payload.len(), 1400);
    }
}
