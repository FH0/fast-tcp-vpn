//! 数据包封装/解封装服务
//!
//! 负责将原始 IP 数据包封装为 VPN 传输格式，以及反向解封装

use crate::infrastructure::crypto::{Encryptor, NONCE_LEN};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// 数据包封装服务
///
/// 负责将原始 IP 数据包封装为 VPN 传输格式，以及反向解封装
/// 封装流程：原始 IP 包 -> 加密 -> 添加封装头 -> 输出
/// 解封装流程：输入 -> 解析封装头 -> 解密 -> 原始 IP 包
pub struct Encapsulator<E: Encryptor> {
    /// 加密器
    encryptor: E,
    /// Nonce 计数器（用于生成唯一 nonce）
    nonce_counter: AtomicU64,
}

impl<E: Encryptor> Encapsulator<E> {
    /// 创建新的封装服务
    pub fn new(encryptor: E) -> Self {
        Self {
            encryptor,
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// 封装原始 IP 包
    ///
    /// # Arguments
    /// * `raw_ip_packet` - 原始 IP 数据包字节
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 封装后的数据（封装头 + 加密的原始 IP 包）
    /// * `Err(EncapsulationError)` - 封装失败
    pub fn encapsulate(&self, raw_ip_packet: &[u8]) -> Result<Vec<u8>, EncapsulationError> {
        // 验证输入
        if raw_ip_packet.is_empty() {
            return Err(EncapsulationError::TooShort {
                expected: 1,
                actual: 0,
            });
        }

        // 生成 nonce
        let nonce = self.generate_nonce();

        // 加密原始 IP 包
        let encrypted = self.encryptor.encrypt(&nonce, raw_ip_packet)
            .map_err(|e| EncapsulationError::EncryptionError(e.to_string()))?;

        // 创建封装数据
        let encapsulated = EncapsulatedData::new(raw_ip_packet.len() as u16, encrypted);

        // 构建最终输出：nonce + 封装数据
        let mut result = Vec::with_capacity(NONCE_LEN + EncapsulationHeader::SIZE + encapsulated.encrypted_payload.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encapsulated.to_bytes());

        Ok(result)
    }

    /// 解封装
    ///
    /// # Arguments
    /// * `encapsulated_data` - 封装后的数据（nonce + 封装头 + 加密的原始 IP 包）
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 原始 IP 包字节
    /// * `Err(EncapsulationError)` - 解封装失败
    pub fn decapsulate(&self, encapsulated_data: &[u8]) -> Result<Vec<u8>, EncapsulationError> {
        // 验证最小长度：nonce + 封装头
        let min_len = NONCE_LEN + EncapsulationHeader::SIZE;
        if encapsulated_data.len() < min_len {
            return Err(EncapsulationError::TooShort {
                expected: min_len,
                actual: encapsulated_data.len(),
            });
        }

        // 提取 nonce
        let nonce = &encapsulated_data[..NONCE_LEN];

        // 解析封装数据
        let encapsulated = EncapsulatedData::parse(&encapsulated_data[NONCE_LEN..])?;

        // 解密
        let decrypted = self.encryptor.decrypt(nonce, &encapsulated.encrypted_payload)
            .map_err(|e| EncapsulationError::DecryptionError(e.to_string()))?;

        // 验证解密后的长度
        let expected_len = encapsulated.original_len();
        if decrypted.len() != expected_len {
            return Err(EncapsulationError::PayloadLengthMismatch {
                expected: expected_len,
                actual: decrypted.len(),
            });
        }

        Ok(decrypted)
    }

    /// 生成唯一的 nonce
    fn generate_nonce(&self) -> [u8; NONCE_LEN] {
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0u8; NONCE_LEN];
        // 使用计数器填充 nonce 的低 8 字节
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

impl<E: Encryptor> std::fmt::Debug for Encapsulator<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encapsulator")
            .field("nonce_counter", &self.nonce_counter.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::crypto::{ChaCha20Poly1305, NoopEncryptor, KEY_LEN};

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

    // ==================== Encapsulator 测试 ====================

    #[test]
    fn test_encapsulator_roundtrip_with_noop() {
        let encryptor = NoopEncryptor::new();
        let encapsulator = Encapsulator::new(encryptor);

        // 模拟一个简单的 IP 包
        let original_ip_packet = vec![
            0x45, 0x00, // Version=4, IHL=5
            0x00, 0x28, // Total length = 40
            0x12, 0x34, // Identification
            0x40, 0x00, // Flags=DF
            0x40, 0x06, // TTL=64, Protocol=TCP
            0x00, 0x00, // Checksum
            0xC0, 0xA8, 0x01, 0x01, // Src: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02, // Dst: 192.168.1.2
            // TCP header (20 bytes)
            0x00, 0x50, 0x01, 0xBB, // Ports
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, 0x02, 0xFF, 0xFF, // Flags
            0x00, 0x00, 0x00, 0x00, // Checksum + Urgent
        ];

        // 封装
        let encapsulated = encapsulator.encapsulate(&original_ip_packet)
            .expect("Failed to encapsulate");

        // 解封装
        let decapsulated = encapsulator.decapsulate(&encapsulated)
            .expect("Failed to decapsulate");

        assert_eq!(decapsulated, original_ip_packet);
    }

    #[test]
    fn test_encapsulator_roundtrip_with_chacha20() {
        let key = [0x42u8; KEY_LEN];
        let encryptor = ChaCha20Poly1305::new(&key).expect("Failed to create encryptor");
        let encapsulator = Encapsulator::new(encryptor);

        // 模拟 UDP 包
        let original_ip_packet = vec![
            0x45, 0x00, // Version=4, IHL=5
            0x00, 0x1C, // Total length = 28
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags
            0x40, 0x11, // TTL=64, Protocol=UDP
            0x00, 0x00, // Checksum
            0x0A, 0x00, 0x00, 0x01, // Src: 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // Dst: 10.0.0.2
            // UDP header (8 bytes)
            0x30, 0x39, 0x00, 0x50, // Ports
            0x00, 0x08, 0x00, 0x00, // Length + Checksum
        ];

        // 封装
        let encapsulated = encapsulator.encapsulate(&original_ip_packet)
            .expect("Failed to encapsulate");

        // 验证加密后的数据与原始数据不同
        assert_ne!(&encapsulated[NONCE_LEN + EncapsulationHeader::SIZE..], &original_ip_packet[..]);

        // 解封装
        let decapsulated = encapsulator.decapsulate(&encapsulated)
            .expect("Failed to decapsulate");

        assert_eq!(decapsulated, original_ip_packet);
    }

    #[test]
    fn test_encapsulator_roundtrip_icmp() {
        let key = [0x55u8; KEY_LEN];
        let encryptor = ChaCha20Poly1305::new(&key).expect("Failed to create encryptor");
        let encapsulator = Encapsulator::new(encryptor);

        // 模拟 ICMP Echo Request
        let original_ip_packet = vec![
            0x45, 0x00, // Version=4, IHL=5
            0x00, 0x1C, // Total length = 28
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags
            0x40, 0x01, // TTL=64, Protocol=ICMP
            0x00, 0x00, // Checksum
            0x0A, 0x00, 0x00, 0x01, // Src: 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // Dst: 10.0.0.2
            // ICMP Echo Request (8 bytes)
            0x08, 0x00, // Type=8, Code=0
            0x00, 0x00, // Checksum
            0x00, 0x01, // Identifier
            0x00, 0x01, // Sequence
        ];

        let encapsulated = encapsulator.encapsulate(&original_ip_packet)
            .expect("Failed to encapsulate");
        let decapsulated = encapsulator.decapsulate(&encapsulated)
            .expect("Failed to decapsulate");

        assert_eq!(decapsulated, original_ip_packet);
    }

    #[test]
    fn test_encapsulator_multiple_packets() {
        let key = [0x77u8; KEY_LEN];
        let encryptor = ChaCha20Poly1305::new(&key).expect("Failed to create encryptor");
        let encapsulator = Encapsulator::new(encryptor);

        // 发送多个包，验证 nonce 递增
        for i in 0..10 {
            let mut packet = vec![0x45, 0x00, 0x00, 0x14]; // Minimal IP header
            packet.extend_from_slice(&[0u8; 16]); // Rest of IP header
            packet[3] = i as u8; // 修改包内容

            let encapsulated = encapsulator.encapsulate(&packet)
                .expect("Failed to encapsulate");
            let decapsulated = encapsulator.decapsulate(&encapsulated)
                .expect("Failed to decapsulate");

            assert_eq!(decapsulated, packet);
        }
    }

    #[test]
    fn test_encapsulator_empty_packet_error() {
        let encryptor = NoopEncryptor::new();
        let encapsulator = Encapsulator::new(encryptor);

        let result = encapsulator.encapsulate(&[]);
        assert!(matches!(result, Err(EncapsulationError::TooShort { .. })));
    }

    #[test]
    fn test_encapsulator_decapsulate_too_short() {
        let encryptor = NoopEncryptor::new();
        let encapsulator = Encapsulator::new(encryptor);

        // 数据太短（小于 nonce + header）
        let short_data = vec![0u8; 10];
        let result = encapsulator.decapsulate(&short_data);
        assert!(matches!(result, Err(EncapsulationError::TooShort { .. })));
    }

    #[test]
    fn test_encapsulator_decapsulate_invalid_magic() {
        let encryptor = NoopEncryptor::new();
        let encapsulator = Encapsulator::new(encryptor);

        // 构造有效长度但无效魔数的数据
        let mut invalid_data = vec![0u8; NONCE_LEN + EncapsulationHeader::SIZE + 20];
        // 魔数位置在 nonce 之后
        invalid_data[NONCE_LEN] = 0x00;
        invalid_data[NONCE_LEN + 1] = 0x00;

        let result = encapsulator.decapsulate(&invalid_data);
        assert!(matches!(result, Err(EncapsulationError::InvalidMagic { .. })));
    }

    #[test]
    fn test_encapsulator_large_packet() {
        let key = [0x99u8; KEY_LEN];
        let encryptor = ChaCha20Poly1305::new(&key).expect("Failed to create encryptor");
        let encapsulator = Encapsulator::new(encryptor);

        // 模拟大包（接近 MTU）
        let mut large_packet = vec![0x45, 0x00];
        large_packet.extend_from_slice(&1400u16.to_be_bytes()); // Total length
        large_packet.extend(vec![0xAB; 1396]); // 填充到 1400 字节

        let encapsulated = encapsulator.encapsulate(&large_packet)
            .expect("Failed to encapsulate");
        let decapsulated = encapsulator.decapsulate(&encapsulated)
            .expect("Failed to decapsulate");

        assert_eq!(decapsulated, large_packet);
    }
}
