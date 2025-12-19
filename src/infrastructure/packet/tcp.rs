use super::PacketError;
use std::ops::{BitAnd, BitOr, BitOrAssign};

/// TCP 标志位
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    /// 创建空标志
    pub const fn empty() -> Self {
        TcpFlags(0)
    }

    /// 从原始值创建
    pub const fn from_bits(bits: u8) -> Self {
        TcpFlags(bits)
    }

    /// 获取原始值
    pub const fn bits(&self) -> u8 {
        self.0
    }

    /// 检查是否包含指定标志
    pub const fn contains(&self, other: TcpFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    /// 检查是否为空
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        TcpFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for TcpFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        TcpFlags(self.0 & rhs.0)
    }
}

/// TCP 头部
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 序列号
    pub seq: u32,
    /// 确认号
    pub ack: u32,
    /// 数据偏移 (头部长度，以 4 字节为单位)
    pub data_offset: u8,
    /// 保留位
    pub reserved: u8,
    /// 标志位
    pub flags: TcpFlags,
    /// 窗口大小
    pub window: u16,
    /// 校验和
    pub checksum: u16,
    /// 紧急指针
    pub urgent_ptr: u16,
    /// 选项 (可选)
    pub options: Vec<u8>,
}

impl TcpHeader {
    /// 最小 TCP 头部长度 (无选项)
    pub const MIN_LEN: usize = 20;

    /// 创建新的 TCP 头部
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            data_offset: 5, // 20 bytes / 4
            reserved: 0,
            flags: TcpFlags::empty(),
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }
    }

    /// 从字节解析 TCP 头部
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < Self::MIN_LEN {
            return Err(PacketError::TooShort {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = data[12] >> 4;
        let reserved = (data[12] >> 1) & 0x07;
        let flags = TcpFlags::from_bits(((data[12] & 0x01) << 7) | (data[13] >> 1));
        // 实际上 flags 在 data[13] 的低 6 位，加上 data[12] 的最低位作为 NS 标志
        // 简化处理：flags 在 data[13]
        let flags = TcpFlags::from_bits(data[13]);
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        if data_offset < 5 {
            return Err(PacketError::InvalidTcpHeaderLength { data_offset });
        }

        let header_len = (data_offset as usize) * 4;
        let options = if header_len > Self::MIN_LEN && data.len() >= header_len {
            data[Self::MIN_LEN..header_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
            options,
        })
    }

    /// 序列化 TCP 头部为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_len = self.header_len();
        let mut bytes = Vec::with_capacity(header_len);

        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        bytes.extend_from_slice(&self.dst_port.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.ack.to_be_bytes());
        bytes.push((self.data_offset << 4) | ((self.reserved & 0x07) << 1));
        bytes.push(self.flags.bits());
        bytes.extend_from_slice(&self.window.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        bytes.extend_from_slice(&self.options);

        // 填充到 4 字节对齐
        while bytes.len() < header_len {
            bytes.push(0);
        }

        bytes
    }

    /// 获取头部长度 (字节)
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }
}

/// TCP 包构造器
#[derive(Debug, Clone)]
pub struct TcpPacketBuilder {
    header: TcpHeader,
}

impl TcpPacketBuilder {
    /// 创建新的构造器
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            header: TcpHeader::new(src_port, dst_port),
        }
    }

    /// 设置序列号
    pub fn seq(mut self, seq: u32) -> Self {
        self.header.seq = seq;
        self
    }

    /// 设置确认号
    pub fn ack(mut self, ack: u32) -> Self {
        self.header.ack = ack;
        self
    }

    /// 设置标志位
    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.header.flags = flags;
        self
    }

    /// 添加标志位
    pub fn add_flag(mut self, flag: TcpFlags) -> Self {
        self.header.flags |= flag;
        self
    }

    /// 设置窗口大小
    pub fn window(mut self, window: u16) -> Self {
        self.header.window = window;
        self
    }

    /// 构建 TCP 头部
    pub fn build(self) -> TcpHeader {
        self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::SYN | TcpFlags::ACK;
        assert!(flags.contains(TcpFlags::SYN));
        assert!(flags.contains(TcpFlags::ACK));
        assert!(!flags.contains(TcpFlags::FIN));
    }

    #[test]
    fn test_tcp_header_roundtrip() {
        let header = TcpPacketBuilder::new(12345, 80)
            .seq(1000)
            .ack(2000)
            .flags(TcpFlags::SYN | TcpFlags::ACK)
            .window(32768)
            .build();

        let bytes = header.to_bytes();
        let parsed = TcpHeader::parse(&bytes).expect("Failed to parse");

        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 80);
        assert_eq!(parsed.seq, 1000);
        assert_eq!(parsed.ack, 2000);
        assert!(parsed.flags.contains(TcpFlags::SYN));
        assert!(parsed.flags.contains(TcpFlags::ACK));
        assert_eq!(parsed.window, 32768);
    }

    #[test]
    fn test_tcp_header_builder() {
        let header = TcpPacketBuilder::new(8080, 443)
            .seq(100)
            .add_flag(TcpFlags::SYN)
            .add_flag(TcpFlags::ACK)
            .build();

        assert_eq!(header.src_port, 8080);
        assert_eq!(header.dst_port, 443);
        assert_eq!(header.seq, 100);
        assert!(header.flags.contains(TcpFlags::SYN));
        assert!(header.flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn test_tcp_header_too_short() {
        let bytes = vec![0u8; 10];
        let result = TcpHeader::parse(&bytes);
        assert!(matches!(result, Err(PacketError::TooShort { .. })));
    }
}
