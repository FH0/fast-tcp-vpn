mod ip;
mod tcp;
mod checksum;
mod error;
mod transport;

pub use ip::*;
pub use tcp::*;
pub use checksum::*;
pub use error::*;
pub use transport::*;

use std::net::Ipv4Addr;

/// Raw TCP 数据包，包含 IP 头 + TCP 头 + Payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub ip_header: IpHeader,
    pub tcp_header: TcpHeader,
    pub payload: Vec<u8>,
}

impl Packet {
    /// 创建新的 TCP 数据包
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Self {
        let tcp_header = TcpHeader::new(src_port, dst_port);
        let total_len = IpHeader::MIN_LEN + tcp_header.header_len() + payload.len();

        let ip_header = IpHeader {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: total_len as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6, // TCP
            checksum: 0,
            src_ip,
            dst_ip,
        };

        Self {
            ip_header,
            tcp_header,
            payload,
        }
    }

    /// 从原始字节解析数据包
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < IpHeader::MIN_LEN {
            return Err(PacketError::TooShort {
                expected: IpHeader::MIN_LEN,
                actual: data.len(),
            });
        }

        let ip_header = IpHeader::parse(data)?;

        if ip_header.protocol != 6 {
            return Err(PacketError::NotTcp {
                protocol: ip_header.protocol,
            });
        }

        let ip_header_len = (ip_header.ihl as usize) * 4;
        if data.len() < ip_header_len {
            return Err(PacketError::TooShort {
                expected: ip_header_len,
                actual: data.len(),
            });
        }

        let tcp_data = &data[ip_header_len..];
        let tcp_header = TcpHeader::parse(tcp_data)?;

        let tcp_header_len = tcp_header.header_len();
        let payload_start = tcp_header_len;
        let payload = if tcp_data.len() > payload_start {
            tcp_data[payload_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            ip_header,
            tcp_header,
            payload,
        })
    }

    /// 序列化数据包为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            IpHeader::MIN_LEN + self.tcp_header.header_len() + self.payload.len()
        );

        // 先计算校验和
        let mut ip_header = self.ip_header.clone();
        let mut tcp_header = self.tcp_header.clone();

        // 计算 TCP 校验和
        tcp_header.checksum = 0;
        let tcp_bytes = tcp_header.to_bytes();
        tcp_header.checksum = compute_tcp_checksum(
            &ip_header.src_ip,
            &ip_header.dst_ip,
            &tcp_bytes,
            &self.payload,
        );

        // 计算 IP 校验和
        ip_header.checksum = 0;
        let ip_bytes = ip_header.to_bytes();
        ip_header.checksum = compute_ip_checksum(&ip_bytes);

        result.extend_from_slice(&ip_header.to_bytes());
        result.extend_from_slice(&tcp_header.to_bytes());
        result.extend_from_slice(&self.payload);

        result
    }

    /// 验证数据包校验和
    pub fn verify_checksums(&self) -> Result<(), PacketError> {
        // 验证 IP 校验和
        let ip_bytes = self.ip_header.to_bytes();
        if !verify_ip_checksum(&ip_bytes) {
            return Err(PacketError::InvalidIpChecksum);
        }

        // 验证 TCP 校验和
        let tcp_bytes = self.tcp_header.to_bytes();
        if !verify_tcp_checksum(
            &self.ip_header.src_ip,
            &self.ip_header.dst_ip,
            &tcp_bytes,
            &self.payload,
            self.tcp_header.checksum,
        ) {
            return Err(PacketError::InvalidTcpChecksum);
        }

        Ok(())
    }
}

/// 通用 IP 数据包（支持任意协议：TCP/UDP/ICMP 等）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket {
    /// 原始字节数据
    pub raw: Vec<u8>,
    /// IP 头（已解析）
    pub ip_header: IpHeader,
    /// Payload 起始偏移
    pub payload_offset: usize,
}

impl IpPacket {
    /// 从原始字节解析（不限制协议类型）
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < IpHeader::MIN_LEN {
            return Err(PacketError::TooShort {
                expected: IpHeader::MIN_LEN,
                actual: data.len(),
            });
        }

        let ip_header = IpHeader::parse(data)?;
        let payload_offset = ip_header.header_len();

        if data.len() < payload_offset {
            return Err(PacketError::TooShort {
                expected: payload_offset,
                actual: data.len(),
            });
        }

        Ok(Self {
            raw: data.to_vec(),
            ip_header,
            payload_offset,
        })
    }

    /// 获取 payload（IP 头之后的所有数据）
    pub fn payload(&self) -> &[u8] {
        &self.raw[self.payload_offset..]
    }

    /// 转换为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// 获取协议类型
    pub fn protocol(&self) -> u8 {
        self.ip_header.protocol
    }

    /// 获取源 IP
    pub fn src_ip(&self) -> Ipv4Addr {
        self.ip_header.src_ip
    }

    /// 获取目标 IP
    pub fn dst_ip(&self) -> Ipv4Addr {
        self.ip_header.dst_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = b"Hello, TCP!".to_vec();

        let mut packet = Packet::new(src_ip, dst_ip, 12345, 80, payload.clone());
        packet.tcp_header.seq = 1000;
        packet.tcp_header.ack = 2000;
        packet.tcp_header.flags = TcpFlags::SYN | TcpFlags::ACK;

        let bytes = packet.to_bytes();
        let parsed = Packet::parse(&bytes).expect("Failed to parse packet");

        assert_eq!(parsed.ip_header.src_ip, src_ip);
        assert_eq!(parsed.ip_header.dst_ip, dst_ip);
        assert_eq!(parsed.tcp_header.src_port, 12345);
        assert_eq!(parsed.tcp_header.dst_port, 80);
        assert_eq!(parsed.tcp_header.seq, 1000);
        assert_eq!(parsed.tcp_header.ack, 2000);
        assert!(parsed.tcp_header.flags.contains(TcpFlags::SYN));
        assert!(parsed.tcp_header.flags.contains(TcpFlags::ACK));
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_packet_checksum_verification() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let payload = b"Test data".to_vec();

        let packet = Packet::new(src_ip, dst_ip, 8080, 443, payload);
        let bytes = packet.to_bytes();
        let parsed = Packet::parse(&bytes).expect("Failed to parse packet");

        assert!(parsed.verify_checksums().is_ok());
    }

    #[test]
    fn test_packet_corrupted_checksum() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let payload = b"Test data".to_vec();

        let packet = Packet::new(src_ip, dst_ip, 8080, 443, payload);
        let mut bytes = packet.to_bytes();

        // 篡改 payload
        if let Some(last) = bytes.last_mut() {
            *last ^= 0xFF;
        }

        let parsed = Packet::parse(&bytes).expect("Failed to parse packet");
        assert!(parsed.verify_checksums().is_err());
    }

    #[test]
    fn test_empty_payload() {
        let src_ip = Ipv4Addr::new(192, 168, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 0, 2);

        let mut packet = Packet::new(src_ip, dst_ip, 1234, 5678, Vec::new());
        packet.tcp_header.flags = TcpFlags::SYN;

        let bytes = packet.to_bytes();
        let parsed = Packet::parse(&bytes).expect("Failed to parse packet");

        assert!(parsed.payload.is_empty());
        assert!(parsed.verify_checksums().is_ok());
    }

    // ==================== IpPacket 测试 ====================

    #[test]
    fn test_ip_packet_parse_tcp() {
        // 构造一个 TCP 包
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = b"Hello, TCP!".to_vec();

        let packet = Packet::new(src_ip, dst_ip, 12345, 80, payload.clone());
        let bytes = packet.to_bytes();

        // 使用 IpPacket 解析（不限制协议）
        let ip_packet = IpPacket::parse(&bytes).expect("Failed to parse IP packet");

        assert_eq!(ip_packet.ip_header.src_ip, src_ip);
        assert_eq!(ip_packet.ip_header.dst_ip, dst_ip);
        assert_eq!(ip_packet.ip_header.protocol, 6); // TCP
        assert_eq!(ip_packet.payload_offset, 20); // 标准 IP 头长度
        assert!(!ip_packet.payload().is_empty());
    }

    #[test]
    fn test_ip_packet_parse_udp() {
        // 手动构造一个 UDP 包（protocol = 17）
        let bytes = vec![
            0x45, 0x00, // Version=4, IHL=5, DSCP=0, ECN=0
            0x00, 0x1C, // Total length = 28 (20 IP + 8 UDP)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment offset
            0x40, 0x11, // TTL=64, Protocol=17 (UDP)
            0x00, 0x00, // Checksum (placeholder)
            0xC0, 0xA8, 0x01, 0x01, // Src IP: 192.168.1.1
            0xC0, 0xA8, 0x01, 0x02, // Dst IP: 192.168.1.2
            // UDP header (8 bytes)
            0x30, 0x39, // Src port: 12345
            0x00, 0x50, // Dst port: 80
            0x00, 0x08, // Length: 8
            0x00, 0x00, // Checksum
        ];

        let ip_packet = IpPacket::parse(&bytes).expect("Failed to parse UDP packet");

        assert_eq!(ip_packet.ip_header.protocol, 17); // UDP
        assert_eq!(ip_packet.ip_header.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip_packet.ip_header.dst_ip, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(ip_packet.payload().len(), 8); // UDP header
    }

    #[test]
    fn test_ip_packet_parse_icmp() {
        // 手动构造一个 ICMP 包（protocol = 1）
        let bytes = vec![
            0x45, 0x00, // Version=4, IHL=5
            0x00, 0x1C, // Total length = 28 (20 IP + 8 ICMP)
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags + Fragment offset
            0x40, 0x01, // TTL=64, Protocol=1 (ICMP)
            0x00, 0x00, // Checksum
            0x0A, 0x00, 0x00, 0x01, // Src IP: 10.0.0.1
            0x0A, 0x00, 0x00, 0x02, // Dst IP: 10.0.0.2
            // ICMP Echo Request (8 bytes)
            0x08, 0x00, // Type=8 (Echo), Code=0
            0x00, 0x00, // Checksum
            0x00, 0x01, // Identifier
            0x00, 0x01, // Sequence
        ];

        let ip_packet = IpPacket::parse(&bytes).expect("Failed to parse ICMP packet");

        assert_eq!(ip_packet.ip_header.protocol, 1); // ICMP
        assert_eq!(ip_packet.ip_header.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip_packet.ip_header.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip_packet.payload().len(), 8); // ICMP header
    }

    #[test]
    fn test_ip_packet_roundtrip() {
        let original_bytes = vec![
            0x45, 0x00, // Version=4, IHL=5
            0x00, 0x28, // Total length = 40
            0x12, 0x34, // Identification
            0x40, 0x00, // Flags=DF, Fragment offset=0
            0x40, 0x06, // TTL=64, Protocol=6 (TCP)
            0xAB, 0xCD, // Checksum
            0xC0, 0xA8, 0x00, 0x01, // Src IP: 192.168.0.1
            0xC0, 0xA8, 0x00, 0x02, // Dst IP: 192.168.0.2
            // TCP header (20 bytes)
            0x00, 0x50, 0x01, 0xBB, // Ports: 80 -> 443
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, 0x02, // Data offset=5, Flags=SYN
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent ptr
        ];

        let ip_packet = IpPacket::parse(&original_bytes).expect("Failed to parse");
        let roundtrip_bytes = ip_packet.to_bytes();

        assert_eq!(roundtrip_bytes, original_bytes);
    }

    #[test]
    fn test_ip_packet_too_short() {
        let bytes = vec![0x45, 0x00, 0x00]; // Only 3 bytes
        let result = IpPacket::parse(&bytes);
        assert!(matches!(result, Err(PacketError::TooShort { .. })));
    }

    #[test]
    fn test_ip_packet_invalid_version() {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x60; // IPv6
        let result = IpPacket::parse(&bytes);
        assert!(matches!(result, Err(PacketError::InvalidIpVersion { version: 6 })));
    }
}
