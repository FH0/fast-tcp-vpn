//! VPN 传输包结构
//!
//! 用于封装和传输加密的原始 IP 数据包

use std::net::Ipv4Addr;
use super::{IpHeader, TcpHeader, PacketError, compute_ip_checksum, compute_tcp_checksum};

/// VPN 传输包
///
/// 格式: [IP头(20B)] + [TCP头(20B+)] + [加密的原始IP包]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPacket {
    /// 外层 IP 头（传输用）
    pub outer_ip: IpHeader,
    /// 外层 TCP 头（传输用）
    pub outer_tcp: TcpHeader,
    /// 加密后的 payload（原始 IP 包）
    pub encrypted_payload: Vec<u8>,
}

impl TransportPacket {
    /// 创建传输包
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        encrypted_payload: Vec<u8>,
    ) -> Self {
        let outer_tcp = TcpHeader::new(src_port, dst_port);
        let total_len = IpHeader::MIN_LEN + outer_tcp.header_len() + encrypted_payload.len();

        let outer_ip = IpHeader {
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
            outer_ip,
            outer_tcp,
            encrypted_payload,
        }
    }

    /// 从原始字节解析
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < IpHeader::MIN_LEN {
            return Err(PacketError::TooShort {
                expected: IpHeader::MIN_LEN,
                actual: data.len(),
            });
        }

        let outer_ip = IpHeader::parse(data)?;

        // 必须是 TCP 协议
        if outer_ip.protocol != 6 {
            return Err(PacketError::NotTcp {
                protocol: outer_ip.protocol,
            });
        }

        let ip_header_len = outer_ip.header_len();
        if data.len() < ip_header_len {
            return Err(PacketError::TooShort {
                expected: ip_header_len,
                actual: data.len(),
            });
        }

        let tcp_data = &data[ip_header_len..];
        let outer_tcp = TcpHeader::parse(tcp_data)?;

        let tcp_header_len = outer_tcp.header_len();
        let payload_start = tcp_header_len;
        let encrypted_payload = if tcp_data.len() > payload_start {
            tcp_data[payload_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            outer_ip,
            outer_tcp,
            encrypted_payload,
        })
    }

    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            IpHeader::MIN_LEN + self.outer_tcp.header_len() + self.encrypted_payload.len()
        );

        // 先计算校验和
        let mut ip_header = self.outer_ip.clone();
        let mut tcp_header = self.outer_tcp.clone();

        // 计算 TCP 校验和
        tcp_header.checksum = 0;
        let tcp_bytes = tcp_header.to_bytes();
        tcp_header.checksum = compute_tcp_checksum(
            &ip_header.src_ip,
            &ip_header.dst_ip,
            &tcp_bytes,
            &self.encrypted_payload,
        );

        // 计算 IP 校验和
        ip_header.checksum = 0;
        let ip_bytes = ip_header.to_bytes();
        ip_header.checksum = compute_ip_checksum(&ip_bytes);

        result.extend_from_slice(&ip_header.to_bytes());
        result.extend_from_slice(&tcp_header.to_bytes());
        result.extend_from_slice(&self.encrypted_payload);

        result
    }

    /// 获取源 IP
    pub fn src_ip(&self) -> Ipv4Addr {
        self.outer_ip.src_ip
    }

    /// 获取目标 IP
    pub fn dst_ip(&self) -> Ipv4Addr {
        self.outer_ip.dst_ip
    }

    /// 获取源端口
    pub fn src_port(&self) -> u16 {
        self.outer_tcp.src_port
    }

    /// 获取目标端口
    pub fn dst_port(&self) -> u16 {
        self.outer_tcp.dst_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_packet_roundtrip() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = b"encrypted data here".to_vec();

        let packet = TransportPacket::new(src_ip, dst_ip, 8443, 8443, payload.clone());

        let bytes = packet.to_bytes();
        let parsed = TransportPacket::parse(&bytes).expect("Failed to parse transport packet");

        assert_eq!(parsed.outer_ip.src_ip, src_ip);
        assert_eq!(parsed.outer_ip.dst_ip, dst_ip);
        assert_eq!(parsed.outer_tcp.src_port, 8443);
        assert_eq!(parsed.outer_tcp.dst_port, 8443);
        assert_eq!(parsed.encrypted_payload, payload);
    }

    #[test]
    fn test_transport_packet_empty_payload() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);

        let packet = TransportPacket::new(src_ip, dst_ip, 12345, 54321, Vec::new());

        let bytes = packet.to_bytes();
        let parsed = TransportPacket::parse(&bytes).expect("Failed to parse transport packet");

        assert!(parsed.encrypted_payload.is_empty());
    }

    #[test]
    fn test_transport_packet_large_payload() {
        let src_ip = Ipv4Addr::new(172, 16, 0, 1);
        let dst_ip = Ipv4Addr::new(172, 16, 0, 2);
        let payload = vec![0xAB; 1400]; // 模拟大 payload

        let packet = TransportPacket::new(src_ip, dst_ip, 8443, 8443, payload.clone());

        let bytes = packet.to_bytes();
        let parsed = TransportPacket::parse(&bytes).expect("Failed to parse transport packet");

        assert_eq!(parsed.encrypted_payload.len(), 1400);
        assert_eq!(parsed.encrypted_payload, payload);
    }
}
