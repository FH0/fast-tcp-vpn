mod ip;
mod tcp;
mod checksum;
mod error;

pub use ip::*;
pub use tcp::*;
pub use checksum::*;
pub use error::*;

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
}
