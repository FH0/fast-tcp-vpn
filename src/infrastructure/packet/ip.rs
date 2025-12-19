use std::net::Ipv4Addr;
use super::PacketError;

/// IPv4 头部
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHeader {
    /// IP 版本 (4)
    pub version: u8,
    /// 头部长度 (以 4 字节为单位)
    pub ihl: u8,
    /// 差分服务代码点
    pub dscp: u8,
    /// 显式拥塞通知
    pub ecn: u8,
    /// 总长度
    pub total_length: u16,
    /// 标识
    pub identification: u16,
    /// 标志
    pub flags: u8,
    /// 片偏移
    pub fragment_offset: u16,
    /// 生存时间
    pub ttl: u8,
    /// 协议 (6 = TCP)
    pub protocol: u8,
    /// 头部校验和
    pub checksum: u16,
    /// 源 IP 地址
    pub src_ip: Ipv4Addr,
    /// 目的 IP 地址
    pub dst_ip: Ipv4Addr,
}

impl IpHeader {
    /// 最小 IP 头部长度 (无选项)
    pub const MIN_LEN: usize = 20;

    /// 从字节解析 IP 头部
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < Self::MIN_LEN {
            return Err(PacketError::TooShort {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        let version = data[0] >> 4;
        if version != 4 {
            return Err(PacketError::InvalidIpVersion { version });
        }

        let ihl = data[0] & 0x0F;
        if ihl < 5 {
            return Err(PacketError::InvalidIpHeaderLength { ihl });
        }

        let dscp = data[1] >> 2;
        let ecn = data[1] & 0x03;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags = data[6] >> 5;
        let fragment_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
        })
    }

    /// 序列化 IP 头部为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::MIN_LEN);

        bytes.push((self.version << 4) | (self.ihl & 0x0F));
        bytes.push((self.dscp << 2) | (self.ecn & 0x03));
        bytes.extend_from_slice(&self.total_length.to_be_bytes());
        bytes.extend_from_slice(&self.identification.to_be_bytes());
        bytes.push((self.flags << 5) | ((self.fragment_offset >> 8) as u8 & 0x1F));
        bytes.push(self.fragment_offset as u8);
        bytes.push(self.ttl);
        bytes.push(self.protocol);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.src_ip.octets());
        bytes.extend_from_slice(&self.dst_ip.octets());

        bytes
    }

    /// 获取头部长度 (字节)
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_roundtrip() {
        let header = IpHeader {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 60,
            identification: 0x1234,
            flags: 2,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6,
            checksum: 0,
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(192, 168, 1, 2),
        };

        let bytes = header.to_bytes();
        let parsed = IpHeader::parse(&bytes).expect("Failed to parse");

        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.ihl, header.ihl);
        assert_eq!(parsed.total_length, header.total_length);
        assert_eq!(parsed.identification, header.identification);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.ttl, header.ttl);
        assert_eq!(parsed.protocol, header.protocol);
        assert_eq!(parsed.src_ip, header.src_ip);
        assert_eq!(parsed.dst_ip, header.dst_ip);
    }

    #[test]
    fn test_ip_header_invalid_version() {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x60; // IPv6

        let result = IpHeader::parse(&bytes);
        assert!(matches!(result, Err(PacketError::InvalidIpVersion { version: 6 })));
    }

    #[test]
    fn test_ip_header_too_short() {
        let bytes = vec![0u8; 10];
        let result = IpHeader::parse(&bytes);
        assert!(matches!(result, Err(PacketError::TooShort { .. })));
    }
}
