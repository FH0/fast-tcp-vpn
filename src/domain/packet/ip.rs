use bytes::{Buf, BufMut, Bytes, BytesMut};

/// IPv4 首部格式 (RFC 791)
///
/// ```text
///    0                   1                   2                   3   
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |Version|  IHL  |Type of Service|          Total Length         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         Identification        |Flags|      Fragment Offset    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  Time to Live |    Protocol   |         Header Checksum       |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       Source Address                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Destination Address                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Options                    |    Padding    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// IPv6 首部格式 (RFC 8200)
///
/// ```text
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |Version| Traffic Class |           Flow Label                  |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         Payload Length        |  Next Header  |   Hop Limit   |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   +                                                               +
///   |                                                               |
///   +                         Source Address                        +
///   |                                                               |
///   +                                                               +
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                                                               |
///   +                                                               +
///   |                                                               |
///   +                      Destination Address                      +
///   |                                                               |
///   +                                                               +
///   |                                                               |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub data: Bytes,
}

impl Ipv4Packet {
    /// 创建一个新的 IPv4 报文
    pub fn new(source_ip: [u8; 4], destination_ip: [u8; 4], data: Bytes) -> Self {
        Self {
            version: 4,
            ihl: 5, // 最小首部长度
            tos: 0,
            total_length: (20 + data.len()) as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6, // 本项目默认使用 TCP
            checksum: 0,
            source_ip,
            destination_ip,
            data,
        }
    }

    pub fn source_ip(&self) -> [u8; 4] {
        self.source_ip
    }

    pub fn destination_ip(&self) -> [u8; 4] {
        self.destination_ip
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// 将 IPv4 报文序列化为字节流
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(20 + self.data.len());

        // 版本 (4位) 和 IHL (4位)
        bytes.put_u8((self.version << 4) | (self.ihl & 0x0F));

        // 服务类型
        bytes.put_u8(self.tos);

        // 总长度
        bytes.put_u16(self.total_length);

        // 标识
        bytes.put_u16(self.identification);

        // 标志位 (3位) 和 分片偏移 (13位)
        let flags_offset = ((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF);
        bytes.put_u16(flags_offset);

        // 生存时间 (TTL)
        bytes.put_u8(self.ttl);

        // 协议
        bytes.put_u8(self.protocol);

        // 首部校验和
        bytes.put_u16(self.checksum);

        // 源 IP 地址
        bytes.put_slice(&self.source_ip);

        // 目的 IP 地址
        bytes.put_slice(&self.destination_ip);

        // 数据
        bytes.put_slice(&self.data);

        bytes.freeze()
    }

    /// 从字节流反序列化 IPv4 报文
    pub fn from_bytes(mut buffer: Bytes) -> Result<Self, String> {
        if buffer.remaining() < 20 {
            return Err("Buffer too short for IPv4 header".to_string());
        }

        let first_byte = buffer.get_u8();
        let version = (first_byte & 0xF0) >> 4;
        let ihl = first_byte & 0x0F;
        let tos = buffer.get_u8();
        let total_length = buffer.get_u16();
        let identification = buffer.get_u16();

        let flags_offset = buffer.get_u16();
        let flags = (flags_offset >> 13) as u8;
        let fragment_offset = flags_offset & 0x1FFF;

        let ttl = buffer.get_u8();
        let protocol = buffer.get_u8();
        let checksum = buffer.get_u16();

        let mut source_ip = [0u8; 4];
        buffer.copy_to_slice(&mut source_ip);

        let mut destination_ip = [0u8; 4];
        buffer.copy_to_slice(&mut destination_ip);

        let header_len = (ihl * 4) as usize;
        let options_len = if header_len > 20 { header_len - 20 } else { 0 };

        if buffer.remaining() < options_len {
            return Err("Buffer shorter than IPv4 header length specified in IHL".to_string());
        }

        // 暂时跳过选项
        if options_len > 0 {
            buffer.advance(options_len);
        }

        // 剩余部分为数据，应遵循 total_length
        let data_len = (total_length as usize).saturating_sub(header_len);
        let actual_data_len = std::cmp::min(data_len, buffer.remaining());

        let data = buffer.split_to(actual_data_len);

        Ok(Self {
            version,
            ihl,
            tos,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source_ip,
            destination_ip,
            data,
        })
    }

    /// 计算并设置 IPv4 首部校验和
    pub fn update_checksum(&mut self) {
        self.checksum = 0;
        let bytes = self.to_bytes();
        // 校验和仅覆盖首部 (ihl * 4 字节)
        let header_len = (self.ihl * 4) as usize;
        self.checksum = calculate_checksum(&bytes[..header_len]);
    }
}

pub fn calculate_checksum(buffer: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < buffer.len() - 1 {
        let word = u16::from_be_bytes([buffer[i], buffer[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < buffer.len() {
        sum += (buffer[i] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
