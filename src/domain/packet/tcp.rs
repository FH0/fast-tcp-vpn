use bytes::{Buf, BufMut, Bytes, BytesMut};

/// TCP 报文结构 (RFC 9293)
///
/// ```text
///        0                   1                   2                   3
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |          Source Port          |       Destination Port        |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                        Sequence Number                        |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                    Acknowledgment Number                      |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |  Data |       |C|E|U|A|P|R|S|F|                               |
///       | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
///       |       |       |R|E|G|K|H|T|N|N|                               |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |           Checksum            |         Urgent Pointer        |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                           [Options]                           |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///       |                                                               :
///       :                             Data                              :
///       :                                                               |
///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub data: Bytes,
}

pub const TCP_FLAG_FIN: u16 = 0x01;
pub const TCP_FLAG_SYN: u16 = 0x02;
pub const TCP_FLAG_RST: u16 = 0x04;
pub const TCP_FLAG_PSH: u16 = 0x08;
pub const TCP_FLAG_ACK: u16 = 0x10;
pub const TCP_FLAG_URG: u16 = 0x20;
pub const TCP_FLAG_ECE: u16 = 0x40;
pub const TCP_FLAG_CWR: u16 = 0x80;

impl TcpPacket {
    /// 创建一个新的 TCP 报文
    pub fn new(source_port: u16, destination_port: u16, data: Bytes) -> Self {
        Self {
            source_port,
            destination_port,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset: 5, // 最小首部长度
            flags: 0,
            window_size: 65535,
            checksum: 0,
            urgent_pointer: 0,
            data,
        }
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    pub fn destination_port(&self) -> u16 {
        self.destination_port
    }

    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub fn acknowledgment_number(&self) -> u32 {
        self.acknowledgment_number
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// 将 TCP 报文序列化为字节流
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(20 + self.data.len());

        // 源端口
        bytes.put_u16(self.source_port);

        // 目的端口
        bytes.put_u16(self.destination_port);

        // 序列号
        bytes.put_u32(self.sequence_number);

        // 确认号
        bytes.put_u32(self.acknowledgment_number);

        // 数据偏移 (4位), 保留 (4位), 以及标志位 (8位)
        let offset_res_flags = ((self.data_offset as u16) << 12) | (self.flags & 0x0FFF);
        bytes.put_u16(offset_res_flags);

        // 窗口大小
        bytes.put_u16(self.window_size);

        // 校验和
        bytes.put_u16(self.checksum);

        // 紧急指针
        bytes.put_u16(self.urgent_pointer);

        // 数据
        bytes.put_slice(&self.data);

        bytes.freeze()
    }

    /// 从字节流反序列化 TCP 报文
    pub fn from_bytes(mut buffer: Bytes) -> Result<Self, String> {
        if buffer.remaining() < 20 {
            return Err("Buffer too short for TCP header".to_string());
        }

        let source_port = buffer.get_u16();
        let destination_port = buffer.get_u16();
        let sequence_number = buffer.get_u32();
        let acknowledgment_number = buffer.get_u32();

        let offset_res_flags = buffer.get_u16();
        let data_offset = (offset_res_flags >> 12) as u8;
        let flags = offset_res_flags & 0x0FFF; // 包含保留位

        let window_size = buffer.get_u16();
        let checksum = buffer.get_u16();
        let urgent_pointer = buffer.get_u16();

        let header_len = (data_offset * 4) as usize;
        let options_len = if header_len > 20 { header_len - 20 } else { 0 };

        if buffer.remaining() < options_len {
            return Err(
                "Buffer shorter than TCP header length specified in data_offset".to_string(),
            );
        }

        // 暂时跳过选项
        if options_len > 0 {
            buffer.advance(options_len);
        }

        let data = buffer; // 剩余部分为数据

        Ok(Self {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            data,
        })
    }

    /// 计算并设置 TCP 校验和
    /// 需要源和目的 IP 地址来构建伪首部
    pub fn update_checksum(&mut self, source_ip: [u8; 4], destination_ip: [u8; 4]) {
        self.checksum = 0;
        let tcp_bytes = self.to_bytes();

        let mut pseudo_header = Vec::with_capacity(12 + tcp_bytes.len());
        pseudo_header.extend_from_slice(&source_ip);
        pseudo_header.extend_from_slice(&destination_ip);
        pseudo_header.push(0);
        pseudo_header.push(6); // TCP 协议号为 6
        pseudo_header.extend_from_slice(&(tcp_bytes.len() as u16).to_be_bytes());
        pseudo_header.extend_from_slice(&tcp_bytes);

        self.checksum = crate::domain::packet::ip::calculate_checksum(&pseudo_header);
    }
}
