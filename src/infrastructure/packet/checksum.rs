use std::net::Ipv4Addr;

/// 计算 Internet 校验和 (RFC 1071)
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // 按 16 位字累加
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // 处理奇数字节
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // 折叠进位
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 取反
    !(sum as u16)
}

/// 计算 IP 头部校验和
pub fn compute_ip_checksum(ip_header: &[u8]) -> u16 {
    // 假设 checksum 字段已经设为 0
    internet_checksum(ip_header)
}

/// 验证 IP 头部校验和
pub fn verify_ip_checksum(ip_header: &[u8]) -> bool {
    // 包含校验和字段的完整头部，校验和应为 0
    internet_checksum(ip_header) == 0
}

/// 计算 TCP 校验和 (包含伪头部)
pub fn compute_tcp_checksum(
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    tcp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let tcp_len = tcp_header.len() + payload.len();

    // 构建伪头部 + TCP 头部 + 数据
    let mut data = Vec::with_capacity(12 + tcp_len);

    // 伪头部
    data.extend_from_slice(&src_ip.octets());
    data.extend_from_slice(&dst_ip.octets());
    data.push(0); // 保留
    data.push(6); // 协议 (TCP)
    data.extend_from_slice(&(tcp_len as u16).to_be_bytes());

    // TCP 头部 (checksum 字段应为 0)
    data.extend_from_slice(tcp_header);

    // 数据
    data.extend_from_slice(payload);

    internet_checksum(&data)
}

/// 验证 TCP 校验和
pub fn verify_tcp_checksum(
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    tcp_header: &[u8],
    payload: &[u8],
    expected_checksum: u16,
) -> bool {
    // 创建一个副本，将 checksum 字段设为 0
    let mut tcp_header_copy = tcp_header.to_vec();
    if tcp_header_copy.len() >= 18 {
        tcp_header_copy[16] = 0;
        tcp_header_copy[17] = 0;
    }

    let computed = compute_tcp_checksum(src_ip, dst_ip, &tcp_header_copy, payload);
    computed == expected_checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum_basic() {
        // 简单测试：全 0 数据
        let data = vec![0u8; 20];
        let checksum = internet_checksum(&data);
        assert_eq!(checksum, 0xFFFF);
    }

    #[test]
    fn test_internet_checksum_odd_length() {
        // 奇数长度数据
        let data = vec![0x01, 0x02, 0x03];
        let _ = internet_checksum(&data); // 只要不 panic 就行
    }

    #[test]
    fn test_ip_checksum_roundtrip() {
        // 构造一个简单的 IP 头部
        let mut ip_header = vec![
            0x45, 0x00, // version, ihl, dscp, ecn
            0x00, 0x3c, // total length
            0x1c, 0x46, // identification
            0x40, 0x00, // flags, fragment offset
            0x40, 0x06, // ttl, protocol
            0x00, 0x00, // checksum (placeholder)
            0xac, 0x10, 0x0a, 0x63, // src ip
            0xac, 0x10, 0x0a, 0x0c, // dst ip
        ];

        let checksum = compute_ip_checksum(&ip_header);
        ip_header[10] = (checksum >> 8) as u8;
        ip_header[11] = checksum as u8;

        assert!(verify_ip_checksum(&ip_header));
    }

    #[test]
    fn test_tcp_checksum_roundtrip() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);

        let mut tcp_header = vec![
            0x30, 0x39, // src port (12345)
            0x00, 0x50, // dst port (80)
            0x00, 0x00, 0x03, 0xe8, // seq (1000)
            0x00, 0x00, 0x07, 0xd0, // ack (2000)
            0x50, 0x12, // data offset, flags (SYN+ACK)
            0x80, 0x00, // window
            0x00, 0x00, // checksum (placeholder)
            0x00, 0x00, // urgent ptr
        ];

        let payload = b"Hello";

        let checksum = compute_tcp_checksum(&src_ip, &dst_ip, &tcp_header, payload);
        tcp_header[16] = (checksum >> 8) as u8;
        tcp_header[17] = checksum as u8;

        assert!(verify_tcp_checksum(&src_ip, &dst_ip, &tcp_header, payload, checksum));
    }

    #[test]
    fn test_tcp_checksum_corrupted() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);

        let tcp_header = vec![
            0x30, 0x39, 0x00, 0x50,
            0x00, 0x00, 0x03, 0xe8,
            0x00, 0x00, 0x07, 0xd0,
            0x50, 0x12, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let payload = b"Hello";
        let checksum = compute_tcp_checksum(&src_ip, &dst_ip, &tcp_header, payload);

        // 使用错误的校验和
        assert!(!verify_tcp_checksum(&src_ip, &dst_ip, &tcp_header, payload, checksum.wrapping_add(1)));
    }

    #[test]
    fn test_empty_payload_checksum() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);

        let tcp_header = vec![
            0x1f, 0x90, 0x01, 0xbb, // ports
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xff, 0xff, // data offset, flags, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ];

        let payload: &[u8] = &[];
        let checksum = compute_tcp_checksum(&src_ip, &dst_ip, &tcp_header, payload);

        assert!(verify_tcp_checksum(&src_ip, &dst_ip, &tcp_header, payload, checksum));
    }
}
