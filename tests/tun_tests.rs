//! TUN 设备集成测试
//!
//! 注意: Linux TUN 测试需要 root 权限才能运行

use fast_tcp_vpn::infrastructure::tun::{MockTun, TunConfig, TunDevice, TunError};
use std::net::Ipv4Addr;
use std::time::Duration;

// ============================================================================
// Mock TUN 测试 (不需要 root 权限)
// ============================================================================

#[test]
fn test_mock_tun_basic_operations() {
    let tun = MockTun::with_defaults();

    // 验证默认配置
    assert_eq!(tun.name(), "tun0");
    assert_eq!(tun.mtu(), 1500);
    assert_eq!(tun.address(), Ipv4Addr::new(10, 0, 0, 1));
}

#[test]
fn test_mock_tun_custom_config() {
    let config = TunConfig::new("vpn0")
        .with_address(Ipv4Addr::new(192, 168, 100, 1))
        .with_netmask(Ipv4Addr::new(255, 255, 255, 0))
        .with_mtu(1400);

    let tun = MockTun::new(config).unwrap();

    assert_eq!(tun.name(), "vpn0");
    assert_eq!(tun.mtu(), 1400);
    assert_eq!(tun.address(), Ipv4Addr::new(192, 168, 100, 1));
}

#[test]
fn test_mock_tun_write_and_retrieve() {
    let tun = MockTun::with_defaults();

    // 模拟写入 IP 数据包
    let ip_packet = create_dummy_ip_packet();
    let written = tun.write(&ip_packet).unwrap();
    assert_eq!(written, ip_packet.len());

    // 验证写入队列
    assert_eq!(tun.write_queue_len(), 1);

    // 获取写入的数据包
    let retrieved = tun.pop_written_packet().unwrap();
    assert_eq!(retrieved, ip_packet);

    // 队列应该为空
    assert_eq!(tun.write_queue_len(), 0);
}

#[test]
fn test_mock_tun_inject_and_read() {
    let tun = MockTun::with_defaults();

    // 注入数据包 (模拟从网络收到的数据)
    let ip_packet = create_dummy_ip_packet();
    tun.inject_packet(ip_packet.clone());

    // 读取数据包
    let mut buf = [0u8; 2048];
    let len = tun.read(&mut buf).unwrap();

    assert_eq!(len, ip_packet.len());
    assert_eq!(&buf[..len], &ip_packet[..]);
}

#[test]
fn test_mock_tun_read_empty_blocking() {
    let tun = MockTun::with_defaults();

    // 阻塞模式下，空队列返回 0
    let mut buf = [0u8; 2048];
    let len = tun.read(&mut buf).unwrap();
    assert_eq!(len, 0);
}

#[test]
fn test_mock_tun_read_empty_nonblocking() {
    let tun = MockTun::with_defaults();
    tun.set_nonblocking(true).unwrap();

    // 非阻塞模式下，空队列返回 WouldBlock 错误
    let mut buf = [0u8; 2048];
    let result = tun.read(&mut buf);
    assert!(matches!(result, Err(TunError::Io(_))));
}

#[test]
fn test_mock_tun_read_with_timeout() {
    let tun = MockTun::with_defaults();

    // 没有数据时应该超时
    let mut buf = [0u8; 2048];
    let start = std::time::Instant::now();
    let result = tun.read_with_timeout(&mut buf, Duration::from_millis(100));
    let elapsed = start.elapsed();

    assert!(matches!(result, Err(TunError::Timeout)));
    assert!(elapsed >= Duration::from_millis(100));
}

#[test]
fn test_mock_tun_read_with_timeout_success() {
    let tun = MockTun::with_defaults();

    // 先注入数据
    let ip_packet = create_dummy_ip_packet();
    tun.inject_packet(ip_packet.clone());

    // 应该立即返回
    let mut buf = [0u8; 2048];
    let len = tun.read_with_timeout(&mut buf, Duration::from_secs(1)).unwrap();

    assert_eq!(len, ip_packet.len());
    assert_eq!(&buf[..len], &ip_packet[..]);
}

#[test]
fn test_mock_tun_multiple_packets() {
    let tun = MockTun::with_defaults();

    // 写入多个数据包
    for i in 0..5 {
        let packet = vec![0x45, 0x00, 0x00, 0x14 + i];
        tun.write(&packet).unwrap();
    }

    assert_eq!(tun.write_queue_len(), 5);

    // 获取所有写入的数据包
    let packets = tun.get_written_packets();
    assert_eq!(packets.len(), 5);

    // 清空队列
    tun.clear_written_packets();
    assert_eq!(tun.write_queue_len(), 0);
}

#[test]
fn test_mock_tun_clone_shares_state() {
    let tun1 = MockTun::with_defaults();
    let tun2 = tun1.clone();

    // 通过 tun1 写入
    let packet = create_dummy_ip_packet();
    tun1.write(&packet).unwrap();

    // 通过 tun2 可以看到
    assert_eq!(tun2.write_queue_len(), 1);

    // 通过 tun2 注入
    tun2.inject_packet(packet.clone());

    // 通过 tun1 可以读取
    assert_eq!(tun1.read_queue_len(), 1);
}

// ============================================================================
// Linux TUN 集成测试 (需要 root 权限)
// ============================================================================

#[test]
#[ignore] // 需要 root 权限运行: cargo test -- --ignored
fn test_linux_tun_creation() {
    use fast_tcp_vpn::infrastructure::tun::LinuxTun;

    let config = TunConfig::new("test_tun0")
        .with_address(Ipv4Addr::new(10, 200, 0, 1))
        .with_netmask(Ipv4Addr::new(255, 255, 255, 0))
        .with_mtu(1500);

    let tun = LinuxTun::new(config);
    assert!(tun.is_ok(), "Failed to create TUN device: {:?}", tun.err());

    let tun = tun.unwrap();
    assert!(tun.name().starts_with("test_tun"));
    assert_eq!(tun.mtu(), 1500);
    assert_eq!(tun.address(), Ipv4Addr::new(10, 200, 0, 1));
}

#[test]
#[ignore] // 需要 root 权限运行
fn test_linux_tun_read_write() {
    use fast_tcp_vpn::infrastructure::tun::LinuxTun;
    use std::thread;

    let config = TunConfig::new("test_tun1")
        .with_address(Ipv4Addr::new(10, 200, 1, 1))
        .with_netmask(Ipv4Addr::new(255, 255, 255, 0));

    let tun = LinuxTun::new(config).expect("Failed to create TUN device");

    // 设置非阻塞模式用于测试
    tun.set_nonblocking(true).unwrap();

    // 尝试读取 (应该返回 WouldBlock 因为没有数据)
    let mut buf = [0u8; 2048];
    let result = tun.read(&mut buf);
    // 非阻塞模式下没有数据会返回 WouldBlock
    assert!(result.is_err() || result.unwrap() == 0);

    // 写入一个简单的 IP 数据包 (会被内核处理)
    let ip_packet = create_dummy_ip_packet();
    let result = tun.write(&ip_packet);
    assert!(result.is_ok(), "Failed to write to TUN: {:?}", result.err());
}

// ============================================================================
// Windows Wintun 集成测试 (占位符)
// ============================================================================

#[test]
#[ignore] // Windows 平台专用
fn test_windows_wintun_creation() {
    use fast_tcp_vpn::infrastructure::tun::WindowsTun;

    let config = TunConfig::new("TestVPN")
        .with_address(Ipv4Addr::new(10, 200, 0, 1))
        .with_netmask(Ipv4Addr::new(255, 255, 255, 0));

    // 在非 Windows 平台应该返回 PlatformNotSupported
    let result = WindowsTun::new(config);

    #[cfg(not(target_os = "windows"))]
    assert!(matches!(result, Err(TunError::PlatformNotSupported)));

    #[cfg(target_os = "windows")]
    {
        // Windows 平台的实际测试
        // 目前返回未实现错误
        assert!(result.is_err());
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建一个简单的 IPv4 数据包用于测试
fn create_dummy_ip_packet() -> Vec<u8> {
    // 最小的 IPv4 头部 (20 字节) + 一些数据
    let mut packet = vec![
        // IPv4 头部
        0x45,       // Version (4) + IHL (5)
        0x00,       // DSCP + ECN
        0x00, 0x1c, // Total Length (28 bytes)
        0x00, 0x01, // Identification
        0x00, 0x00, // Flags + Fragment Offset
        0x40,       // TTL (64)
        0x11,       // Protocol (UDP = 17)
        0x00, 0x00, // Header Checksum (placeholder)
        10, 0, 0, 1,    // Source IP
        10, 0, 0, 2,    // Destination IP
        // 简单的 UDP 数据
        0x00, 0x50, // Source Port (80)
        0x00, 0x51, // Dest Port (81)
        0x00, 0x08, // Length
        0x00, 0x00, // Checksum
    ];

    // 计算 IP 头部校验和
    let checksum = compute_ip_checksum(&packet[..20]);
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xff) as u8;

    packet
}

/// 计算 IP 头部校验和
fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            ((header[i] as u32) << 8) | (header[i + 1] as u32)
        } else {
            (header[i] as u32) << 8
        };
        sum += word;
    }

    // 折叠进位
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}
