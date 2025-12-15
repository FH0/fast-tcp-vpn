use etherparse::{Ipv4Header, TcpHeader};
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

/// 集成测试：测试通过 TUN 接口发送 TCP SYN 包并接收 ACK 响应
#[tokio::test]
async fn test_tcp_syn_ack() -> Result<(), Box<dyn std::error::Error>> {
    // 创建 TUN 接口
    let tun_name = "tun0";
    if Command::new("ip")
        .args(&["link", "show", tun_name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = Command::new("ip")
            .args(&["link", "delete", tun_name])
            .output();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 1))
        .netmask((255, 0, 0, 0))
        .up()
        .tun_name(tun_name);
    let device = tun::create_as_async(&config)?;
    let (mut reader, mut writer) = tokio::io::split(device);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 启动 TCP 监听器
    let listener = TcpListener::bind("0.0.0.0:1234").await?;
    let listener_handle = tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 构造 TCP SYN 包
    let source_ip = Ipv4Addr::new(10, 0, 0, 2);
    let dest_ip = Ipv4Addr::new(10, 0, 0, 1);
    let source_port = 1234u16;
    let dest_port = 1234u16;

    let mut tcp_header = TcpHeader::new(source_port, dest_port, 0, u16::MAX);
    tcp_header.syn = true;

    let ip_header = Ipv4Header::new(
        tcp_header.header_len() as u16,
        64,
        etherparse::ip_number::TCP,
        source_ip.octets(),
        dest_ip.octets(),
    )?;
    tcp_header.checksum = tcp_header.calc_checksum_ipv4(&ip_header, &[])?;

    // 构建 IP 包
    let mut packet = Vec::<u8>::with_capacity(ip_header.total_len as usize);
    ip_header.write(&mut packet)?;
    tcp_header.write(&mut packet)?;

    // 发送 SYN 包
    writer.write_all(&packet).await?;
    writer.flush().await?;

    // 接收 ACK 响应
    let mut buffer = vec![0u8; 1500];
    let (ip_header, ip_payload) = loop {
        let received_packet =
            timeout(Duration::from_millis(100), reader.read(&mut buffer)).await??;
        match Ipv4Header::from_slice(&buffer[..received_packet]) {
            Ok(x) => break x,
            Err(_) => continue,
        }
    };

    // 验证 ACK 包
    assert_eq!(ip_header.source, dest_ip.octets());
    assert_eq!(ip_header.destination, source_ip.octets());

    let (tcp_header, _) = TcpHeader::from_slice(ip_payload)?;
    assert_eq!(tcp_header.source_port, dest_port);
    assert_eq!(tcp_header.destination_port, source_port);
    assert!(tcp_header.ack && tcp_header.syn);

    listener_handle.abort();

    Ok(())
}
