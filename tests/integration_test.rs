use etherparse::{Ipv4Header, TcpHeader};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

async fn init_tun(
    name: &str,
    addr: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<tun::AsyncDevice, Box<dyn std::error::Error>> {
    let mut config = tun::Configuration::default();
    config.address(addr).netmask(netmask).up().tun_name(name);
    let mut device = tun::create_as_async(&config)?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    device.persist()?;
    Ok(device)
}

fn init_raw_tcp(
    addr: Ipv4Addr,
) -> Result<tokio::io::unix::AsyncFd<i32>, Box<dyn std::error::Error>> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        if sock == -1 {
            return Err("Failed to create raw socket".into());
        }

        let bind_addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(addr).to_be(),
            },
            sin_zero: [0; 8],
        };
        if libc::bind(
            sock,
            &bind_addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        ) == -1
        {
            libc::close(sock);
            return Err("Failed to bind raw socket".into());
        }

        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        if flags == -1 {
            libc::close(sock);
            return Err("Failed to get socket flags".into());
        }
        let ret = libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
        if ret == -1 {
            libc::close(sock);
            return Err("Failed to set socket to non-blocking".into());
        }

        let async_fd = tokio::io::unix::AsyncFd::new(sock)?;
        Ok(async_fd)
    }
}

/// 集成测试：测试通过 TUN 接口发送 TCP SYN 包并接收 ACK 响应
#[tokio::test]
async fn test_tcp_syn_ack() -> Result<(), Box<dyn std::error::Error>> {
    let device = init_tun(
        "tun0",
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(255, 0, 0, 0),
    )
    .await?;
    let (mut reader, mut writer) = tokio::io::split(device);

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

#[tokio::test]
async fn test_raw_tcp_syn() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let raw_tcp = init_raw_tcp(Ipv4Addr::new(127, 0, 0, 1))?;
        let mut buffer = [0u8; 1500];
        let mut count = 0;

        loop {
            let _guard = raw_tcp.readable().await?;
            loop {
                let nread = libc::recv(
                    *raw_tcp.get_ref(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                );
                if nread < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(err.into());
                }
                println!("Received {} bytes", nread);
                if nread <= 0 {
                    break;
                }

                let slice = &buffer[..nread as usize];
                let ip_header = etherparse::Ipv4HeaderSlice::from_slice(slice)?;
                println!(
                    "IPv4 header, len={}, src={:?}, dst={:?}",
                    ip_header.ihl() * 4,
                    ip_header.source(),
                    ip_header.destination()
                );

                let tcp_payload = &slice[(ip_header.ihl() * 4) as usize..];
                if let Ok(tcp_header) = etherparse::TcpHeaderSlice::from_slice(tcp_payload) {
                    println!(
                        "  TCP header, src_port={}, dst_port={}",
                        tcp_header.source_port(),
                        tcp_header.destination_port()
                    );
                }
                count += 1;
            }

            if count >= 5 {
                break;
            }
        }
    }

    Ok(())
}
