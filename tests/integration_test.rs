use etherparse::{Ipv4Header, TcpHeader};
use scopeguard::defer;
use std::net::Ipv4Addr;
use std::sync::Arc;
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

    let mut ip_header = Ipv4Header::new(
        tcp_header.header_len() as u16,
        64,
        etherparse::ip_number::TCP,
        source_ip.octets(),
        dest_ip.octets(),
    )?;
    ip_header.header_checksum = ip_header.calc_header_checksum();
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

fn init_raw_tcp(
    interface: &str,
) -> Result<tokio::io::unix::AsyncFd<i32>, Box<dyn std::error::Error>> {
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        if sock == -1 {
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to create raw socket: {}", err).into());
        }

        // IP_HDRINCL
        let one: libc::c_int = 1;
        if libc::setsockopt(
            sock,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        ) == -1
        {
            libc::close(sock);
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to set IP_HDRINCL: {}", err).into());
        }

        // SO_BINDTODEVICE
        let if_name_c = std::ffi::CString::new(interface)
            .map_err(|e| format!("Invalid interface name: {}", e))?;
        if libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            if_name_c.as_ptr() as *const libc::c_void,
            if_name_c.as_bytes_with_nul().len() as libc::socklen_t,
        ) == -1
        {
            libc::close(sock);
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to set SO_BINDTODEVICE: {}", err).into());
        }

        // O_NONBLOCK
        let flags = libc::fcntl(sock, libc::F_GETFL, 0);
        if flags == -1 {
            libc::close(sock);
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to get socket flags: {}", err).into());
        }
        let ret = libc::fcntl(sock, libc::F_SETFL, flags | libc::O_NONBLOCK);
        if ret == -1 {
            libc::close(sock);
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to set socket to non-blocking: {}", err).into());
        }

        let async_fd = tokio::io::unix::AsyncFd::new(sock)?;
        Ok(async_fd)
    }
}

fn read_and_print_raw_tcp(raw_tcp: &tokio::io::unix::AsyncFd<i32>) -> std::io::Result<()> {
    let mut buffer = [0u8; 1500];
    loop {
        let nread = unsafe {
            libc::recv(
                *raw_tcp.get_ref(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };
        if nread < 0 {
            return Err(std::io::Error::last_os_error());
        } else if nread == 0 {
            break;
        }

        let slice = &buffer[..nread as usize];
        let ip_header = etherparse::Ipv4HeaderSlice::from_slice(slice)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        if ip_header.source() != [1, 1, 1, 1] {
            continue;
        }
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
    }

    Ok(())
}

async fn write_syn(
    raw_tcp: &tokio::io::unix::AsyncFd<i32>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 构造 TCP SYN 包
    let source_ip = Ipv4Addr::new(172, 28, 199, 195);
    let dest_ip = Ipv4Addr::new(1, 1, 1, 1);
    let source_port = 1234u16;
    let dest_port = 80u16;

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
    let dst_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(dest_ip.octets()).to_be(),
        },
        sin_zero: [0; 8],
    };

    loop {
        let mut guard = raw_tcp.writable().await?;
        match guard.try_io(|_| {
            let result = unsafe {
                libc::sendto(
                    *raw_tcp.get_ref(),
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &dst_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of_val(&dst_addr) as libc::socklen_t,
                )
            };

            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        }) {
            Ok(Ok(())) => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_would_block) => continue,
        }
    }

    Ok(())
}

fn exec(command: &str) -> std::io::Result<()> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("command failed: {}, stderr: {}", command, stderr.trim()),
        ));
    }
    Ok(())
}

#[tokio::test]
async fn test_raw_tcp_syn() -> Result<(), Box<dyn std::error::Error>> {
    exec("iptables -t raw -I OUTPUT 1 -p tcp -o eth0 -d 1.1.1.1 --dport 80 --sport 1234 --tcp-flags RST RST -j DROP")?;
    defer! {
        exec("iptables -t raw -D OUTPUT -p tcp -o eth0 -d 1.1.1.1 --dport 80 --sport 1234 --tcp-flags RST RST -j DROP").ok();
    }

    let raw_tcp0 = Arc::new(init_raw_tcp("eth0")?);
    let raw_tcp1 = raw_tcp0.clone();

    // tokio spawn two and wait
    let spawn0 = tokio::spawn(async move {
        loop {
            let mut guard = raw_tcp0.readable().await.unwrap();
            match guard.try_io(|_| read_and_print_raw_tcp(&raw_tcp0)) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => panic!("raw tcp read failed: {}", e),
                Err(_would_block) => continue,
            }
        }
    });

    let spawn1 = tokio::spawn(async move {
        for _ in 0..5 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            write_syn(&raw_tcp1).await.unwrap();
        }
    });

    let _ = tokio::join!(spawn0, spawn1);

    Ok(())
}
