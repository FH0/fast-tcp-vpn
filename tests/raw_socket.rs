use fast_tcp_vpn::infrastructure::raw_socket::RawTcpSocket;

#[test]
fn test_receive_10_packets() {
    // 注意：此测试需要 root 权限或 CAP_NET_RAW。
    // 如果没有权限，该测试应当被跳过或预期失败。
    // 我们使用 "eth0" 作为测试的网络接口。
    let socket = match RawTcpSocket::new("eth0", 0) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket (maybe missing root?): {}", e);
            return;
        }
    };

    println!("Starting to receive 10 TCP packets...");

    for i in 1..=10 {
        match socket.receive_packet() {
            Ok(packet) => {
                println!(
                    "Packet {}: Source IP: {:?}, Dest IP: {:?}, Protocol: {}, Data Len: {}",
                    i,
                    packet.source_ip,
                    packet.destination_ip,
                    packet.protocol,
                    packet.data.len()
                );
            }
            Err(e) => {
                eprintln!("Error receiving packet {}: {}", i, e);
            }
        }
    }

    println!("Received 10 packets successfully.");
}

use bytes::Bytes;
use fast_tcp_vpn::infrastructure::ip::Ipv4Packet;
use fast_tcp_vpn::infrastructure::tcp::{
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_SYN, TcpPacket,
};
use std::time::{Duration, Instant};

#[test]
fn test_tcp_http_request() {
    // 此测试模拟一个完整的 TCP 过程：三次握手 -> HTTP 请求 -> 接收响应 -> 四次挥手 (简化)
    // 目标地址: 1.1.1.1 (Cloudflare DNS, 同时也支持 HTTP)
    let interface = "eth0";
    let src_port = 12345;
    let dst_port = 80;
    let dst_ip = [1, 1, 1, 1];

    let socket = match RawTcpSocket::new(interface, src_port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket: {}", e);
            return;
        }
    };

    let src_ip = socket.get_local_ip().expect("Failed to get local IP");

    // 1. 发送 SYN
    let mut tcp_syn = TcpPacket::new(src_port, dst_port, Bytes::new());
    tcp_syn.flags = TCP_FLAG_SYN;
    tcp_syn.sequence_number = 1000;
    tcp_syn.update_checksum(src_ip, dst_ip);

    let mut ip_syn = Ipv4Packet::new(src_ip, dst_ip, tcp_syn.to_bytes());
    ip_syn.update_checksum();

    socket.send_packet(&ip_syn).expect("Failed to send SYN");
    println!("Sent SYN");

    // 2. 等待 SYN-ACK
    let mut seq = 1001;
    let mut ack = 0;
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Timeout waiting for SYN-ACK");
        }
        let packet = socket.receive_packet().expect("Failed to receive packet");
        if packet.source_ip == dst_ip && packet.protocol == 6 {
            let tcp_reply = TcpPacket::from_bytes(packet.data).expect("Failed to parse TCP");
            if tcp_reply.destination_port == src_port
                && (tcp_reply.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK))
                    == (TCP_FLAG_SYN | TCP_FLAG_ACK)
            {
                println!("Received SYN-ACK");
                ack = tcp_reply.sequence_number + 1;
                break;
            }
        }
    }

    // 3. 发送 ACK
    let mut tcp_ack = TcpPacket::new(src_port, dst_port, Bytes::new());
    tcp_ack.flags = TCP_FLAG_ACK;
    tcp_ack.sequence_number = seq;
    tcp_ack.acknowledgment_number = ack;
    tcp_ack.update_checksum(src_ip, dst_ip);

    let mut ip_ack = Ipv4Packet::new(src_ip, dst_ip, tcp_ack.to_bytes());
    ip_ack.update_checksum();
    socket.send_packet(&ip_ack).expect("Failed to send ACK");
    println!("Sent ACK, connection established");

    // 4. 发送 HTTP GET 请求
    let http_get = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    let mut tcp_data = TcpPacket::new(
        src_port,
        dst_port,
        Bytes::copy_from_slice(http_get.as_bytes()),
    );
    tcp_data.flags = TCP_FLAG_PSH | TCP_FLAG_ACK;
    tcp_data.sequence_number = seq;
    tcp_data.acknowledgment_number = ack;
    tcp_data.update_checksum(src_ip, dst_ip);

    let mut ip_data = Ipv4Packet::new(src_ip, dst_ip, tcp_data.to_bytes());
    ip_data.update_checksum();
    socket
        .send_packet(&ip_data)
        .expect("Failed to send HTTP GET");
    println!("Sent HTTP GET");
    seq += http_get.len() as u32;

    // 5. 等待响应数据
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(10) {
            panic!("Timeout waiting for HTTP response");
        }
        let packet = socket.receive_packet().expect("Failed to receive packet");
        if packet.source_ip == dst_ip && packet.protocol == 6 {
            let tcp_reply =
                TcpPacket::from_bytes(packet.data.clone()).expect("Failed to parse TCP");
            if tcp_reply.destination_port == src_port {
                println!(
                    "Received TCP packet: flags=0x{:x}, seq={}, ack={}, len={}",
                    tcp_reply.flags,
                    tcp_reply.sequence_number,
                    tcp_reply.acknowledgment_number,
                    tcp_reply.data.len()
                );
                if tcp_reply.data.len() > 0 {
                    println!(
                        "Received HTTP Response Content ({} bytes)",
                        tcp_reply.data.len()
                    );
                    ack = tcp_reply.sequence_number + tcp_reply.data.len() as u32;
                    if (tcp_reply.flags & TCP_FLAG_FIN) != 0 {
                        ack += 1;
                    }
                    break;
                }
            }
        }
    }

    // 6. 发送 FIN 关闭连接
    let mut tcp_fin = TcpPacket::new(src_port, dst_port, Bytes::new());
    tcp_fin.flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
    tcp_fin.sequence_number = seq;
    tcp_fin.acknowledgment_number = ack;
    tcp_fin.update_checksum(src_ip, dst_ip);

    let mut ip_fin = Ipv4Packet::new(src_ip, dst_ip, tcp_fin.to_bytes());
    ip_fin.update_checksum();
    socket.send_packet(&ip_fin).expect("Failed to send FIN");
    println!("Sent FIN, connection closing");
}
