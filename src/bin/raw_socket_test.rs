//! 完整的 TCP 流程测试
//!
//! 实现完整的 TCP 三次握手、双向数据传输和四次挥手。
//!
//! 用法:
//!   服务端: sudo ./raw_socket_test server [port]
//!   客户端: sudo ./raw_socket_test client <server_ip> [port]

use fast_tcp_vpn::infrastructure::packet::{Packet, TcpFlags};
use fast_tcp_vpn::infrastructure::socket::{
    get_outbound_ip, LinuxRawSocket, PacketReceiver, PacketSender, SocketError,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 54321;
const TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match mode {
        "server" => run_server(&args),
        "client" => run_client(&args),
        _ => print_usage(&args[0]),
    }
}

fn print_usage(prog: &str) {
    println!("完整的 TCP 流程测试");
    println!();
    println!("用法:");
    println!("  {} server [port]            - 启动服务端", prog);
    println!("  {} client <server_ip> [port] - 启动客户端", prog);
    println!();
    println!("示例:");
    println!("  {} server 54321", prog);
    println!("  {} client 38.175.192.236 54321", prog);
    println!();
    println!("注意: 需要 root 权限运行");
}

// ============================================================================
// 服务端
// ============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerState {
    Listen,
    SynReceived,
    Established,
    FinWait,
    Closed,
}

#[allow(dead_code)]
struct ServerConnection {
    state: ServerState,
    client_ip: Ipv4Addr,
    client_port: u16,
    server_seq: u32,
    client_seq: u32,
    last_activity: Instant,
}

fn run_server(args: &[String]) {
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT);

    println!("=== TCP 服务端 ===");
    println!("端口: {}", port);
    println!();

    let socket = match LinuxRawSocket::new() {
        Ok(s) => {
            println!("[OK] Raw socket 创建成功");
            s
        }
        Err(SocketError::PermissionDenied) => {
            eprintln!("[ERROR] 权限不足，请使用 sudo 运行");
            return;
        }
        Err(e) => {
            eprintln!("[ERROR] 创建 socket 失败: {:?}", e);
            return;
        }
    };

    println!("[INFO] 监听端口 {}...", port);
    println!();

    let mut connections: HashMap<(Ipv4Addr, u16), ServerConnection> = HashMap::new();

    loop {
        match socket.receive(Some(Duration::from_millis(100))) {
            Ok(packet) => {
                if packet.tcp_header.dst_port != port {
                    continue;
                }

                let key = (packet.ip_header.src_ip, packet.tcp_header.src_port);
                let conn = connections.get_mut(&key);

                // 处理 SYN - 三次握手第一步
                if packet.tcp_header.flags.contains(TcpFlags::SYN)
                    && !packet.tcp_header.flags.contains(TcpFlags::ACK) {

                    println!(
                        "[1/6] 收到 SYN from {}:{} seq={}",
                        packet.ip_header.src_ip,
                        packet.tcp_header.src_port,
                        packet.tcp_header.seq
                    );

                    let server_seq = 2000u32;
                    let client_seq = packet.tcp_header.seq;

                    // 发送 SYN+ACK - 三次握手第二步
                    let mut reply = Packet::new(
                        packet.ip_header.dst_ip,
                        packet.ip_header.src_ip,
                        packet.tcp_header.dst_port,
                        packet.tcp_header.src_port,
                        Vec::new(),
                    );
                    reply.tcp_header.flags = TcpFlags::SYN | TcpFlags::ACK;
                    reply.tcp_header.seq = server_seq;
                    reply.tcp_header.ack = client_seq.wrapping_add(1);
                    reply.tcp_header.window = 65535;

                    if socket.send(&reply).is_ok() {
                        println!(
                            "[2/6] 发送 SYN+ACK to {}:{} seq={} ack={}",
                            reply.ip_header.dst_ip,
                            reply.tcp_header.dst_port,
                            server_seq,
                            reply.tcp_header.ack
                        );

                        connections.insert(
                            key,
                            ServerConnection {
                                state: ServerState::SynReceived,
                                client_ip: packet.ip_header.src_ip,
                                client_port: packet.tcp_header.src_port,
                                server_seq: server_seq.wrapping_add(1),
                                client_seq: client_seq.wrapping_add(1),
                                last_activity: Instant::now(),
                            },
                        );
                    }
                    continue;
                }

                // 处理 ACK - 三次握手第三步
                if let Some(conn) = conn {
                    if conn.state == ServerState::SynReceived
                        && packet.tcp_header.flags.contains(TcpFlags::ACK)
                        && !packet.tcp_header.flags.contains(TcpFlags::SYN)
                        && packet.tcp_header.ack == conn.server_seq
                    {
                        println!(
                            "[3/6] 收到 ACK from {}:{} - 连接建立",
                            packet.ip_header.src_ip, packet.tcp_header.src_port
                        );
                        conn.state = ServerState::Established;
                        conn.last_activity = Instant::now();
                        continue;
                    }

                    // 处理数据包
                    if conn.state == ServerState::Established
                        && packet.tcp_header.flags.contains(TcpFlags::ACK)
                        && !packet.payload.is_empty()
                    {
                        let data = String::from_utf8_lossy(&packet.payload);
                        println!(
                            "[4/6] 收到数据 from {}:{} len={} data=\"{}\"",
                            packet.ip_header.src_ip,
                            packet.tcp_header.src_port,
                            packet.payload.len(),
                            data
                        );

                        conn.client_seq = packet.tcp_header.seq.wrapping_add(packet.payload.len() as u32);

                        // 发送 ACK
                        let mut ack_reply = Packet::new(
                            packet.ip_header.dst_ip,
                            packet.ip_header.src_ip,
                            packet.tcp_header.dst_port,
                            packet.tcp_header.src_port,
                            Vec::new(),
                        );
                        ack_reply.tcp_header.flags = TcpFlags::ACK;
                        ack_reply.tcp_header.seq = conn.server_seq;
                        ack_reply.tcp_header.ack = conn.client_seq;
                        ack_reply.tcp_header.window = 65535;

                        let _ = socket.send(&ack_reply);

                        // 发送响应数据
                        let response = b"Hello from server!";
                        let mut data_reply = Packet::new(
                            packet.ip_header.dst_ip,
                            packet.ip_header.src_ip,
                            packet.tcp_header.dst_port,
                            packet.tcp_header.src_port,
                            response.to_vec(),
                        );
                        data_reply.tcp_header.flags = TcpFlags::ACK;
                        data_reply.tcp_header.seq = conn.server_seq;
                        data_reply.tcp_header.ack = conn.client_seq;
                        data_reply.tcp_header.window = 65535;

                        if socket.send(&data_reply).is_ok() {
                            println!(
                                "[5/6] 发送数据 to {}:{} len={} data=\"{}\"",
                                data_reply.ip_header.dst_ip,
                                data_reply.tcp_header.dst_port,
                                response.len(),
                                String::from_utf8_lossy(response)
                            );
                            conn.server_seq = conn.server_seq.wrapping_add(response.len() as u32);
                        }

                        conn.last_activity = Instant::now();
                        continue;
                    }

                    // 处理 FIN - 四次挥手第一步（客户端发起）
                    if (conn.state == ServerState::Established || conn.state == ServerState::SynReceived)
                        && packet.tcp_header.flags.contains(TcpFlags::FIN)
                    {
                        println!(
                            "[6/6] 收到 FIN from {}:{} - 开始关闭连接",
                            packet.ip_header.src_ip, packet.tcp_header.src_port
                        );

                        conn.client_seq = packet.tcp_header.seq.wrapping_add(1);

                        // 发送 ACK - 四次挥手第二步
                        let mut ack_reply = Packet::new(
                            packet.ip_header.dst_ip,
                            packet.ip_header.src_ip,
                            packet.tcp_header.dst_port,
                            packet.tcp_header.src_port,
                            Vec::new(),
                        );
                        ack_reply.tcp_header.flags = TcpFlags::ACK;
                        ack_reply.tcp_header.seq = conn.server_seq;
                        ack_reply.tcp_header.ack = conn.client_seq;
                        ack_reply.tcp_header.window = 65535;

                        if socket.send(&ack_reply).is_ok() {
                            println!(
                                "[6/6] 发送 ACK to {}:{}",
                                ack_reply.ip_header.dst_ip, ack_reply.tcp_header.dst_port
                            );
                        }

                        // 发送 FIN+ACK - 四次挥手第三步
                        let mut fin_reply = Packet::new(
                            packet.ip_header.dst_ip,
                            packet.ip_header.src_ip,
                            packet.tcp_header.dst_port,
                            packet.tcp_header.src_port,
                            Vec::new(),
                        );
                        fin_reply.tcp_header.flags = TcpFlags::FIN | TcpFlags::ACK;
                        fin_reply.tcp_header.seq = conn.server_seq;
                        fin_reply.tcp_header.ack = conn.client_seq;
                        fin_reply.tcp_header.window = 65535;

                        if socket.send(&fin_reply).is_ok() {
                            println!(
                                "[6/6] 发送 FIN+ACK to {}:{}",
                                fin_reply.ip_header.dst_ip, fin_reply.tcp_header.dst_port
                            );
                            conn.state = ServerState::FinWait;
                            conn.server_seq = conn.server_seq.wrapping_add(1);
                        }

                        continue;
                    }

                    // 处理最后的 ACK - 四次挥手第四步
                    if conn.state == ServerState::FinWait
                        && packet.tcp_header.flags.contains(TcpFlags::ACK)
                        && packet.tcp_header.ack == conn.server_seq
                    {
                        println!(
                            "[6/6] 收到最后的 ACK from {}:{} - 连接关闭",
                            packet.ip_header.src_ip, packet.tcp_header.src_port
                        );
                        connections.remove(&key);
                        println!();
                        println!("=== 连接完成，等待新连接 ===");
                        println!();
                        continue;
                    }
                }
            }
            Err(SocketError::Timeout) => {
                // 清理超时连接
                let now = Instant::now();
                connections.retain(|_, conn| now.duration_since(conn.last_activity) < Duration::from_secs(30));
            }
            Err(e) => {
                eprintln!("[ERROR] 接收错误: {:?}", e);
            }
        }
    }
}

// ============================================================================
// 客户端
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
}

fn run_client(args: &[String]) {
    if args.len() < 3 {
        eprintln!("用法: {} client <server_ip> [port]", args[0]);
        return;
    }

    let server_ip: Ipv4Addr = match args[2].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("[ERROR] 无效的 IP 地址: {}", args[2]);
            return;
        }
    };

    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT);

    println!("=== TCP 客户端 ===");
    println!("服务器: {}:{}", server_ip, port);
    println!();

    let local_ip = match get_outbound_ip(server_ip) {
        Ok(ip) => {
            println!("[OK] 本地 IP: {}", ip);
            ip
        }
        Err(e) => {
            eprintln!("[ERROR] 获取本地 IP 失败: {:?}", e);
            return;
        }
    };

    let socket = match LinuxRawSocket::new() {
        Ok(s) => {
            println!("[OK] Raw socket 创建成功");
            s
        }
        Err(SocketError::PermissionDenied) => {
            eprintln!("[ERROR] 权限不足，请使用 sudo 运行");
            return;
        }
        Err(e) => {
            eprintln!("[ERROR] 创建 socket 失败: {:?}", e);
            return;
        }
    };

    println!();
    println!("开始 TCP 连接...");
    println!();

    let local_port: u16 = 44444;
    let mut state = ClientState::Closed;
    let mut client_seq = 1000u32;
    let mut server_seq = 0u32;

    // ========================================================================
    // 第一步：发送 SYN（三次握手第一步）
    // ========================================================================
    println!("[1/6] 发送 SYN to {}:{} seq={}", server_ip, port, client_seq);

    let mut syn_packet = Packet::new(local_ip, server_ip, local_port, port, Vec::new());
    syn_packet.tcp_header.flags = TcpFlags::SYN;
    syn_packet.tcp_header.seq = client_seq;
    syn_packet.tcp_header.window = 65535;

    if socket.send(&syn_packet).is_err() {
        eprintln!("[ERROR] 发送 SYN 失败");
        return;
    }

    state = ClientState::SynSent;
    let syn_time = Instant::now();

    // ========================================================================
    // 第二步：接收 SYN+ACK（三次握手第二步）
    // ========================================================================
    let mut syn_ack_received = false;
    while syn_time.elapsed() < TIMEOUT && !syn_ack_received {
        match socket.receive(Some(Duration::from_millis(100))) {
            Ok(packet) => {
                if packet.ip_header.src_ip == server_ip
                    && packet.tcp_header.src_port == port
                    && packet.tcp_header.dst_port == local_port
                    && packet.tcp_header.flags.contains(TcpFlags::SYN)
                    && packet.tcp_header.flags.contains(TcpFlags::ACK)
                    && packet.tcp_header.ack == client_seq.wrapping_add(1)
                {
                    server_seq = packet.tcp_header.seq;
                    client_seq = client_seq.wrapping_add(1);

                    println!(
                        "[2/6] 收到 SYN+ACK from {}:{} seq={} ack={}",
                        packet.ip_header.src_ip,
                        packet.tcp_header.src_port,
                        server_seq,
                        packet.tcp_header.ack
                    );

                    syn_ack_received = true;
                }
            }
            Err(SocketError::Timeout) => continue,
            Err(e) => {
                eprintln!("[ERROR] 接收错误: {:?}", e);
            }
        }
    }

    if !syn_ack_received {
        eprintln!("[ERROR] 未收到 SYN+ACK，连接超时");
        return;
    }

    // ========================================================================
    // 第三步：发送 ACK（三次握手第三步）
    // ========================================================================
    println!("[3/6] 发送 ACK to {}:{} ack={}", server_ip, port, server_seq.wrapping_add(1));

    let mut ack_packet = Packet::new(local_ip, server_ip, local_port, port, Vec::new());
    ack_packet.tcp_header.flags = TcpFlags::ACK;
    ack_packet.tcp_header.seq = client_seq;
    ack_packet.tcp_header.ack = server_seq.wrapping_add(1);
    ack_packet.tcp_header.window = 65535;

    if socket.send(&ack_packet).is_err() {
        eprintln!("[ERROR] 发送 ACK 失败");
        return;
    }

    state = ClientState::Established;
    server_seq = server_seq.wrapping_add(1);

    println!("[3/6] 连接建立成功！");
    println!();

    std::thread::sleep(Duration::from_millis(100));

    // ========================================================================
    // 第四步：发送数据
    // ========================================================================
    let message = b"Hello from client!";
    println!("[4/6] 发送数据 to {}:{} len={} data=\"{}\"",
        server_ip, port, message.len(), String::from_utf8_lossy(message));

    let mut data_packet = Packet::new(local_ip, server_ip, local_port, port, message.to_vec());
    data_packet.tcp_header.flags = TcpFlags::ACK;
    data_packet.tcp_header.seq = client_seq;
    data_packet.tcp_header.ack = server_seq;
    data_packet.tcp_header.window = 65535;

    if socket.send(&data_packet).is_err() {
        eprintln!("[ERROR] 发送数据失败");
        return;
    }

    client_seq = client_seq.wrapping_add(message.len() as u32);

    // ========================================================================
    // 第五步：接收服务器响应数据
    // ========================================================================
    let data_time = Instant::now();
    let mut data_received = false;

    while data_time.elapsed() < TIMEOUT && !data_received {
        match socket.receive(Some(Duration::from_millis(100))) {
            Ok(packet) => {
                if packet.ip_header.src_ip == server_ip
                    && packet.tcp_header.src_port == port
                    && packet.tcp_header.dst_port == local_port
                    && !packet.payload.is_empty()
                {
                    let response = String::from_utf8_lossy(&packet.payload);
                    println!(
                        "[5/6] 收到数据 from {}:{} len={} data=\"{}\"",
                        packet.ip_header.src_ip,
                        packet.tcp_header.src_port,
                        packet.payload.len(),
                        response
                    );

                    server_seq = packet.tcp_header.seq.wrapping_add(packet.payload.len() as u32);
                    data_received = true;

                    // 发送 ACK 确认收到数据
                    let mut ack_data = Packet::new(local_ip, server_ip, local_port, port, Vec::new());
                    ack_data.tcp_header.flags = TcpFlags::ACK;
                    ack_data.tcp_header.seq = client_seq;
                    ack_data.tcp_header.ack = server_seq;
                    ack_data.tcp_header.window = 65535;
                    let _ = socket.send(&ack_data);
                }
            }
            Err(SocketError::Timeout) => continue,
            Err(e) => {
                eprintln!("[ERROR] 接收错误: {:?}", e);
            }
        }
    }

    if !data_received {
        println!("[WARN] 未收到服务器响应数据");
    }

    println!();
    std::thread::sleep(Duration::from_millis(200));

    // ========================================================================
    // 第六步：四次挥手 - 发送 FIN（第一步）
    // ========================================================================
    println!("[6/6] 发送 FIN to {}:{} - 开始关闭连接", server_ip, port);

    let mut fin_packet = Packet::new(local_ip, server_ip, local_port, port, Vec::new());
    fin_packet.tcp_header.flags = TcpFlags::FIN | TcpFlags::ACK;
    fin_packet.tcp_header.seq = client_seq;
    fin_packet.tcp_header.ack = server_seq;
    fin_packet.tcp_header.window = 65535;

    if socket.send(&fin_packet).is_err() {
        eprintln!("[ERROR] 发送 FIN 失败");
        return;
    }

    state = ClientState::FinWait1;
    client_seq = client_seq.wrapping_add(1);

    // ========================================================================
    // 接收服务器的 ACK（四次挥手第二步）
    // ========================================================================
    let fin_time = Instant::now();
    let mut ack_received = false;
    let mut fin_ack_received = false;

    while fin_time.elapsed() < TIMEOUT {
        match socket.receive(Some(Duration::from_millis(100))) {
            Ok(packet) => {
                if packet.ip_header.src_ip == server_ip
                    && packet.tcp_header.src_port == port
                    && packet.tcp_header.dst_port == local_port
                {
                    // 收到 ACK
                    if !ack_received
                        && packet.tcp_header.flags.contains(TcpFlags::ACK)
                        && !packet.tcp_header.flags.contains(TcpFlags::FIN)
                        && packet.tcp_header.ack == client_seq
                    {
                        println!("[6/6] 收到 ACK from {}:{}", packet.ip_header.src_ip, packet.tcp_header.src_port);
                        ack_received = true;
                        state = ClientState::FinWait2;
                    }

                    // 收到 FIN+ACK（四次挥手第三步）
                    if packet.tcp_header.flags.contains(TcpFlags::FIN)
                        && packet.tcp_header.flags.contains(TcpFlags::ACK)
                    {
                        println!("[6/6] 收到 FIN+ACK from {}:{}", packet.ip_header.src_ip, packet.tcp_header.src_port);
                        server_seq = packet.tcp_header.seq.wrapping_add(1);
                        fin_ack_received = true;

                        // 发送最后的 ACK（四次挥手第四步）
                        let mut final_ack = Packet::new(local_ip, server_ip, local_port, port, Vec::new());
                        final_ack.tcp_header.flags = TcpFlags::ACK;
                        final_ack.tcp_header.seq = client_seq;
                        final_ack.tcp_header.ack = server_seq;
                        final_ack.tcp_header.window = 65535;

                        if socket.send(&final_ack).is_ok() {
                            println!("[6/6] 发送最后的 ACK to {}:{}", server_ip, port);
                            state = ClientState::TimeWait;
                        }
                        break;
                    }
                }
            }
            Err(SocketError::Timeout) => continue,
            Err(e) => {
                eprintln!("[ERROR] 接收错误: {:?}", e);
            }
        }
    }

    if fin_ack_received {
        println!();
        println!("=== 连接正常关闭 ===");
        println!("状态: {:?}", state);
    } else {
        println!();
        println!("=== 连接关闭（部分完成）===");
        println!("状态: {:?}", state);
    }
}

