//! Raw Socket 物理层测试
//!
//! 测试 raw socket 在客户端和服务端之间的双向通信能力。
//!
//! 用法:
//!   服务端: sudo ./raw_socket_test server [port]
//!   客户端: sudo ./raw_socket_test client <server_ip> [port] [count]

use fast_tcp_vpn::infrastructure::packet::{Packet, TcpFlags};
use fast_tcp_vpn::infrastructure::socket::{
    get_outbound_ip, LinuxRawSocket, PacketReceiver, PacketSender, SocketError,
};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 54321;

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
    println!("Raw Socket 物理层测试");
    println!();
    println!("用法:");
    println!("  {} server [port]                      - 启动服务端", prog);
    println!("  {} client <server_ip> [port] [count]  - 启动客户端", prog);
    println!();
    println!("示例:");
    println!("  {} server 54321", prog);
    println!("  {} client 38.175.192.236 54321 10", prog);
    println!();
    println!("注意: 需要 root 权限运行");
}

// ============================================================================
// 服务端
// ============================================================================

fn run_server(args: &[String]) {
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT);

    println!("=== Raw Socket 服务端 ===");
    println!("端口: {}", port);
    println!();

    // 创建 raw socket
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

    let mut stats = Stats::new();

    loop {
        match socket.receive(Some(Duration::from_secs(1))) {
            Ok(packet) => {
                if packet.tcp_header.dst_port != port {
                    continue;
                }

                // 只处理 SYN 包
                if !packet.tcp_header.flags.contains(TcpFlags::SYN) {
                    continue;
                }

                stats.packets_received += 1;
                stats.bytes_received += 40;

                let seq_num = packet.tcp_header.seq;

                println!(
                    "[RECV #{}] {}:{} -> seq={}",
                    stats.packets_received,
                    packet.ip_header.src_ip,
                    packet.tcp_header.src_port,
                    seq_num
                );

                // 发送 SYN+ACK 回复
                let mut reply = Packet::new(
                    packet.ip_header.dst_ip,
                    packet.ip_header.src_ip,
                    packet.tcp_header.dst_port,
                    packet.tcp_header.src_port,
                    Vec::new(),
                );
                reply.tcp_header.flags = TcpFlags::SYN | TcpFlags::ACK;
                reply.tcp_header.seq = 1000;
                reply.tcp_header.ack = seq_num.wrapping_add(1);
                reply.tcp_header.window = 65535;

                match socket.send(&reply) {
                    Ok(n) => {
                        stats.packets_sent += 1;
                        stats.bytes_sent += n as u64;
                        println!(
                            "[SEND] -> {}:{} ack={}",
                            reply.ip_header.dst_ip,
                            reply.tcp_header.dst_port,
                            reply.tcp_header.ack
                        );
                    }
                    Err(e) => {
                        eprintln!("[ERROR] 发送失败: {:?}", e);
                    }
                }

                if stats.packets_received % 10 == 0 {
                    stats.print();
                }
            }
            Err(SocketError::Timeout) => continue,
            Err(e) => {
                eprintln!("[ERROR] 接收错误: {:?}", e);
            }
        }
    }
}

// ============================================================================
// 客户端
// ============================================================================

fn run_client(args: &[String]) {
    if args.len() < 3 {
        eprintln!("用法: {} client <server_ip> [port] [count]", args[0]);
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
    let count: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(10);

    println!("=== Raw Socket 客户端 ===");
    println!("服务器: {}:{}", server_ip, port);
    println!("发送数量: {}", count);
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
    println!("开始测试...");
    println!();

    let local_port: u16 = 44444;
    let mut stats = Stats::new();
    let mut success_count = 0u32;
    let start_time = Instant::now();

    for i in 0..count {
        let seq_num = 1000 + i;

        // 发送 SYN 包
        let mut packet = Packet::new(local_ip, server_ip, local_port, port, Vec::new());
        packet.tcp_header.flags = TcpFlags::SYN;
        packet.tcp_header.seq = seq_num;
        packet.tcp_header.window = 65535;

        let send_time = Instant::now();

        match socket.send(&packet) {
            Ok(n) => {
                stats.packets_sent += 1;
                stats.bytes_sent += n as u64;
            }
            Err(e) => {
                eprintln!("[ERROR] 发送 #{} 失败: {:?}", i, e);
                continue;
            }
        }

        // 等待回复
        let timeout = Duration::from_secs(2);
        let mut received = false;

        while send_time.elapsed() < timeout {
            match socket.receive(Some(Duration::from_millis(100))) {
                Ok(reply) => {
                    if reply.ip_header.src_ip == server_ip
                        && reply.tcp_header.src_port == port
                        && reply.tcp_header.flags.contains(TcpFlags::SYN)
                        && reply.tcp_header.flags.contains(TcpFlags::ACK)
                        && reply.tcp_header.ack == seq_num.wrapping_add(1)
                    {
                        let rtt = send_time.elapsed();
                        stats.packets_received += 1;
                        stats.bytes_received += 40;
                        stats.total_rtt_ms += rtt.as_millis() as u64;
                        success_count += 1;
                        received = true;

                        println!(
                            "[{}/{}] seq={} -> ack={} RTT={:.2}ms",
                            success_count,
                            count,
                            seq_num,
                            reply.tcp_header.ack,
                            rtt.as_secs_f64() * 1000.0
                        );
                        break;
                    }
                }
                Err(SocketError::Timeout) => continue,
                Err(_) => continue,
            }
        }

        if !received {
            println!("[{}/{}] seq={} 超时", i + 1, count, seq_num);
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let total_time = start_time.elapsed();

    println!();
    println!("=== 测试结果 ===");
    println!("发送: {} 包", stats.packets_sent);
    println!("接收: {} 包", stats.packets_received);
    println!(
        "成功率: {:.1}%",
        (success_count as f64 / count as f64) * 100.0
    );
    if stats.packets_received > 0 {
        println!(
            "平均 RTT: {:.2}ms",
            stats.total_rtt_ms as f64 / stats.packets_received as f64
        );
    }
    println!("总耗时: {:.2}s", total_time.as_secs_f64());
}

// ============================================================================
// 统计
// ============================================================================

struct Stats {
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    total_rtt_ms: u64,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            total_rtt_ms: 0,
            start_time: Instant::now(),
        }
    }

    fn print(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        println!(
            "[STATS] {:.1}s | 发送: {} 包 ({:.1} KB) | 接收: {} 包 ({:.1} KB)",
            elapsed,
            self.packets_sent,
            self.bytes_sent as f64 / 1024.0,
            self.packets_received,
            self.bytes_received as f64 / 1024.0
        );
    }
}
