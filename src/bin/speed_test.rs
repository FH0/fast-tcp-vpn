//! 虚拟客户端和服务端速度测试
//!
//! 不使用 TUN 设备，直接生成和消费数据包，用于测试网络传输性能。
//!
//! 用法:
//!   服务端: sudo ./speed_test server [port] [duration_secs]
//!   客户端: sudo ./speed_test client <server_ip> [port] [duration_secs] [packet_size]

use fast_tcp_vpn::infrastructure::crypto::{ChaCha20Poly1305, KEY_LEN};
use fast_tcp_vpn::infrastructure::packet::TransportPacket;
use fast_tcp_vpn::infrastructure::socket::{
    get_outbound_ip, LinuxRawSocket, PacketReceiver, PacketSender, SocketError,
};
use fast_tcp_vpn::tunnel::Encapsulator;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 9000;
const DEFAULT_DURATION_SECS: u64 = 10;
const DEFAULT_PACKET_SIZE: usize = 1400;
const TEST_PSK: [u8; KEY_LEN] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

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
    println!("虚拟客户端和服务端速度测试");
    println!();
    println!("用法:");
    println!("  {} server [port] [duration_secs]                    - 启动虚拟服务端", prog);
    println!("  {} client <server_ip> [port] [duration_secs] [size] - 启动虚拟客户端", prog);
    println!();
    println!("参数:");
    println!("  port          - 端口号 (默认: {})", DEFAULT_PORT);
    println!("  duration_secs - 测试时长(秒) (默认: {})", DEFAULT_DURATION_SECS);
    println!("  size          - 数据包大小(字节) (默认: {})", DEFAULT_PACKET_SIZE);
    println!();
    println!("示例:");
    println!("  {} server 9000 30", prog);
    println!("  {} client 38.175.192.236 9000 30 1400", prog);
    println!();
    println!("注意: 需要 root 权限运行");
}

// ============================================================================
// 虚拟服务端
// ============================================================================

fn run_server(args: &[String]) {
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT);
    let duration_secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_DURATION_SECS);

    println!("=== 虚拟服务端速度测试 ===");
    println!("端口: {}", port);
    println!("测试时长: {}秒", duration_secs);
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

    // 创建解密器
    let encryptor = match ChaCha20Poly1305::new(&TEST_PSK) {
        Ok(e) => {
            println!("[OK] 加密器创建成功");
            e
        }
        Err(e) => {
            eprintln!("[ERROR] 创建加密器失败: {}", e);
            return;
        }
    };
    let encapsulator = Encapsulator::new(encryptor);

    println!("[INFO] 监听端口 {}...", port);
    println!("[INFO] Echo Server 模式: 接收数据并回显...");
    println!();

    let stats = Arc::new(ServerStats::new());
    let running = Arc::new(AtomicBool::new(true));
    let start_time = Instant::now();

    // 统计线程
    let stats_clone = stats.clone();
    let running_clone = running.clone();
    let stats_handle = thread::spawn(move || {
        let mut last_print = Instant::now();
        while running_clone.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
            if last_print.elapsed() >= Duration::from_secs(1) {
                stats_clone.print_progress();
                last_print = Instant::now();
            }
        }
    });

    // 接收并回显循环
    let mut buffer = [0u8; 65535];
    loop {
        if start_time.elapsed() >= Duration::from_secs(duration_secs) {
            println!();
            println!("[INFO] 测试时间到，停止服务");
            break;
        }

        match socket.receive_raw(&mut buffer, Some(Duration::from_millis(100))) {
            Ok(len) => {
                if len < 40 {
                    continue;
                }

                // 解析传输包
                let transport = match TransportPacket::parse(&buffer[..len]) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                // 验证端口
                if transport.outer_tcp.dst_port != port && transport.outer_tcp.src_port != port {
                    continue;
                }

                if transport.encrypted_payload.is_empty() {
                    continue;
                }

                // 解密
                let decrypted = match encapsulator.decapsulate(&transport.encrypted_payload) {
                    Ok(decrypted) => {
                        if decrypted.len() >= 20 && (decrypted[0] >> 4) == 4 {
                            decrypted
                        } else {
                            continue;
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                };

                // 记录接收统计
                stats.record_packet(len, decrypted.len());

                // 回显: 重新加密并发送回客户端
                let echo_encrypted = match encapsulator.encapsulate(&decrypted) {
                    Ok(data) => data,
                    Err(_) => continue,
                };

                // 构造回显包 (交换源和目标)
                let echo_transport = TransportPacket::new(
                    transport.outer_ip.dst_ip,
                    transport.outer_ip.src_ip,
                    transport.outer_tcp.dst_port,
                    transport.outer_tcp.src_port,
                    echo_encrypted,
                );

                let echo_bytes = echo_transport.to_bytes();

                // 发送回显
                if let Err(e) = socket.send_raw(&echo_bytes, transport.outer_ip.src_ip) {
                    eprintln!("[WARN] 回显发送失败: {:?}", e);
                }
            }
            Err(SocketError::Timeout) => continue,
            Err(e) => {
                eprintln!("[ERROR] 接收错误: {:?}", e);
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    let _ = stats_handle.join();

    println!();
    stats.print_final(start_time.elapsed());
}

// ============================================================================
// 虚拟客户端
// ============================================================================

fn run_client(args: &[String]) {
    if args.len() < 3 {
        eprintln!("用法: {} client <server_ip> [port] [duration_secs] [packet_size]", args[0]);
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
    let duration_secs: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_DURATION_SECS);
    let packet_size: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PACKET_SIZE);

    println!("=== 虚拟客户端速度测试 ===");
    println!("服务器: {}:{}", server_ip, port);
    println!("测试时长: {}秒", duration_secs);
    println!("数据包大小: {}字节", packet_size);
    println!();

    // 获取本地 IP
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

    // 创建加密器
    let encryptor = match ChaCha20Poly1305::new(&TEST_PSK) {
        Ok(e) => {
            println!("[OK] 加密器创建成功");
            e
        }
        Err(e) => {
            eprintln!("[ERROR] 创建加密器失败: {}", e);
            return;
        }
    };
    let encapsulator = Encapsulator::new(encryptor);

    println!("[INFO] Echo Client 模式: 一发一收计算往返...");
    println!();

    let stats = Arc::new(ClientStats::new());
    let running = Arc::new(AtomicBool::new(true));
    let start_time = Instant::now();

    // 统计线程
    let stats_clone = stats.clone();
    let running_clone = running.clone();
    let stats_handle = thread::spawn(move || {
        let mut last_print = Instant::now();
        while running_clone.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
            if last_print.elapsed() >= Duration::from_secs(1) {
                stats_clone.print_progress();
                last_print = Instant::now();
            }
        }
    });

    // 生成测试数据（模拟 IP 包）
    let mut test_payload = vec![0u8; packet_size];
    // 构造一个简单的 IP 头
    test_payload[0] = 0x45; // Version 4, IHL 5
    test_payload[1] = 0x00; // DSCP, ECN
    let total_len = packet_size as u16;
    test_payload[2] = (total_len >> 8) as u8;
    test_payload[3] = (total_len & 0xff) as u8;
    test_payload[9] = 0x11; // Protocol: UDP
    // 源和目标 IP (10.0.0.2 -> 10.0.0.1)
    test_payload[12..16].copy_from_slice(&[10, 0, 0, 2]);
    test_payload[16..20].copy_from_slice(&[10, 0, 0, 1]);
    // 填充随机数据
    for i in 20..packet_size {
        test_payload[i] = (i % 256) as u8;
    }

    // Echo 循环: 发送一个包，等待回显，再发送下一个
    let mut buffer = [0u8; 65535];

    loop {
        if start_time.elapsed() >= Duration::from_secs(duration_secs) {
            println!();
            println!("[INFO] 测试时间到，停止测试");
            break;
        }

        // 1. 加密并发送数据
        let encrypted = match encapsulator.encapsulate(&test_payload) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("[ERROR] 加密失败: {}", e);
                stats.record_error();
                continue;
            }
        };

        let transport = TransportPacket::new(
            local_ip,
            server_ip,
            port,
            port,
            encrypted,
        );

        let packet_bytes = transport.to_bytes();
        let send_time = Instant::now();

        if let Err(e) = socket.send_raw(&packet_bytes, server_ip) {
            eprintln!("[ERROR] 发送失败: {:?}", e);
            stats.record_error();
            continue;
        }

        // 2. 等待回显响应 (超时 1 秒)
        let timeout = Duration::from_secs(1);
        let deadline = Instant::now() + timeout;
        let mut received = false;

        while Instant::now() < deadline {
            match socket.receive_raw(&mut buffer, Some(Duration::from_millis(10))) {
                Ok(len) => {
                    if len < 40 {
                        continue;
                    }

                    // 解析回显包
                    let echo_transport = match TransportPacket::parse(&buffer[..len]) {
                        Ok(t) => t,
                        Err(_) => continue,
                    };

                    // 验证是否是我们的回显包
                    if echo_transport.outer_ip.src_ip != server_ip ||
                       echo_transport.outer_tcp.src_port != port {
                        continue;
                    }

                    if echo_transport.encrypted_payload.is_empty() {
                        continue;
                    }

                    // 解密验证
                    match encapsulator.decapsulate(&echo_transport.encrypted_payload) {
                        Ok(decrypted) => {
                            if decrypted.len() >= 20 && (decrypted[0] >> 4) == 4 {
                                // 成功接收回显
                                let rtt = send_time.elapsed();
                                stats.record_round_trip(packet_bytes.len(), test_payload.len(), rtt);
                                received = true;
                                break;
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Err(SocketError::Timeout) => continue,
                Err(e) => {
                    eprintln!("[ERROR] 接收错误: {:?}", e);
                    break;
                }
            }
        }

        if !received {
            stats.record_timeout();
        }
    }

    running.store(false, Ordering::Relaxed);
    let _ = stats_handle.join();

    println!();
    stats.print_final(start_time.elapsed());
}

// ============================================================================
// 统计结构
// ============================================================================

struct ServerStats {
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    decrypted_bytes: AtomicU64,
}

impl ServerStats {
    fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            decrypted_bytes: AtomicU64::new(0),
        }
    }

    fn record_packet(&self, raw_len: usize, decrypted_len: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(raw_len as u64, Ordering::Relaxed);
        self.decrypted_bytes.fetch_add(decrypted_len as u64, Ordering::Relaxed);
    }

    fn print_progress(&self) {
        let packets = self.packets_received.load(Ordering::Relaxed);
        let bytes = self.bytes_received.load(Ordering::Relaxed);
        let decrypted = self.decrypted_bytes.load(Ordering::Relaxed);

        print!("\r[接收] 包: {} | 原始: {:.2} MB | 解密: {:.2} MB | 速率: {:.2} Mbps",
            packets,
            bytes as f64 / 1_000_000.0,
            decrypted as f64 / 1_000_000.0,
            (bytes as f64 * 8.0) / 1_000_000.0
        );
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }

    fn print_final(&self, duration: Duration) {
        let packets = self.packets_received.load(Ordering::Relaxed);
        let bytes = self.bytes_received.load(Ordering::Relaxed);
        let decrypted = self.decrypted_bytes.load(Ordering::Relaxed);
        let secs = duration.as_secs_f64();

        println!("=== 服务端测试结果 ===");
        println!("测试时长: {:.2}秒", secs);
        println!("接收包数: {}", packets);
        println!("原始数据: {:.2} MB", bytes as f64 / 1_000_000.0);
        println!("解密数据: {:.2} MB", decrypted as f64 / 1_000_000.0);
        println!("包速率: {:.2} pps", packets as f64 / secs);
        println!("吞吐量: {:.2} Mbps (原始)", (bytes as f64 * 8.0) / secs / 1_000_000.0);
        println!("吞吐量: {:.2} Mbps (解密)", (decrypted as f64 * 8.0) / secs / 1_000_000.0);
    }
}

struct ClientStats {
    round_trips: AtomicU64,
    bytes_sent: AtomicU64,
    plaintext_bytes: AtomicU64,
    total_rtt_micros: AtomicU64,
    timeouts: AtomicU64,
    errors: AtomicU64,
}

impl ClientStats {
    fn new() -> Self {
        Self {
            round_trips: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            plaintext_bytes: AtomicU64::new(0),
            total_rtt_micros: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    fn record_round_trip(&self, raw_len: usize, plaintext_len: usize, rtt: Duration) {
        self.round_trips.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(raw_len as u64, Ordering::Relaxed);
        self.plaintext_bytes.fetch_add(plaintext_len as u64, Ordering::Relaxed);
        self.total_rtt_micros.fetch_add(rtt.as_micros() as u64, Ordering::Relaxed);
    }

    fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn print_progress(&self) {
        let round_trips = self.round_trips.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let total_rtt = self.total_rtt_micros.load(Ordering::Relaxed);
        let timeouts = self.timeouts.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);

        let avg_rtt_ms = if round_trips > 0 {
            (total_rtt as f64 / round_trips as f64) / 1000.0
        } else {
            0.0
        };

        print!("\r[往返] 次数: {} | 平均RTT: {:.2}ms | 超时: {} | 错误: {} | 数据: {:.2} MB",
            round_trips,
            avg_rtt_ms,
            timeouts,
            errors,
            bytes as f64 / 1_000_000.0
        );
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }

    fn print_final(&self, duration: Duration) {
        let round_trips = self.round_trips.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let plaintext = self.plaintext_bytes.load(Ordering::Relaxed);
        let total_rtt = self.total_rtt_micros.load(Ordering::Relaxed);
        let timeouts = self.timeouts.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let secs = duration.as_secs_f64();

        let avg_rtt_ms = if round_trips > 0 {
            (total_rtt as f64 / round_trips as f64) / 1000.0
        } else {
            0.0
        };

        let success_rate = if round_trips + timeouts + errors > 0 {
            (round_trips as f64 / (round_trips + timeouts + errors) as f64) * 100.0
        } else {
            0.0
        };

        println!("=== 客户端测试结果 ===");
        println!("测试时长: {:.2}秒", secs);
        println!("成功往返: {}", round_trips);
        println!("超时次数: {}", timeouts);
        println!("发送错误: {}", errors);
        println!("成功率: {:.2}%", success_rate);
        println!("平均RTT: {:.2}ms", avg_rtt_ms);
        println!("往返速率: {:.2} 次/秒", round_trips as f64 / secs);
        println!("原始数据: {:.2} MB", bytes as f64 / 1_000_000.0);
        println!("明文数据: {:.2} MB", plaintext as f64 / 1_000_000.0);
        println!("吞吐量: {:.2} Mbps (原始)", (bytes as f64 * 8.0) / secs / 1_000_000.0);
        println!("吞吐量: {:.2} Mbps (明文)", (plaintext as f64 * 8.0) / secs / 1_000_000.0);
        if plaintext > 0 {
            println!("加密开销: {:.2}%", ((bytes - plaintext) as f64 / plaintext as f64) * 100.0);
        }
    }
}
