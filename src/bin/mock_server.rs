//! Mock Server for Speed Testing
//!
//! A simple TCP server that:
//! - Accepts connections on a specified port
//! - Receives data and measures throughput
//! - Sends data back for bidirectional testing

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 9999;
const BUFFER_SIZE: usize = 64 * 1024; // 64KB buffer
const STATS_INTERVAL: Duration = Duration::from_secs(1);

fn main() {
    let port = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    println!("=== Mock Speed Test Server ===");
    println!("Listening on 0.0.0.0:{}", port);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).expect("Failed to bind");

    // Global stats
    let total_bytes_received = Arc::new(AtomicU64::new(0));
    let total_bytes_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Stats printer thread
    let stats_received = total_bytes_received.clone();
    let stats_sent = total_bytes_sent.clone();
    let stats_running = running.clone();
    thread::spawn(move || {
        let mut last_received = 0u64;
        let mut last_sent = 0u64;
        let start = Instant::now();

        while stats_running.load(Ordering::Relaxed) {
            thread::sleep(STATS_INTERVAL);

            let current_received = stats_received.load(Ordering::Relaxed);
            let current_sent = stats_sent.load(Ordering::Relaxed);

            let recv_speed = (current_received - last_received) as f64 / 1024.0 / 1024.0;
            let send_speed = (current_sent - last_sent) as f64 / 1024.0 / 1024.0;

            let elapsed = start.elapsed().as_secs_f64();
            let avg_recv = current_received as f64 / 1024.0 / 1024.0 / elapsed;
            let avg_send = current_sent as f64 / 1024.0 / 1024.0 / elapsed;

            println!(
                "[{:.1}s] Recv: {:.2} MB/s (avg: {:.2}), Send: {:.2} MB/s (avg: {:.2}), Total: {:.2} MB recv, {:.2} MB sent",
                elapsed,
                recv_speed,
                avg_recv,
                send_speed,
                avg_send,
                current_received as f64 / 1024.0 / 1024.0,
                current_sent as f64 / 1024.0 / 1024.0
            );

            last_received = current_received;
            last_sent = current_sent;
        }
    });

    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().ok();
                println!("New connection from: {:?}", peer);

                let bytes_received = total_bytes_received.clone();
                let bytes_sent = total_bytes_sent.clone();

                thread::spawn(move || {
                    handle_client(stream, bytes_received, bytes_sent);
                    println!("Connection closed: {:?}", peer);
                });
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    bytes_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
) {
    let mut buffer = vec![0u8; BUFFER_SIZE];

    // Set socket options for performance
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));

    // Read mode command (first byte)
    // 'd' = download (server sends data to client)
    // 'u' = upload (client sends data to server)
    // 'b' = bidirectional (echo mode)
    let mut mode_buf = [0u8; 1];
    if stream.read_exact(&mut mode_buf).is_err() {
        return;
    }

    let mode = mode_buf[0] as char;
    println!("Mode: {}", mode);

    match mode {
        'd' => {
            // Download mode: send data to client
            let data = vec![0xABu8; BUFFER_SIZE];
            loop {
                match stream.write(&data) {
                    Ok(n) if n > 0 => {
                        bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    _ => break,
                }
            }
        }
        'u' => {
            // Upload mode: receive data from client
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
        }
        'b' => {
            // Bidirectional mode: echo back
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                        if stream.write_all(&buffer[..n]).is_ok() {
                            bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
        }
    }
}
