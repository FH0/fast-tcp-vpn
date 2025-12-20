//! Mock Client for Speed Testing
//!
//! A simple TCP client that:
//! - Connects to the mock server
//! - Performs download/upload/bidirectional speed tests
//! - Reports throughput statistics

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 9999;
const BUFFER_SIZE: usize = 64 * 1024; // 64KB buffer
const DEFAULT_DURATION: u64 = 10; // 10 seconds test

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <server_ip> [port] [mode] [duration_secs]", args[0]);
        println!("  mode: d=download, u=upload, b=bidirectional (default: d)");
        println!("  duration_secs: test duration in seconds (default: 10)");
        println!();
        println!("Examples:");
        println!("  {} 38.175.192.236          # Download test", args[0]);
        println!("  {} 38.175.192.236 9999 u   # Upload test", args[0]);
        println!("  {} 38.175.192.236 9999 b 30 # Bidirectional, 30s", args[0]);
        return;
    }

    let server_ip = &args[1];
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT);
    let mode = args.get(3).map(|s| s.chars().next().unwrap_or('d')).unwrap_or('d');
    let duration_secs: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_DURATION);

    let mode_name = match mode {
        'd' => "Download",
        'u' => "Upload",
        'b' => "Bidirectional",
        _ => "Unknown",
    };

    println!("=== Mock Speed Test Client ===");
    println!("Server: {}:{}", server_ip, port);
    println!("Mode: {} ({})", mode, mode_name);
    println!("Duration: {} seconds", duration_secs);
    println!();

    let addr = format!("{}:{}", server_ip, port);
    println!("Connecting to {}...", addr);

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return;
        }
    };

    println!("Connected!");

    // Set socket options
    let _ = stream.set_nodelay(true);

    // Send mode
    if stream.write_all(&[mode as u8]).is_err() {
        eprintln!("Failed to send mode");
        return;
    }

    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let start = Instant::now();
    let test_duration = Duration::from_secs(duration_secs);

    // Stats printer thread
    let stats_sent = bytes_sent.clone();
    let stats_received = bytes_received.clone();
    let stats_running = running.clone();
    let stats_handle = thread::spawn(move || {
        let mut last_sent = 0u64;
        let mut last_received = 0u64;
        let stats_start = Instant::now();

        while stats_running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            let current_sent = stats_sent.load(Ordering::Relaxed);
            let current_received = stats_received.load(Ordering::Relaxed);

            let send_speed = (current_sent - last_sent) as f64 / 1024.0 / 1024.0;
            let recv_speed = (current_received - last_received) as f64 / 1024.0 / 1024.0;

            let elapsed = stats_start.elapsed().as_secs_f64();

            println!(
                "[{:.1}s] Upload: {:.2} MB/s, Download: {:.2} MB/s",
                elapsed, send_speed, recv_speed
            );

            last_sent = current_sent;
            last_received = current_received;
        }
    });

    match mode {
        'd' => {
            // Download mode: receive data from server
            let mut buffer = vec![0u8; BUFFER_SIZE];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

            while start.elapsed() < test_duration {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            eprintln!("Read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        'u' => {
            // Upload mode: send data to server
            let data = vec![0xCDu8; BUFFER_SIZE];

            while start.elapsed() < test_duration {
                match stream.write(&data) {
                    Ok(n) if n > 0 => {
                        bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    _ => break,
                }
            }
        }
        'b' => {
            // Bidirectional mode
            let mut read_stream = stream.try_clone().expect("Failed to clone stream");
            let write_stream = stream;

            let recv_bytes = bytes_received.clone();
            let recv_running = running.clone();

            // Reader thread
            let reader_handle = thread::spawn(move || {
                let mut buffer = vec![0u8; BUFFER_SIZE];
                let _ = read_stream.set_read_timeout(Some(Duration::from_millis(100)));

                while recv_running.load(Ordering::Relaxed) {
                    match read_stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            recv_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock
                                && e.kind() != std::io::ErrorKind::TimedOut
                            {
                                break;
                            }
                        }
                    }
                }
            });

            // Writer (main thread)
            let data = vec![0xCDu8; BUFFER_SIZE];
            let mut write_stream = write_stream;

            while start.elapsed() < test_duration {
                match write_stream.write(&data) {
                    Ok(n) if n > 0 => {
                        bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    _ => break,
                }
            }

            running.store(false, Ordering::Relaxed);
            let _ = reader_handle.join();
        }
        _ => {}
    }

    running.store(false, Ordering::Relaxed);
    let _ = stats_handle.join();

    // Final statistics
    let elapsed = start.elapsed().as_secs_f64();
    let total_sent = bytes_sent.load(Ordering::Relaxed);
    let total_received = bytes_received.load(Ordering::Relaxed);

    println!();
    println!("=== Test Results ===");
    println!("Duration: {:.2} seconds", elapsed);
    println!();
    println!("Upload:");
    println!("  Total: {:.2} MB", total_sent as f64 / 1024.0 / 1024.0);
    println!("  Speed: {:.2} MB/s", total_sent as f64 / 1024.0 / 1024.0 / elapsed);
    println!("  Speed: {:.2} Mbps", total_sent as f64 * 8.0 / 1000.0 / 1000.0 / elapsed);
    println!();
    println!("Download:");
    println!("  Total: {:.2} MB", total_received as f64 / 1024.0 / 1024.0);
    println!("  Speed: {:.2} MB/s", total_received as f64 / 1024.0 / 1024.0 / elapsed);
    println!("  Speed: {:.2} Mbps", total_received as f64 * 8.0 / 1000.0 / 1000.0 / elapsed);
}
