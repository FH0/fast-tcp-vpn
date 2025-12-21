use fast_tcp_vpn::domain::stack::Stack;
use std::io::{Read, Write};

#[test]
fn test_stack_http_request() {
    // 注意：此测试需要 root 权限和外部网络访问。
    // 如果没有权限，该测试应当被跳过或预期失败。
    let interface = "eth0";
    let stack = Stack::new(interface).expect("Failed to create stack");
    let dst_ip = [1, 1, 1, 1];
    let dst_port = 80;

    println!("Connecting to 1.1.1.1:80...");
    let mut stream = stack.connect(dst_ip, dst_port).expect("Failed to connect");
    println!("Connected.");

    let http_get = "GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    stream
        .write_all(http_get.as_bytes())
        .expect("Failed to write");
    println!("Sent HTTP GET request.");

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).expect("Failed to read");

    println!("Received response ({} bytes):", n);
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("{}", response);

    assert!(n > 0);
    assert!(response.contains("HTTP/1.1"));
}
