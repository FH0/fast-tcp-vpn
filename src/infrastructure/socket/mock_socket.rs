use super::{PacketReceiver, PacketSender, RawSocket, SocketError};
use crate::infrastructure::packet::Packet;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Mock Socket 用于测试
///
/// 提供一个内存中的发送/接收队列，可以用于单元测试
#[derive(Clone)]
pub struct MockSocket {
    /// 已发送的数据包
    sent_packets: Arc<Mutex<Vec<Packet>>>,
    /// 待接收的数据包队列
    receive_queue: Arc<Mutex<VecDeque<Packet>>>,
    /// 是否模拟发送失败
    fail_send: Arc<Mutex<bool>>,
    /// 是否模拟接收失败
    fail_receive: Arc<Mutex<bool>>,
}

impl MockSocket {
    /// 创建新的 Mock Socket
    pub fn new() -> Self {
        Self {
            sent_packets: Arc::new(Mutex::new(Vec::new())),
            receive_queue: Arc::new(Mutex::new(VecDeque::new())),
            fail_send: Arc::new(Mutex::new(false)),
            fail_receive: Arc::new(Mutex::new(false)),
        }
    }

    /// 获取所有已发送的数据包
    pub fn get_sent_packets(&self) -> Vec<Packet> {
        self.sent_packets.lock().unwrap().clone()
    }

    /// 向接收队列添加数据包 (模拟收到数据)
    pub fn push_receive(&self, packet: Packet) {
        self.receive_queue.lock().unwrap().push_back(packet);
    }

    /// 向接收队列批量添加数据包
    pub fn push_receive_batch(&self, packets: Vec<Packet>) {
        let mut queue = self.receive_queue.lock().unwrap();
        for packet in packets {
            queue.push_back(packet);
        }
    }

    /// 设置是否模拟发送失败
    pub fn set_fail_send(&self, fail: bool) {
        *self.fail_send.lock().unwrap() = fail;
    }

    /// 设置是否模拟接收失败
    pub fn set_fail_receive(&self, fail: bool) {
        *self.fail_receive.lock().unwrap() = fail;
    }

    /// 获取接收队列中剩余的数据包数量
    pub fn receive_queue_len(&self) -> usize {
        self.receive_queue.lock().unwrap().len()
    }

    /// 检查接收队列是否为空
    pub fn receive_queue_is_empty(&self) -> bool {
        self.receive_queue.lock().unwrap().is_empty()
    }
}

impl Default for MockSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketSender for MockSocket {
    fn send(&self, packet: &Packet) -> Result<usize, SocketError> {
        if *self.fail_send.lock().unwrap() {
            return Err(SocketError::SendFailed {
                reason: "Mock send failure".to_string(),
            });
        }

        let bytes = packet.to_bytes();
        let len = bytes.len();
        self.sent_packets.lock().unwrap().push(packet.clone());
        Ok(len)
    }

    fn send_raw(&self, data: &[u8], _dest: Ipv4Addr) -> Result<usize, SocketError> {
        if *self.fail_send.lock().unwrap() {
            return Err(SocketError::SendFailed {
                reason: "Mock send failure".to_string(),
            });
        }

        // 尝试解析数据包并存储
        if let Ok(packet) = Packet::parse(data) {
            self.sent_packets.lock().unwrap().push(packet);
        }

        Ok(data.len())
    }
}

impl PacketReceiver for MockSocket {
    fn receive(&self, timeout: Option<Duration>) -> Result<Packet, SocketError> {
        if *self.fail_receive.lock().unwrap() {
            return Err(SocketError::ReceiveFailed {
                reason: "Mock receive failure".to_string(),
            });
        }

        match self.receive_queue.lock().unwrap().pop_front() {
            Some(packet) => Ok(packet),
            None => {
                if timeout.is_some() {
                    Err(SocketError::Timeout)
                } else {
                    Err(SocketError::ReceiveFailed {
                        reason: "No packets in queue".to_string(),
                    })
                }
            }
        }
    }

    fn receive_raw(&self, buffer: &mut [u8], timeout: Option<Duration>) -> Result<usize, SocketError> {
        let packet = self.receive(timeout)?;
        let bytes = packet.to_bytes();

        if bytes.len() > buffer.len() {
            return Err(SocketError::ReceiveFailed {
                reason: "Buffer too small".to_string(),
            });
        }

        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

impl RawSocket for MockSocket {
    fn local_addr(&self) -> Option<Ipv4Addr> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::packet::TcpFlags;

    #[test]
    fn test_mock_socket_send_receive() {
        let socket = MockSocket::new();

        // 创建测试数据包
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let mut packet = Packet::new(src_ip, dst_ip, 12345, 80, b"Hello".to_vec());
        packet.tcp_header.flags = TcpFlags::SYN;

        // 发送数据包
        let result = socket.send(&packet);
        assert!(result.is_ok());

        // 检查已发送的数据包
        let sent = socket.get_sent_packets();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].ip_header.src_ip, src_ip);
        assert_eq!(sent[0].ip_header.dst_ip, dst_ip);
    }

    #[test]
    fn test_mock_socket_receive_queue() {
        let socket = MockSocket::new();

        // 创建测试数据包
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let packet = Packet::new(src_ip, dst_ip, 8080, 443, Vec::new());

        // 添加到接收队列
        socket.push_receive(packet.clone());
        assert_eq!(socket.receive_queue_len(), 1);

        // 接收数据包
        let received = socket.receive(None).unwrap();
        assert_eq!(received.ip_header.src_ip, src_ip);
        assert_eq!(received.tcp_header.src_port, 8080);

        // 队列应该为空
        assert!(socket.receive_queue_is_empty());
    }

    #[test]
    fn test_mock_socket_timeout() {
        let socket = MockSocket::new();

        // 空队列，设置超时应返回 Timeout 错误
        let result = socket.receive(Some(Duration::from_millis(100)));
        assert!(matches!(result, Err(SocketError::Timeout)));
    }

    #[test]
    fn test_mock_socket_fail_send() {
        let socket = MockSocket::new();
        socket.set_fail_send(true);

        let packet = Packet::new(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1000,
            2000,
            Vec::new(),
        );

        let result = socket.send(&packet);
        assert!(matches!(result, Err(SocketError::SendFailed { .. })));
    }

    #[test]
    fn test_mock_socket_fail_receive() {
        let socket = MockSocket::new();
        socket.set_fail_receive(true);

        // 即使队列中有数据，也应该失败
        let packet = Packet::new(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1000,
            2000,
            Vec::new(),
        );
        socket.push_receive(packet);

        let result = socket.receive(None);
        assert!(matches!(result, Err(SocketError::ReceiveFailed { .. })));
    }

    #[test]
    fn test_mock_socket_batch_receive() {
        let socket = MockSocket::new();

        let packets: Vec<Packet> = (0..5)
            .map(|i| {
                Packet::new(
                    Ipv4Addr::new(192, 168, 1, i as u8),
                    Ipv4Addr::new(192, 168, 1, 100),
                    1000 + i,
                    80,
                    Vec::new(),
                )
            })
            .collect();

        socket.push_receive_batch(packets);
        assert_eq!(socket.receive_queue_len(), 5);

        // 按顺序接收
        for i in 0..5 {
            let received = socket.receive(None).unwrap();
            assert_eq!(received.tcp_header.src_port, 1000 + i);
        }
    }

    #[test]
    fn test_mock_socket_clone() {
        let socket1 = MockSocket::new();

        let packet = Packet::new(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            1000,
            2000,
            Vec::new(),
        );

        socket1.send(&packet).unwrap();

        // Clone 后应该共享状态
        let socket2 = socket1.clone();
        assert_eq!(socket2.get_sent_packets().len(), 1);

        // 通过 socket2 发送，socket1 也能看到
        socket2.send(&packet).unwrap();
        assert_eq!(socket1.get_sent_packets().len(), 2);
    }
}
