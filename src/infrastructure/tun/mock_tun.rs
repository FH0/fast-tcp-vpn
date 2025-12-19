use super::{TunConfig, TunDevice, TunError};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Mock TUN 设备，用于测试
#[derive(Clone)]
pub struct MockTun {
    inner: Arc<MockTunInner>,
}

struct MockTunInner {
    config: TunConfig,
    /// 待读取的数据包队列 (模拟从 TUN 读取)
    read_queue: Mutex<VecDeque<Vec<u8>>>,
    /// 已写入的数据包队列 (模拟写入 TUN)
    write_queue: Mutex<VecDeque<Vec<u8>>>,
    /// 是否为非阻塞模式
    nonblocking: Mutex<bool>,
}

impl MockTun {
    /// 创建新的 Mock TUN 设备
    pub fn new(config: TunConfig) -> Result<Self, TunError> {
        Ok(Self {
            inner: Arc::new(MockTunInner {
                config,
                read_queue: Mutex::new(VecDeque::new()),
                write_queue: Mutex::new(VecDeque::new()),
                nonblocking: Mutex::new(false),
            }),
        })
    }

    /// 使用默认配置创建
    pub fn with_defaults() -> Self {
        Self::new(TunConfig::default()).unwrap()
    }

    /// 向读取队列添加数据包 (模拟收到的数据包)
    pub fn inject_packet(&self, packet: Vec<u8>) {
        let mut queue = self.inner.read_queue.lock().unwrap();
        queue.push_back(packet);
    }

    /// 从写入队列获取数据包 (获取发送的数据包)
    pub fn pop_written_packet(&self) -> Option<Vec<u8>> {
        let mut queue = self.inner.write_queue.lock().unwrap();
        queue.pop_front()
    }

    /// 获取所有已写入的数据包
    pub fn get_written_packets(&self) -> Vec<Vec<u8>> {
        let queue = self.inner.write_queue.lock().unwrap();
        queue.iter().cloned().collect()
    }

    /// 清空写入队列
    pub fn clear_written_packets(&self) {
        let mut queue = self.inner.write_queue.lock().unwrap();
        queue.clear();
    }

    /// 获取读取队列长度
    pub fn read_queue_len(&self) -> usize {
        let queue = self.inner.read_queue.lock().unwrap();
        queue.len()
    }

    /// 获取写入队列长度
    pub fn write_queue_len(&self) -> usize {
        let queue = self.inner.write_queue.lock().unwrap();
        queue.len()
    }
}

impl TunDevice for MockTun {
    fn read(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut queue = self.inner.read_queue.lock().map_err(|_| TunError::ReadFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;

        if let Some(packet) = queue.pop_front() {
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        } else {
            let nonblocking = *self.inner.nonblocking.lock().unwrap();
            if nonblocking {
                Err(TunError::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "No data available",
                )))
            } else {
                // 在阻塞模式下，返回 0 表示没有数据
                Ok(0)
            }
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, TunError> {
        let mut queue = self.inner.write_queue.lock().map_err(|_| TunError::WriteFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;

        queue.push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn read_with_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, TunError> {
        let start = std::time::Instant::now();
        let check_interval = Duration::from_millis(10);

        loop {
            {
                let mut queue = self.inner.read_queue.lock().map_err(|_| TunError::ReadFailed {
                    reason: "Failed to acquire lock".to_string(),
                })?;

                if let Some(packet) = queue.pop_front() {
                    let len = packet.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet[..len]);
                    return Ok(len);
                }
            }

            if start.elapsed() >= timeout {
                return Err(TunError::Timeout);
            }

            std::thread::sleep(check_interval);
        }
    }

    fn name(&self) -> &str {
        &self.inner.config.name
    }

    fn mtu(&self) -> u16 {
        self.inner.config.mtu
    }

    fn address(&self) -> Ipv4Addr {
        self.inner.config.address
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), TunError> {
        let mut nb = self.inner.nonblocking.lock().map_err(|_| TunError::ConfigFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;
        *nb = nonblocking;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_tun_creation() {
        let tun = MockTun::with_defaults();
        assert_eq!(tun.name(), "tun0");
        assert_eq!(tun.mtu(), 1500);
        assert_eq!(tun.address(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_mock_tun_write_read() {
        let tun = MockTun::with_defaults();

        // 写入数据
        let data = vec![0x45, 0x00, 0x00, 0x14]; // 简单的 IP 头部
        let written = tun.write(&data).unwrap();
        assert_eq!(written, data.len());

        // 检查写入队列
        assert_eq!(tun.write_queue_len(), 1);
        let written_packet = tun.pop_written_packet().unwrap();
        assert_eq!(written_packet, data);
    }

    #[test]
    fn test_mock_tun_inject_read() {
        let tun = MockTun::with_defaults();

        // 注入数据包
        let packet = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01];
        tun.inject_packet(packet.clone());

        // 读取数据
        let mut buf = [0u8; 1500];
        let len = tun.read(&mut buf).unwrap();
        assert_eq!(len, packet.len());
        assert_eq!(&buf[..len], &packet[..]);
    }

    #[test]
    fn test_mock_tun_read_timeout() {
        let tun = MockTun::with_defaults();

        // 没有数据时应该超时
        let mut buf = [0u8; 1500];
        let result = tun.read_with_timeout(&mut buf, Duration::from_millis(50));
        assert!(matches!(result, Err(TunError::Timeout)));
    }

    #[test]
    fn test_mock_tun_nonblocking() {
        let tun = MockTun::with_defaults();

        // 设置非阻塞模式
        tun.set_nonblocking(true).unwrap();

        // 没有数据时应该返回 WouldBlock
        let mut buf = [0u8; 1500];
        let result = tun.read(&mut buf);
        assert!(matches!(result, Err(TunError::Io(_))));
    }

    #[test]
    fn test_mock_tun_clone() {
        let tun1 = MockTun::with_defaults();
        let tun2 = tun1.clone();

        // 写入 tun1
        let data = vec![1, 2, 3, 4];
        tun1.write(&data).unwrap();

        // 从 tun2 读取写入队列
        assert_eq!(tun2.write_queue_len(), 1);
    }
}
