use super::SocketError;
use crate::infrastructure::packet::Packet;
use std::net::Ipv4Addr;
use std::time::Duration;

/// 数据包发送器 trait
///
/// 负责将构造好的 TCP 数据包发送到网络
pub trait PacketSender: Send + Sync {
    /// 发送一个 TCP 数据包
    ///
    /// # Arguments
    /// * `packet` - 要发送的数据包
    ///
    /// # Returns
    /// * `Ok(usize)` - 成功发送的字节数
    /// * `Err(SocketError)` - 发送失败
    fn send(&self, packet: &Packet) -> Result<usize, SocketError>;

    /// 发送原始字节数据到指定目标
    ///
    /// # Arguments
    /// * `data` - 原始字节数据 (完整的 IP 包)
    /// * `dest` - 目标 IP 地址
    ///
    /// # Returns
    /// * `Ok(usize)` - 成功发送的字节数
    /// * `Err(SocketError)` - 发送失败
    fn send_raw(&self, data: &[u8], dest: Ipv4Addr) -> Result<usize, SocketError>;
}

/// 数据包接收器 trait
///
/// 负责从网络接收 TCP 数据包
pub trait PacketReceiver: Send + Sync {
    /// 接收一个 TCP 数据包
    ///
    /// # Arguments
    /// * `timeout` - 可选的超时时间，None 表示阻塞等待
    ///
    /// # Returns
    /// * `Ok(Packet)` - 接收到的数据包
    /// * `Err(SocketError)` - 接收失败或超时
    fn receive(&self, timeout: Option<Duration>) -> Result<Packet, SocketError>;

    /// 接收原始字节数据
    ///
    /// # Arguments
    /// * `buffer` - 接收缓冲区
    /// * `timeout` - 可选的超时时间
    ///
    /// # Returns
    /// * `Ok(usize)` - 接收到的字节数
    /// * `Err(SocketError)` - 接收失败或超时
    fn receive_raw(&self, buffer: &mut [u8], timeout: Option<Duration>) -> Result<usize, SocketError>;
}

/// 组合的 Socket trait，同时支持发送和接收
pub trait RawSocket: PacketSender + PacketReceiver {
    /// 获取绑定的本地 IP 地址
    fn local_addr(&self) -> Option<Ipv4Addr>;
}
