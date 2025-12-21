use crate::domain::packet::ip::Ipv4Packet;
use std::io;

/// 网络设备接口 (Port)，用于解耦协议栈与具体底层实现
pub trait NetworkDevice: Send + Sync {
    /// 发送 IP 报文
    fn send_packet(&self, packet: &Ipv4Packet) -> io::Result<usize>;

    /// 接收 IP 报文
    fn receive_packet(&self) -> io::Result<Ipv4Packet>;

    /// 获取设备的 IP 地址
    fn get_local_ip(&self) -> io::Result<[u8; 4]>;
}
