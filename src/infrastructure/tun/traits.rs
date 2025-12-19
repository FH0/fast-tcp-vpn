use super::TunError;
use std::net::Ipv4Addr;
use std::time::Duration;

/// TUN 设备配置
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// 设备名称 (如 "tun0")
    pub name: String,
    /// 设备 IP 地址
    pub address: Ipv4Addr,
    /// 子网掩码
    pub netmask: Ipv4Addr,
    /// MTU 大小
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1500,
        }
    }
}

impl TunConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn with_address(mut self, address: Ipv4Addr) -> Self {
        self.address = address;
        self
    }

    pub fn with_netmask(mut self, netmask: Ipv4Addr) -> Self {
        self.netmask = netmask;
        self
    }

    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }
}

/// TUN 设备 trait
///
/// 提供虚拟网络设备的读写能力，用于捕获和注入 IP 数据包
pub trait TunDevice: Send + Sync {
    /// 从 TUN 设备读取一个 IP 数据包
    ///
    /// # Arguments
    /// * `buf` - 接收缓冲区
    ///
    /// # Returns
    /// * `Ok(usize)` - 读取的字节数
    /// * `Err(TunError)` - 读取失败
    fn read(&self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// 向 TUN 设备写入一个 IP 数据包
    ///
    /// # Arguments
    /// * `buf` - 要写入的 IP 数据包
    ///
    /// # Returns
    /// * `Ok(usize)` - 写入的字节数
    /// * `Err(TunError)` - 写入失败
    fn write(&self, buf: &[u8]) -> Result<usize, TunError>;

    /// 带超时的读取
    ///
    /// # Arguments
    /// * `buf` - 接收缓冲区
    /// * `timeout` - 超时时间
    ///
    /// # Returns
    /// * `Ok(usize)` - 读取的字节数
    /// * `Err(TunError::Timeout)` - 超时
    /// * `Err(TunError)` - 其他错误
    fn read_with_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, TunError>;

    /// 获取设备名称
    fn name(&self) -> &str;

    /// 获取设备 MTU
    fn mtu(&self) -> u16;

    /// 获取设备 IP 地址
    fn address(&self) -> Ipv4Addr;

    /// 设置非阻塞模式
    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), TunError>;
}
