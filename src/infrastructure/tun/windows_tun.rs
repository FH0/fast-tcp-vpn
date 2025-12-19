use super::{TunConfig, TunDevice, TunError};
use std::net::Ipv4Addr;
use std::time::Duration;

/// Windows Wintun 设备实现 (占位符)
///
/// 注意: 完整实现需要 wintun crate 和 Windows 平台
/// 当前为占位符实现，在非 Windows 平台返回 PlatformNotSupported 错误
pub struct WindowsTun {
    #[allow(dead_code)]
    config: TunConfig,
}

impl WindowsTun {
    /// 创建新的 Wintun 设备
    #[cfg(target_os = "windows")]
    pub fn new(config: TunConfig) -> Result<Self, TunError> {
        // TODO: 实现 Windows Wintun
        // 需要添加 wintun crate 依赖并实现
        Err(TunError::CreateFailed {
            reason: "Windows Wintun not yet implemented".to_string(),
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn new(_config: TunConfig) -> Result<Self, TunError> {
        Err(TunError::PlatformNotSupported)
    }
}

impl TunDevice for WindowsTun {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, TunError> {
        Err(TunError::PlatformNotSupported)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, TunError> {
        Err(TunError::PlatformNotSupported)
    }

    fn read_with_timeout(&self, _buf: &mut [u8], _timeout: Duration) -> Result<usize, TunError> {
        Err(TunError::PlatformNotSupported)
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn address(&self) -> Ipv4Addr {
        self.config.address
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), TunError> {
        Err(TunError::PlatformNotSupported)
    }
}
