use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::IpAddr;
use tun::platform::Device as TunDevice;

/// TUN 设备配置
pub struct TunConfig {
    /// 接口名称
    pub name: String,
    /// IP 地址
    pub address: IpAddr,
    /// 子网掩码
    pub netmask: IpAddr,
    /// MTU 大小
    pub mtu: i32,
}

/// 异步 TUN 设备封装
///
/// 注意：由于 TUN 设备的特性，异步操作使用 spawn_blocking 在后台线程执行
/// 对于高性能场景，建议使用同步接口配合 tokio::spawn 或自定义事件循环
pub struct AsyncTunDevice {
    inner: std::sync::Arc<std::sync::Mutex<TunDevice>>,
    config: TunConfig,
}

impl AsyncTunDevice {
    /// 创建新的异步 TUN 设备
    pub fn new(config: TunConfig) -> Result<Self> {
        let mut config_builder = tun::Configuration::default();
        config_builder
            .name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();

        #[cfg(target_os = "linux")]
        config_builder.platform(|config| {
            config.packet_information(false);
        });

        let device = tun::create(&config_builder)
            .context("Failed to create TUN device")?;

        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(device)),
            config,
        })
    }

    /// 异步读取数据包（使用 spawn_blocking）
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        struct ReadResult {
            data: Vec<u8>,
            size: usize,
        }

        let inner = self.inner.clone();
        let mut temp_buf = vec![0u8; buf.len()];
        let result = tokio::task::spawn_blocking(move || {
            let mut device = inner.lock().unwrap();
            let size = device
                .read(&mut temp_buf)
                .context("Failed to read packet from TUN device")?;
            Ok::<_, anyhow::Error>(ReadResult {
                data: temp_buf,
                size,
            })
        })
        .await
        .context("Async task execution failed")?
        .context("Failed to read packet from TUN device asynchronously")?;

        if result.size > 0 && result.size <= buf.len() {
            buf[..result.size].copy_from_slice(&result.data[..result.size]);
        }
        Ok(result.size)
    }

    /// 异步写入数据包（使用 spawn_blocking）
    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize> {
        let inner = self.inner.clone();
        let buf_clone = buf.to_vec();

        tokio::task::spawn_blocking(move || {
            let mut device = inner.lock().unwrap();
            device
                .write(&buf_clone)
                .context("Failed to write packet to TUN device")
        })
        .await
        .context("Async task execution failed")?
        .context("Failed to write packet to TUN device asynchronously")
    }

    /// 获取接口名称
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// 获取配置
    pub fn config(&self) -> &TunConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_tun_read_packet() {
        let config = TunConfig {
            name: "tun0".to_string(),
            address: "10.0.0.1".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            mtu: 1500,
        };
        let device = AsyncTunDevice::new(config).unwrap();

        let mut buf = vec![0u8; 1500];
        // 尝试读取一个数据包（可能会阻塞或超时，取决于是否有数据）
        let _result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            device.read_packet(&mut buf)
        ).await;

        // 如果没有数据包也不会失败，只是超时
        // 这里主要测试设备能正常创建和读取操作能执行
        assert!(device.name() == "tun0");
    }
}
