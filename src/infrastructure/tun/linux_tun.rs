use super::{TunConfig, TunDevice, TunError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::sync::Mutex;
use std::time::Duration;

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22],
}

/// Linux TUN 设备实现
pub struct LinuxTun {
    file: Mutex<File>,
    name: String,
    mtu: u16,
    address: Ipv4Addr,
}

impl LinuxTun {
    /// 创建新的 TUN 设备
    pub fn new(config: TunConfig) -> Result<Self, TunError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    TunError::PermissionDenied
                } else {
                    TunError::CreateFailed {
                        reason: e.to_string(),
                    }
                }
            })?;

        let mut ifr = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 22],
        };

        // 设置设备名称
        let name_bytes = config.name.as_bytes();
        let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (i, &b) in name_bytes[..len].iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        // 调用 ioctl 创建 TUN 设备
        let fd = file.as_raw_fd();
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr as *const IfReq) };
        if ret < 0 {
            return Err(TunError::CreateFailed {
                reason: std::io::Error::last_os_error().to_string(),
            });
        }

        // 获取实际的设备名称
        let actual_name = ifr
            .ifr_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect::<String>();

        let tun = Self {
            file: Mutex::new(file),
            name: actual_name.clone(),
            mtu: config.mtu,
            address: config.address,
        };

        // 配置 IP 地址和启用设备
        tun.configure(&config)?;

        Ok(tun)
    }

    /// 配置 TUN 设备的 IP 地址和路由
    fn configure(&self, config: &TunConfig) -> Result<(), TunError> {
        use std::process::Command;

        // 设置 IP 地址
        let status = Command::new("ip")
            .args([
                "addr",
                "add",
                &format!("{}/{}", config.address, netmask_to_cidr(config.netmask)),
                "dev",
                &self.name,
            ])
            .status()
            .map_err(|e| TunError::ConfigFailed {
                reason: format!("Failed to run ip command: {}", e),
            })?;

        if !status.success() {
            return Err(TunError::ConfigFailed {
                reason: "Failed to set IP address".to_string(),
            });
        }

        // 设置 MTU
        let status = Command::new("ip")
            .args(["link", "set", "dev", &self.name, "mtu", &config.mtu.to_string()])
            .status()
            .map_err(|e| TunError::ConfigFailed {
                reason: format!("Failed to run ip command: {}", e),
            })?;

        if !status.success() {
            return Err(TunError::ConfigFailed {
                reason: "Failed to set MTU".to_string(),
            });
        }

        // 启用设备
        let status = Command::new("ip")
            .args(["link", "set", "dev", &self.name, "up"])
            .status()
            .map_err(|e| TunError::ConfigFailed {
                reason: format!("Failed to run ip command: {}", e),
            })?;

        if !status.success() {
            return Err(TunError::ConfigFailed {
                reason: "Failed to bring up interface".to_string(),
            });
        }

        Ok(())
    }
}

impl TunDevice for LinuxTun {
    fn read(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut file = self.file.lock().map_err(|_| TunError::ReadFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;
        file.read(buf).map_err(|e| TunError::ReadFailed {
            reason: e.to_string(),
        })
    }

    fn write(&self, buf: &[u8]) -> Result<usize, TunError> {
        let mut file = self.file.lock().map_err(|_| TunError::WriteFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;
        file.write(buf).map_err(|e| TunError::WriteFailed {
            reason: e.to_string(),
        })
    }

    fn read_with_timeout(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, TunError> {
        let file = self.file.lock().map_err(|_| TunError::ReadFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;

        let fd = file.as_raw_fd();
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let timeout_ms = timeout.as_millis() as libc::c_int;
        let ret = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };

        if ret < 0 {
            return Err(TunError::ReadFailed {
                reason: std::io::Error::last_os_error().to_string(),
            });
        }

        if ret == 0 {
            return Err(TunError::Timeout);
        }

        drop(file);
        self.read(buf)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn address(&self) -> Ipv4Addr {
        self.address
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), TunError> {
        let file = self.file.lock().map_err(|_| TunError::ConfigFailed {
            reason: "Failed to acquire lock".to_string(),
        })?;

        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(TunError::ConfigFailed {
                reason: std::io::Error::last_os_error().to_string(),
            });
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(TunError::ConfigFailed {
                reason: std::io::Error::last_os_error().to_string(),
            });
        }

        Ok(())
    }
}

/// 将子网掩码转换为 CIDR 前缀长度
fn netmask_to_cidr(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from(netmask);
    bits.count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_cidr() {
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.name, "tun0");
        assert_eq!(config.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(config.mtu, 1500);
    }

    #[test]
    fn test_tun_config_builder() {
        let config = TunConfig::new("vpn0")
            .with_address(Ipv4Addr::new(192, 168, 1, 1))
            .with_netmask(Ipv4Addr::new(255, 255, 255, 0))
            .with_mtu(1400);

        assert_eq!(config.name, "vpn0");
        assert_eq!(config.address, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.mtu, 1400);
    }
}
