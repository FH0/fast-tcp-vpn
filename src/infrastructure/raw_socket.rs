use crate::domain::packet::ip::Ipv4Packet;
use bytes::Bytes;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

/// 允许手动构建 IP 首部的原始 TCP 套接字。
/// 此实现提供同步接口。
pub struct RawTcpSocket {
    fd: RawFd,
    interface_name: String,
}

impl RawTcpSocket {
    /// 创建一个新的原始 TCP 套接字并绑定到特定的网络接口。
    /// 通过使用 IPPROTO_TCP，内核将 TCP 报文串联到此套接字。
    /// 设置 IP_HDRINCL 以允许手动构建 IP 首部。
    ///
    /// 注意：创建原始套接字需要 CAP_NET_RAW 权限或 root 权限。
    pub fn new(interface_name: &str) -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 设置 IP_HDRINCL，以便我们可以在 sendto 中提供自己的 IP 首部。
        let on: libc::c_int = 1;
        let res = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if res < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        // 将套接字绑定到特定的网络接口（例如 "eth0" 或 "wlan0"）。
        // 使用 SO_BINDTODEVICE 套接字选项。
        let ifname = interface_name.as_bytes();
        let res = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                ifname.as_ptr() as *const libc::c_void,
                ifname.len() as libc::socklen_t,
            )
        };
        if res < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(Self {
            fd,
            interface_name: interface_name.to_string(),
        })
    }

    /// 获取绑定的网络接口的 IP 地址。
    pub fn get_local_ip(&self) -> io::Result<[u8; 4]> {
        Self::get_interface_ip(&self.interface_name)
    }

    /// 获取指定网络接口的 IPv4 地址。
    pub fn get_interface_ip(interface_name: &str) -> io::Result<[u8; 4]> {
        let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut ifaddr) } == -1 {
            return Err(io::Error::last_os_error());
        }

        let mut current = ifaddr;
        let mut result = Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Interface {} not found or has no IPv4 address",
                interface_name
            ),
        ));

        while !current.is_null() {
            let ifa = unsafe { *current };
            if !ifa.ifa_name.is_null() {
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
                if name.to_string_lossy() == interface_name {
                    if !ifa.ifa_addr.is_null()
                        && unsafe { (*ifa.ifa_addr).sa_family } == libc::AF_INET as u16
                    {
                        let sockaddr_in = unsafe { *(ifa.ifa_addr as *const libc::sockaddr_in) };
                        // sin_addr.s_addr 已经是网络字节序。
                        // 在小端机器上，127.0.0.1 (0x0100007F) 存储为 [0x7F, 0x00, 0x00, 0x01]。
                        // to_ne_bytes() 将按内存顺序返回字节。
                        result = Ok(sockaddr_in.sin_addr.s_addr.to_ne_bytes());
                        break;
                    }
                }
            }
            current = ifa.ifa_next;
        }

        unsafe { libc::freeifaddrs(ifaddr) };
        result
    }

    /// 发送原始 IPv4 报文。
    /// 由于设置了 IP_HDRINCL，报文必须包含有效的 IPv4 首部。
    pub fn send_packet(&self, packet: &Ipv4Packet) -> io::Result<usize> {
        let bytes = packet.to_bytes();
        let dest_ip = packet.destination_ip();

        // 即使设置了 IP_HDRINCL，sendto 仍需要目的地址。
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dest_ip),
            },
            sin_zero: [0; 8],
        };

        let res = unsafe {
            libc::sendto(
                self.fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    /// 从网络接收单个报文。
    /// 接收到的数据将包含 IPv4 首部。
    pub fn receive_packet(&self) -> io::Result<Ipv4Packet> {
        let mut buffer = [0u8; 65535];
        let res = unsafe {
            libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        let n = res as usize;
        let data = Bytes::copy_from_slice(&buffer[..n]);

        Ipv4Packet::from_bytes(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Drop for RawTcpSocket {
    fn drop(&mut self) {
        // 关闭套接字
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl AsRawFd for RawTcpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

// 安全性：RawFd 可以安全地在线程间传递。
unsafe impl Send for RawTcpSocket {}
unsafe impl Sync for RawTcpSocket {}
