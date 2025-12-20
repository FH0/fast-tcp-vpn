use super::{PacketReceiver, PacketSender, RawSocket, SocketError};
use crate::infrastructure::packet::Packet;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

/// Linux Raw Socket 实现
///
/// 使用 AF_INET + SOCK_RAW + IPPROTO_TCP 创建原始套接字
/// 需要 root 权限或 CAP_NET_RAW capability
pub struct LinuxRawSocket {
    fd: RawFd,
}

impl LinuxRawSocket {
    /// 创建新的 Raw Socket
    ///
    /// # Returns
    /// * `Ok(LinuxRawSocket)` - 成功创建
    /// * `Err(SocketError)` - 创建失败 (通常是权限问题)
    pub fn new() -> Result<Self, SocketError> {
        // SOCK_RAW = 3, IPPROTO_TCP = 6
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };

        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(SocketError::PermissionDenied);
            }
            return Err(SocketError::Io(err));
        }

        // 设置 IP_HDRINCL 选项，表示我们自己构造 IP 头
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(SocketError::Io(io::Error::last_os_error()));
        }

        Ok(Self {
            fd,
        })
    }

    /// 设置接收超时
    pub fn set_recv_timeout(&self, timeout: Duration) -> Result<(), SocketError> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };

        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(SocketError::Io(io::Error::last_os_error()));
        }

        Ok(())
    }

    /// 清除接收超时 (设为阻塞模式)
    pub fn clear_recv_timeout(&self) -> Result<(), SocketError> {
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };

        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(SocketError::Io(io::Error::last_os_error()));
        }

        Ok(())
    }
}

impl Drop for LinuxRawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl AsRawFd for LinuxRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl PacketSender for LinuxRawSocket {
    fn send(&self, packet: &Packet) -> Result<usize, SocketError> {
        let data = packet.to_bytes();
        self.send_raw(&data, packet.ip_header.dst_ip)
    }

    fn send_raw(&self, data: &[u8], dest: Ipv4Addr) -> Result<usize, SocketError> {
        let sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dest.octets()),
            },
            sin_zero: [0; 8],
        };

        let sent = unsafe {
            libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            let err = io::Error::last_os_error();
            return Err(SocketError::SendFailed {
                reason: err.to_string(),
            });
        }

        Ok(sent as usize)
    }
}

impl PacketReceiver for LinuxRawSocket {
    fn receive(&self, timeout: Option<Duration>) -> Result<Packet, SocketError> {
        let mut buffer = [0u8; 65535];
        let len = self.receive_raw(&mut buffer, timeout)?;

        Packet::parse(&buffer[..len]).map_err(|_| SocketError::InvalidPacket)
    }

    fn receive_raw(&self, buffer: &mut [u8], timeout: Option<Duration>) -> Result<usize, SocketError> {
        if let Some(t) = timeout {
            self.set_recv_timeout(t)?;
        } else {
            self.clear_recv_timeout()?;
        }

        let received = unsafe {
            libc::recv(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        if received < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Err(SocketError::Timeout);
            }
            return Err(SocketError::ReceiveFailed {
                reason: err.to_string(),
            });
        }

        Ok(received as usize)
    }
}

impl RawSocket for LinuxRawSocket {
    fn local_addr(&self) -> Option<Ipv4Addr> {
        None
    }
}

/// 获取到达指定目标 IP 的本地出口 IP
///
/// 通过创建一个 UDP socket 并 connect 到目标地址来确定本地出口 IP
pub fn get_outbound_ip(dest: Ipv4Addr) -> Result<Ipv4Addr, SocketError> {
    // 创建 UDP socket
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(SocketError::Io(io::Error::last_os_error()));
    }

    // Connect 到目标地址（不会实际发送数据）
    let sockaddr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 80u16.to_be(), // 任意端口
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(dest.octets()),
        },
        sin_zero: [0; 8],
    };

    let ret = unsafe {
        libc::connect(
            fd,
            &sockaddr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(SocketError::Io(io::Error::last_os_error()));
    }

    // 获取本地地址
    let mut local_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockname(
            fd,
            &mut local_addr as *mut _ as *mut libc::sockaddr,
            &mut addr_len,
        )
    };

    unsafe { libc::close(fd) };

    if ret < 0 {
        return Err(SocketError::Io(io::Error::last_os_error()));
    }

    let ip_bytes = local_addr.sin_addr.s_addr.to_ne_bytes();
    Ok(Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::packet::TcpFlags;

    #[test]
    #[ignore] // 需要 root 权限
    fn test_raw_socket_creation() {
        let socket = LinuxRawSocket::new();
        // 在非 root 环境下会失败
        if let Err(SocketError::PermissionDenied) = socket {
            println!("Test skipped: requires root privileges");
            return;
        }
        assert!(socket.is_ok());
    }

    #[test]
    #[ignore] // 需要 root 权限
    fn test_send_tcp_syn() {
        let socket = match LinuxRawSocket::new() {
            Ok(s) => s,
            Err(SocketError::PermissionDenied) => {
                println!("Test skipped: requires root privileges");
                return;
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        };

        // 构造一个 SYN 包发送到 localhost
        let src_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(127, 0, 0, 1);

        let mut packet = Packet::new(src_ip, dst_ip, 12345, 80, Vec::new());
        packet.tcp_header.flags = TcpFlags::SYN;
        packet.tcp_header.seq = 1000;

        let result = socket.send(&packet);
        assert!(result.is_ok());
    }
}
