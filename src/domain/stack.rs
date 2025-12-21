use crate::domain::device::NetworkDevice;
use crate::domain::packet::ip::Ipv4Packet;
use crate::domain::packet::tcp::{TCP_FLAG_SYN, TcpPacket};
use bytes::Bytes;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use crate::domain::tcp_listener::{TcpListener, TcpListenerHandle};
use crate::domain::tcp_stream::{ConnectionId, TcpStream, TcpStreamHandle};

/// TCP 协议栈实现
pub struct Stack {
    inner: Arc<StackInner>,
    #[allow(dead_code)]
    recv_thread: Option<thread::JoinHandle<()>>,
}

pub(crate) struct StackInner {
    pub(crate) socket: Box<dyn NetworkDevice>,
    pub(crate) local_ip: [u8; 4],
    pub(crate) interface_name: String,
    pub(crate) streams: Mutex<HashMap<ConnectionId, TcpStreamHandle>>,
    pub(crate) listeners: Mutex<HashMap<u16, TcpListenerHandle>>,
}

impl Stack {
    /// 使用指定的网络设备创建一个新的 TCP 协议栈
    pub fn new(device: Box<dyn NetworkDevice>, interface_name: &str) -> io::Result<Self> {
        let local_ip = device.get_local_ip()?;

        let inner = Arc::new(StackInner {
            socket: device,
            local_ip,
            interface_name: interface_name.to_string(),
            streams: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
        });

        let inner_clone = Arc::clone(&inner);
        let recv_thread = thread::spawn(move || {
            Self::recv_loop(inner_clone);
        });

        Ok(Self {
            inner,
            recv_thread: Some(recv_thread),
        })
    }

    pub fn local_ip(&self) -> [u8; 4] {
        self.inner.local_ip
    }

    /// 连接到远程地址
    pub fn connect(&self, remote_ip: [u8; 4], remote_port: u16) -> io::Result<TcpStream> {
        // 分配一个本地随机端口
        let local_port = rand::random::<u16>() % 50000 + 10000;
        let conn_id = ConnectionId {
            local_port,
            remote_ip,
            remote_port,
        };

        let (tx, rx) = mpsc::channel();
        let handle = TcpStreamHandle { tx };

        {
            let mut streams = self.inner.streams.lock().unwrap();
            streams.insert(conn_id.clone(), handle);
        }

        let stream = TcpStream::new(
            Arc::clone(&self.inner),
            conn_id,
            rx,
            self.inner.interface_name.clone(),
            true, // is_client = true
        )?;

        Ok(stream)
    }

    /// 监听本地端口
    pub fn listen(&self, local_port: u16) -> io::Result<TcpListener> {
        let (tx, rx) = mpsc::channel();
        let handle = TcpListenerHandle { tx };

        {
            let mut listeners = self.inner.listeners.lock().unwrap();
            if listeners.contains_key(&local_port) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Port already listened",
                ));
            }
            listeners.insert(local_port, handle);
        }

        Ok(TcpListener::new(
            Arc::clone(&self.inner),
            local_port,
            rx,
            self.inner.interface_name.clone(),
        ))
    }

    fn recv_loop(inner: Arc<StackInner>) {
        loop {
            match inner.socket.receive_packet() {
                Ok(ip_packet) => {
                    // 只处理 TCP 协议 (6)
                    if ip_packet.protocol != 6 {
                        continue;
                    }

                    let tcp_packet = match TcpPacket::from_bytes(ip_packet.data) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    let conn_id = ConnectionId {
                        local_port: tcp_packet.destination_port,
                        remote_ip: ip_packet.source_ip,
                        remote_port: tcp_packet.source_port,
                    };

                    // 1. 尝试分发给已有的处理中的连接
                    {
                        let streams = inner.streams.lock().unwrap();
                        if let Some(handle) = streams.get(&conn_id) {
                            let _ = handle.tx.send(tcp_packet);
                            continue;
                        }
                    }

                    // 2. 如果是 SYN 且没有现有连接，尝试分发给监听器
                    if (tcp_packet.flags & TCP_FLAG_SYN) != 0 {
                        let listeners = inner.listeners.lock().unwrap();
                        if let Some(listener_handle) = listeners.get(&tcp_packet.destination_port) {
                            let _ = listener_handle.tx.send((ip_packet.source_ip, tcp_packet));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet in stack loop: {}", e);
                    // 如果套接字关闭，退出循环
                    break;
                }
            }
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // RawTcpSocket 的 Drop 会关闭 fd，导致 recv_loop 退出
    }
}

impl StackInner {
    pub fn send_tcp(
        &self,
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
        seq: u32,
        ack: u32,
        flags: u16,
        data: Bytes,
    ) -> io::Result<()> {
        let mut tcp_packet = TcpPacket::new(local_port, remote_port, data);
        tcp_packet.sequence_number = seq;
        tcp_packet.acknowledgment_number = ack;
        tcp_packet.flags = flags;
        tcp_packet.update_checksum(self.local_ip, remote_ip);

        let mut ip_packet = Ipv4Packet::new(self.local_ip, remote_ip, tcp_packet.to_bytes());
        ip_packet.update_checksum();

        self.socket.send_packet(&ip_packet)?;
        Ok(())
    }
}
