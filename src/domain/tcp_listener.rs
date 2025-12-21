use crate::domain::packet::tcp::TcpPacket;
use std::io;
use std::process::Command;
use std::sync::{Arc, mpsc};

use crate::domain::stack::StackInner;
use crate::domain::tcp_stream::{ConnectionId, TcpStream, TcpStreamHandle};

pub struct TcpListenerHandle {
    pub tx: mpsc::Sender<([u8; 4], TcpPacket)>,
}

pub struct TcpListener {
    inner: Arc<StackInner>,
    local_port: u16,
    rx: mpsc::Receiver<([u8; 4], TcpPacket)>,
    interface_name: String,
}

impl TcpListener {
    pub(crate) fn new(
        inner: Arc<StackInner>,
        local_port: u16,
        rx: mpsc::Receiver<([u8; 4], TcpPacket)>,
        interface_name: String,
    ) -> Self {
        // 监听端口也需要 iptables 规则，防止内核对收到的 SYN 发送 RST
        Self::add_iptables_rule(&interface_name, local_port);

        Self {
            inner,
            local_port,
            rx,
            interface_name,
        }
    }

    fn add_iptables_rule(interface: &str, port: u16) {
        let _ = Command::new("iptables")
            .args([
                "-A",
                "OUTPUT",
                "-o",
                interface,
                "-p",
                "tcp",
                "--sport",
                &port.to_string(),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ])
            .status();
    }

    fn remove_iptables_rule(interface: &str, port: u16) {
        let _ = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-o",
                interface,
                "-p",
                "tcp",
                "--sport",
                &port.to_string(),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ])
            .status();
    }

    pub fn accept(&self) -> io::Result<TcpStream> {
        loop {
            // 等待来自 Stack recv_loop 的 SYN 包
            let (remote_ip, syn_packet) = self.rx.recv().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Listener channel closed: {}", e),
                )
            })?;

            let conn_id = ConnectionId {
                local_port: self.local_port,
                remote_ip,
                remote_port: syn_packet.source_port,
            };

            let (tx, rx) = mpsc::channel();
            let handle = TcpStreamHandle { tx };

            {
                let mut streams = self.inner.streams.lock().unwrap();
                if streams.contains_key(&conn_id) {
                    // 已有连接，可能是重复的 SYN，忽略
                    continue;
                }
                streams.insert(conn_id.clone(), handle);
            }

            let mut stream = TcpStream::new(
                Arc::clone(&self.inner),
                conn_id,
                rx,
                self.interface_name.clone(),
                false, // is_client = false
            )?;

            // 完成握手
            match stream.accept_handshake(syn_packet) {
                Ok(_) => return Ok(stream),
                Err(_) => {
                    // 握手失败，TcpStream 的 Drop 会清理 streams HashMap 和 iptables
                    continue;
                }
            }
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        Self::remove_iptables_rule(&self.interface_name, self.local_port);
        let mut listeners = self.inner.listeners.lock().unwrap();
        listeners.remove(&self.local_port);
    }
}
