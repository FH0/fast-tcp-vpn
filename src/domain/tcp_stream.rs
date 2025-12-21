use crate::domain::packet::tcp::{
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN, TcpPacket,
};
use bytes::Bytes;
use std::io::{self, Read, Write};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::domain::stack::StackInner;

/// TCP 连接标识
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionId {
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
}

pub struct TcpStreamHandle {
    pub tx: mpsc::Sender<TcpPacket>,
}

/// TCP 状态机状态 (根据 RFC 9293)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TcpState {
    /// CLOSED - 表示没有连接状态。
    /// (RFC 9293: CLOSED - represents no connection state at all.)
    Closed,
    /// LISTEN - 表示正在等待来自任何远程 TCP 和端口的连接请求。
    /// (RFC 9293: LISTEN - represents waiting for a connection request from any remote TCP and port.)
    Listen,
    /// SYN-SENT - 表示在发送连接请求后等待匹配的连接请求。
    /// (RFC 9293: SYN-SENT - represents waiting for a matching connection request after having sent a connection request.)
    SynSent,
    /// SYN-RECEIVED - 表示在接收和发送连接请求后，等待确认连接请求的确认。
    /// (RFC 9293: SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.)
    SynReceived,
    /// ESTABLISHED - 表示一个打开的连接，接收到的数据可以交付给用户。这是连接数据传输阶段的正常状态。
    /// (RFC 9293: ESTABLISHED - represents an open connection, data received can be delivered to the user. The normal state for the data transfer phase of the connection.)
    Established,
    /// FIN-WAIT-1 - 表示等待来自远程 TCP 的连接终止请求，或等待之前发送的连接终止请求的确认。
    /// (RFC 9293: FIN-WAIT-1 - represents waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent.)
    FinWait1,
    /// FIN-WAIT-2 - 表示等待来自远程 TCP 的连接终止请求。
    /// (RFC 9293: FIN-WAIT-2 - represents waiting for a connection termination request from the remote TCP.)
    FinWait2,
    /// CLOSE-WAIT - 表示等待来自本地用户的连接终止请求。
    /// (RFC 9293: CLOSE-WAIT - represents waiting for a connection termination request from the local user.)
    CloseWait,
    /// CLOSING - 表示等待来自远程 TCP 的连接终止请求确认。
    /// (RFC 9293: CLOSING - represents waiting for a connection termination request acknowledgment from the remote TCP.)
    Closing,
    /// LAST-ACK - 表示等待对之前发送给远程 TCP 的连接终止请求的确认。
    /// (RFC 9293: LAST-ACK - represents waiting for an acknowledgment of the connection termination request previously sent to the remote TCP.)
    LastAck,
    /// TIME-WAIT - 表示等待足够的时间以确保远程 TCP 接收到对它的连接终止请求的确认。
    /// (RFC 9293: TIME-WAIT - represents waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request.)
    TimeWait,
}

pub struct TcpStream {
    inner: Arc<StackInner>,
    conn_id: ConnectionId,
    rx: mpsc::Receiver<TcpPacket>,
    state: TcpState,
    seq: u32,
    ack: u32,
    recv_buffer: Vec<u8>,
    interface_name: String,
}

impl TcpStream {
    pub(crate) fn new(
        inner: Arc<StackInner>,
        conn_id: ConnectionId,
        rx: mpsc::Receiver<TcpPacket>,
        interface_name: String,
        is_client: bool,
    ) -> io::Result<Self> {
        // 内部维护 iptables 规则，防止内核发送 RST
        Self::add_iptables_rule(&interface_name, conn_id.local_port);

        let mut stream = Self {
            inner,
            conn_id,
            rx,
            state: TcpState::Closed,
            seq: rand::random::<u32>() % 10000 + 1000,
            ack: 0,
            recv_buffer: Vec::new(),
            interface_name,
        };

        if is_client {
            stream.connect()?;
        } else {
            // 被动打开的情况下由 TcpListener 设置状态
            stream.state = TcpState::SynReceived;
        }

        Ok(stream)
    }

    pub fn conn_id(&self) -> &ConnectionId {
        &self.conn_id
    }

    pub fn state(&self) -> TcpState {
        self.state
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

    /// 发送 SYN 并等待 SYN-ACK (三次握手)
    fn connect(&mut self) -> io::Result<()> {
        // 1. A --> B  SYN seq=x
        self.inner.send_tcp(
            self.conn_id.remote_ip,
            self.conn_id.local_port,
            self.conn_id.remote_port,
            self.seq,
            0,
            TCP_FLAG_SYN,
            Bytes::new(),
        )?;
        self.state = TcpState::SynSent;

        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        while start.elapsed() < timeout {
            if let Ok(packet) = self.rx.recv_timeout(Duration::from_millis(100)) {
                if (packet.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) {
                    // 2. B --> A  SYN seq=y ack=x+1
                    self.ack = packet.sequence_number + 1;
                    self.seq += 1;

                    // 3. A --> B  ACK ack=y+1
                    self.inner.send_tcp(
                        self.conn_id.remote_ip,
                        self.conn_id.local_port,
                        self.conn_id.remote_port,
                        self.seq,
                        self.ack,
                        TCP_FLAG_ACK,
                        Bytes::new(),
                    )?;
                    self.state = TcpState::Established;
                    return Ok(());
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Wait for SYN-ACK timeout",
        ))
    }

    /// 被动打开时完成握手
    pub(crate) fn accept_handshake(&mut self, syn_packet: TcpPacket) -> io::Result<()> {
        self.ack = syn_packet.sequence_number + 1;
        // 发送 SYN-ACK
        self.inner.send_tcp(
            self.conn_id.remote_ip,
            self.conn_id.local_port,
            self.conn_id.remote_port,
            self.seq,
            self.ack,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            Bytes::new(),
        )?;
        self.state = TcpState::SynReceived;

        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        while start.elapsed() < timeout {
            if let Ok(packet) = self.rx.recv_timeout(Duration::from_millis(100)) {
                if (packet.flags & TCP_FLAG_ACK) != 0 && (packet.flags & TCP_FLAG_SYN) == 0 {
                    self.seq += 1;
                    self.state = TcpState::Established;
                    return Ok(());
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Wait for ACK in accept_handshake timeout",
        ))
    }

    pub fn close(&mut self) -> io::Result<()> {
        if self.state == TcpState::Closed || self.state == TcpState::TimeWait {
            return Ok(());
        }

        // 发送 FIN
        self.inner.send_tcp(
            self.conn_id.remote_ip,
            self.conn_id.local_port,
            self.conn_id.remote_port,
            self.seq,
            self.ack,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            Bytes::new(),
        )?;

        if self.state == TcpState::Established {
            self.state = TcpState::FinWait1;
        } else if self.state == TcpState::CloseWait {
            self.state = TcpState::LastAck;
        }

        // 简化处理：不在此处循环等待所有阶段，只执行发送。
        // 实际复杂的关闭流程应在 read 循环中驱动状态机。
        Ok(())
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.recv_buffer.is_empty() {
            let n = std::cmp::min(buf.len(), self.recv_buffer.len());
            buf[..n].copy_from_slice(&self.recv_buffer[..n]);
            self.recv_buffer.drain(..n);
            return Ok(n);
        }

        if self.state == TcpState::Closed
            || self.state == TcpState::LastAck
            || self.state == TcpState::TimeWait
        {
            return Ok(0);
        }

        loop {
            match self.rx.recv() {
                Ok(packet) => {
                    if (packet.flags & TCP_FLAG_RST) != 0 {
                        self.state = TcpState::Closed;
                        return Err(io::Error::new(io::ErrorKind::ConnectionReset, "TCP RST"));
                    }

                    // 处理数据
                    if !packet.data.is_empty() {
                        // 更新期望的下一个序列号
                        // 简化：假设没有丢包且顺序达到
                        self.ack = packet.sequence_number + packet.data.len() as u32;

                        // 发送 ACK
                        self.inner.send_tcp(
                            self.conn_id.remote_ip,
                            self.conn_id.local_port,
                            self.conn_id.remote_port,
                            self.seq,
                            self.ack,
                            TCP_FLAG_ACK,
                            Bytes::new(),
                        )?;

                        let n = std::cmp::min(buf.len(), packet.data.len());
                        buf[..n].copy_from_slice(&packet.data[..n]);
                        if n < packet.data.len() {
                            self.recv_buffer.extend_from_slice(&packet.data[n..]);
                        }
                        return Ok(n);
                    }

                    // 处理 FIN
                    if (packet.flags & TCP_FLAG_FIN) != 0 {
                        self.ack = packet.sequence_number + 1;
                        self.inner.send_tcp(
                            self.conn_id.remote_ip,
                            self.conn_id.local_port,
                            self.conn_id.remote_port,
                            self.seq,
                            self.ack,
                            TCP_FLAG_ACK,
                            Bytes::new(),
                        )?;

                        match self.state {
                            TcpState::Established => self.state = TcpState::CloseWait,
                            TcpState::FinWait1 => self.state = TcpState::Closing,
                            TcpState::FinWait2 => self.state = TcpState::TimeWait,
                            _ => {}
                        }
                        return Ok(0);
                    }

                    // 处理单纯的 ACK (可能是对我们 FIN 的回应)
                    if (packet.flags & TCP_FLAG_ACK) != 0 {
                        match self.state {
                            TcpState::FinWait1 => self.state = TcpState::FinWait2,
                            TcpState::LastAck => self.state = TcpState::Closed,
                            TcpState::Closing => self.state = TcpState::TimeWait,
                            _ => {}
                        }
                        if self.state == TcpState::Closed || self.state == TcpState::TimeWait {
                            return Ok(0);
                        }
                    }
                }
                Err(_) => return Ok(0),
            }
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.state != TcpState::Established && self.state != TcpState::CloseWait {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Socket not connected",
            ));
        }

        let data = Bytes::copy_from_slice(buf);
        self.inner.send_tcp(
            self.conn_id.remote_ip,
            self.conn_id.local_port,
            self.conn_id.remote_port,
            self.seq,
            self.ack,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            data,
        )?;

        let n = buf.len() as u32;
        self.seq += n;

        // 简化：等待 ACK (实际上应该在读线程处理，但按要求简化)
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(packet) = self.rx.recv_timeout(Duration::from_millis(100)) {
                if (packet.flags & TCP_FLAG_ACK) != 0 && packet.acknowledgment_number >= self.seq {
                    return Ok(buf.len());
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Wait for ACK timeout",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = self.close();
        Self::remove_iptables_rule(&self.interface_name, self.conn_id.local_port);

        let mut streams = self.inner.streams.lock().unwrap();
        streams.remove(&self.conn_id);
    }
}
