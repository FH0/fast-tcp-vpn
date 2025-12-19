//! No-Backoff Send Window Module
//!
//! Implements a send window that does NOT shrink due to packet loss.
//! This is a key differentiator from traditional TCP congestion control.
//! The window maintains a fixed size regardless of network conditions,
//! relying on redundancy strategies for reliability instead of retransmission.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Configuration for the send window
#[derive(Debug, Clone)]
pub struct SendWindowConfig {
    /// Fixed window size in packets (does not shrink on loss)
    pub window_size: usize,
    /// Maximum bytes per packet
    pub max_packet_size: usize,
    /// Timeout for considering a packet as "in-flight" (for stats only, no retransmit)
    pub packet_timeout: Duration,
}

impl Default for SendWindowConfig {
    fn default() -> Self {
        Self {
            window_size: 64,
            max_packet_size: 1400,
            packet_timeout: Duration::from_secs(5),
        }
    }
}

impl SendWindowConfig {
    /// Create a new configuration with custom window size
    pub fn with_window_size(window_size: usize) -> Self {
        Self {
            window_size: window_size.clamp(1, 1024),
            ..Default::default()
        }
    }
}

/// Represents a packet in the send window
#[derive(Debug, Clone)]
pub struct WindowPacket {
    /// Sequence number
    pub seq: u64,
    /// Packet data
    pub data: Vec<u8>,
    /// Time when the packet was sent
    pub sent_at: Instant,
    /// Whether acknowledgment was received (for stats only)
    pub acked: bool,
}

impl WindowPacket {
    /// Create a new window packet
    pub fn new(seq: u64, data: Vec<u8>) -> Self {
        Self {
            seq,
            data,
            sent_at: Instant::now(),
            acked: false,
        }
    }

    /// Check if the packet has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.sent_at.elapsed() > timeout
    }
}

/// Statistics for the send window
#[derive(Debug, Clone, Default)]
pub struct SendWindowStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets acknowledged
    pub packets_acked: u64,
    /// Total packets timed out (not retransmitted, just for stats)
    pub packets_timed_out: u64,
    /// Current window utilization (packets in flight)
    pub current_in_flight: usize,
    /// Total bytes sent
    pub bytes_sent: u64,
}

impl SendWindowStats {
    /// Calculate the loss rate based on timeouts
    pub fn timeout_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_timed_out as f64 / self.packets_sent as f64
    }

    /// Calculate the acknowledgment rate
    pub fn ack_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            return 1.0;
        }
        self.packets_acked as f64 / self.packets_sent as f64
    }
}

/// No-backoff send window
///
/// Key characteristics:
/// - Window size is FIXED and does NOT shrink on packet loss
/// - No retransmission - relies on redundancy for reliability
/// - Tracks packets for statistics and acknowledgment only
/// - Designed for low-latency, high-throughput scenarios
#[derive(Debug)]
pub struct SendWindow {
    /// Configuration
    config: SendWindowConfig,
    /// Packets currently in the window
    packets: VecDeque<WindowPacket>,
    /// Next sequence number to assign
    next_seq: u64,
    /// Statistics
    stats: SendWindowStats,
}

impl SendWindow {
    /// Create a new send window with the given configuration
    pub fn new(config: SendWindowConfig) -> Self {
        Self {
            packets: VecDeque::with_capacity(config.window_size),
            config,
            next_seq: 0,
            stats: SendWindowStats::default(),
        }
    }

    /// Create a send window with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SendWindowConfig::default())
    }

    /// Create a send window with a specific window size
    pub fn with_window_size(size: usize) -> Self {
        Self::new(SendWindowConfig::with_window_size(size))
    }

    /// Check if the window has space for more packets
    pub fn has_space(&self) -> bool {
        self.packets.len() < self.config.window_size
    }

    /// Get the number of available slots in the window
    pub fn available_slots(&self) -> usize {
        self.config.window_size.saturating_sub(self.packets.len())
    }

    /// Get the current window size configuration
    pub fn window_size(&self) -> usize {
        self.config.window_size
    }

    /// Get the number of packets currently in flight
    pub fn in_flight(&self) -> usize {
        self.packets.iter().filter(|p| !p.acked).count()
    }

    /// Try to add a packet to the window
    ///
    /// Returns the assigned sequence number if successful, None if window is full.
    /// Note: Window being full does NOT trigger any backoff - caller should
    /// wait or use rate limiting.
    pub fn try_send(&mut self, data: Vec<u8>) -> Option<u64> {
        if !self.has_space() {
            return None;
        }

        let seq = self.next_seq;
        self.next_seq += 1;

        let packet = WindowPacket::new(seq, data.clone());
        self.stats.bytes_sent += data.len() as u64;
        self.stats.packets_sent += 1;

        self.packets.push_back(packet);
        self.stats.current_in_flight = self.in_flight();

        Some(seq)
    }

    /// Acknowledge a packet by sequence number
    ///
    /// This marks the packet as acknowledged but does NOT affect window size.
    /// Returns true if the packet was found and acknowledged.
    pub fn acknowledge(&mut self, seq: u64) -> bool {
        for packet in self.packets.iter_mut() {
            if packet.seq == seq && !packet.acked {
                packet.acked = true;
                self.stats.packets_acked += 1;
                self.stats.current_in_flight = self.in_flight();
                return true;
            }
        }
        false
    }

    /// Acknowledge all packets up to and including the given sequence number
    pub fn acknowledge_cumulative(&mut self, seq: u64) -> usize {
        let mut count = 0;
        for packet in self.packets.iter_mut() {
            if packet.seq <= seq && !packet.acked {
                packet.acked = true;
                self.stats.packets_acked += 1;
                count += 1;
            }
        }
        self.stats.current_in_flight = self.in_flight();
        count
    }

    /// Clean up old packets from the window
    ///
    /// Removes packets that are either:
    /// - Acknowledged
    /// - Timed out (for stats tracking, NOT for retransmission)
    ///
    /// This frees up window space for new packets.
    pub fn cleanup(&mut self) -> usize {
        let timeout = self.config.packet_timeout;
        let mut removed = 0;

        // Count timed out packets before removal
        for packet in self.packets.iter() {
            if !packet.acked && packet.is_timed_out(timeout) {
                self.stats.packets_timed_out += 1;
            }
        }

        // Remove acknowledged and timed out packets from the front
        while let Some(front) = self.packets.front() {
            if front.acked || front.is_timed_out(timeout) {
                self.packets.pop_front();
                removed += 1;
            } else {
                break;
            }
        }

        self.stats.current_in_flight = self.in_flight();
        removed
    }

    /// Force cleanup of all acknowledged packets regardless of position
    pub fn cleanup_acked(&mut self) -> usize {
        let before = self.packets.len();
        self.packets.retain(|p| !p.acked);
        let removed = before - self.packets.len();
        self.stats.current_in_flight = self.in_flight();
        removed
    }

    /// Get statistics
    pub fn stats(&self) -> &SendWindowStats {
        &self.stats
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.packets.clear();
        self.next_seq = 0;
        self.stats = SendWindowStats::default();
    }

    /// Get the next sequence number that will be assigned
    pub fn next_sequence(&self) -> u64 {
        self.next_seq
    }

    /// Get a reference to packets in the window (for inspection)
    pub fn packets(&self) -> &VecDeque<WindowPacket> {
        &self.packets
    }
}

impl Default for SendWindow {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_creation() {
        let window = SendWindow::with_window_size(32);
        assert_eq!(window.window_size(), 32);
        assert!(window.has_space());
        assert_eq!(window.available_slots(), 32);
    }

    #[test]
    fn test_send_packet() {
        let mut window = SendWindow::with_window_size(4);

        let seq = window.try_send(vec![1, 2, 3]).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(window.available_slots(), 3);
        assert_eq!(window.in_flight(), 1);
    }

    #[test]
    fn test_window_full() {
        let mut window = SendWindow::with_window_size(2);

        assert!(window.try_send(vec![1]).is_some());
        assert!(window.try_send(vec![2]).is_some());
        assert!(window.try_send(vec![3]).is_none()); // Window full
        assert!(!window.has_space());
    }

    #[test]
    fn test_acknowledge() {
        let mut window = SendWindow::with_window_size(4);

        let seq0 = window.try_send(vec![1]).unwrap();
        let seq1 = window.try_send(vec![2]).unwrap();

        assert!(window.acknowledge(seq0));
        assert_eq!(window.in_flight(), 1);

        assert!(window.acknowledge(seq1));
        assert_eq!(window.in_flight(), 0);

        // Double ack should return false
        assert!(!window.acknowledge(seq0));
    }

    #[test]
    fn test_cumulative_ack() {
        let mut window = SendWindow::with_window_size(8);

        for _ in 0..5 {
            window.try_send(vec![1]);
        }

        let acked = window.acknowledge_cumulative(2);
        assert_eq!(acked, 3); // seq 0, 1, 2
        assert_eq!(window.in_flight(), 2); // seq 3, 4
    }

    #[test]
    fn test_cleanup_acked() {
        let mut window = SendWindow::with_window_size(4);

        window.try_send(vec![1]);
        window.try_send(vec![2]);
        window.acknowledge(0);

        let removed = window.cleanup_acked();
        assert_eq!(removed, 1);
        assert_eq!(window.available_slots(), 3);
    }

    #[test]
    fn test_window_does_not_shrink_on_loss() {
        // This is the KEY test - window size must remain constant
        let mut window = SendWindow::with_window_size(4);

        // Fill window
        for _ in 0..4 {
            window.try_send(vec![1]);
        }
        assert_eq!(window.window_size(), 4);

        // Simulate "loss" by not acknowledging and cleaning up
        // Window size should NOT change
        window.cleanup_acked();
        assert_eq!(window.window_size(), 4);

        // Even after timeout simulation, window size stays the same
        assert_eq!(window.window_size(), 4);
    }

    #[test]
    fn test_stats() {
        let mut window = SendWindow::with_window_size(4);

        window.try_send(vec![1, 2, 3]);
        window.try_send(vec![4, 5]);
        window.acknowledge(0);

        let stats = window.stats();
        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.packets_acked, 1);
        assert_eq!(stats.bytes_sent, 5);
    }
}
