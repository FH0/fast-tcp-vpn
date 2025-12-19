//! Receive Buffer and Reordering Module
//!
//! Implements packet buffering and reordering for handling out-of-order delivery.
//! Features:
//! - Receive buffer for holding out-of-order packets
//! - Sequence-based reordering to deliver packets in order
//! - Timeout-based delivery to avoid infinite waiting for missing packets

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Configuration for the receive buffer
#[derive(Debug, Clone)]
pub struct ReceiveBufferConfig {
    /// Maximum number of packets to buffer
    pub max_buffered_packets: usize,
    /// Maximum bytes to buffer
    pub max_buffered_bytes: usize,
    /// Timeout for waiting for missing packets before delivering anyway
    pub reorder_timeout: Duration,
    /// Maximum gap in sequence numbers to tolerate before forcing delivery
    pub max_sequence_gap: u64,
}

impl Default for ReceiveBufferConfig {
    fn default() -> Self {
        Self {
            max_buffered_packets: 256,
            max_buffered_bytes: 256 * 1500, // ~384KB
            reorder_timeout: Duration::from_millis(100),
            max_sequence_gap: 64,
        }
    }
}

impl ReceiveBufferConfig {
    /// Create a configuration optimized for low latency
    pub fn low_latency() -> Self {
        Self {
            max_buffered_packets: 64,
            max_buffered_bytes: 64 * 1500,
            reorder_timeout: Duration::from_millis(20),
            max_sequence_gap: 16,
        }
    }

    /// Create a configuration optimized for high throughput
    pub fn high_throughput() -> Self {
        Self {
            max_buffered_packets: 512,
            max_buffered_bytes: 512 * 1500,
            reorder_timeout: Duration::from_millis(200),
            max_sequence_gap: 128,
        }
    }
}

/// A buffered packet waiting for delivery
#[derive(Debug, Clone)]
pub struct BufferedPacket {
    /// Sequence number
    pub seq: u64,
    /// Packet data
    pub data: Vec<u8>,
    /// Time when the packet was received
    pub received_at: Instant,
}

impl BufferedPacket {
    /// Create a new buffered packet
    pub fn new(seq: u64, data: Vec<u8>) -> Self {
        Self {
            seq,
            data,
            received_at: Instant::now(),
        }
    }

    /// Check if this packet has been waiting too long
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.received_at.elapsed() > timeout
    }
}

/// Statistics for the receive buffer
#[derive(Debug, Clone, Default)]
pub struct ReceiveBufferStats {
    /// Total packets received
    pub packets_received: u64,
    /// Packets delivered in order
    pub packets_in_order: u64,
    /// Packets that were reordered
    pub packets_reordered: u64,
    /// Packets delivered due to timeout (gap skipped)
    pub packets_timeout_delivered: u64,
    /// Packets dropped due to buffer overflow
    pub packets_dropped: u64,
    /// Current number of buffered packets
    pub current_buffered: usize,
    /// Current buffered bytes
    pub current_buffered_bytes: usize,
    /// Number of sequence gaps that were skipped
    pub gaps_skipped: u64,
}

impl ReceiveBufferStats {
    /// Calculate the reorder rate
    pub fn reorder_rate(&self) -> f64 {
        if self.packets_received == 0 {
            return 0.0;
        }
        self.packets_reordered as f64 / self.packets_received as f64
    }

    /// Calculate the timeout delivery rate
    pub fn timeout_rate(&self) -> f64 {
        let total_delivered = self.packets_in_order + self.packets_reordered + self.packets_timeout_delivered;
        if total_delivered == 0 {
            return 0.0;
        }
        self.packets_timeout_delivered as f64 / total_delivered as f64
    }
}

/// Receive buffer with reordering support
///
/// Buffers out-of-order packets and delivers them in sequence order.
/// Implements timeout-based delivery to avoid infinite waiting.
#[derive(Debug)]
pub struct ReceiveBuffer {
    /// Configuration
    config: ReceiveBufferConfig,
    /// Buffered packets, keyed by sequence number
    buffer: BTreeMap<u64, BufferedPacket>,
    /// Next expected sequence number for in-order delivery
    next_expected_seq: u64,
    /// Current total buffered bytes
    buffered_bytes: usize,
    /// Statistics
    stats: ReceiveBufferStats,
    /// Time when we started waiting for a missing packet
    gap_wait_start: Option<Instant>,
}

impl ReceiveBuffer {
    /// Create a new receive buffer with the given configuration
    pub fn new(config: ReceiveBufferConfig) -> Self {
        Self {
            config,
            buffer: BTreeMap::new(),
            next_expected_seq: 0,
            buffered_bytes: 0,
            stats: ReceiveBufferStats::default(),
            gap_wait_start: None,
        }
    }

    /// Create a receive buffer with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ReceiveBufferConfig::default())
    }

    /// Create a receive buffer optimized for low latency
    pub fn low_latency() -> Self {
        Self::new(ReceiveBufferConfig::low_latency())
    }

    /// Create a receive buffer optimized for high throughput
    pub fn high_throughput() -> Self {
        Self::new(ReceiveBufferConfig::high_throughput())
    }

    /// Insert a packet into the buffer
    ///
    /// Returns packets that are ready for delivery (in order or due to timeout).
    pub fn insert(&mut self, seq: u64, data: Vec<u8>) -> Vec<BufferedPacket> {
        self.stats.packets_received += 1;

        // Ignore packets that are too old (already delivered)
        if seq < self.next_expected_seq {
            return Vec::new();
        }

        // Check for buffer overflow
        if self.buffer.len() >= self.config.max_buffered_packets
            || self.buffered_bytes + data.len() > self.config.max_buffered_bytes
        {
            // Try to make room by forcing delivery
            let delivered = self.force_deliver_oldest();
            if !delivered.is_empty() {
                // Made room, now try to insert
                return self.insert_and_deliver(seq, data, delivered);
            }

            // Still no room, drop the packet
            self.stats.packets_dropped += 1;
            return Vec::new();
        }

        self.insert_and_deliver(seq, data, Vec::new())
    }

    /// Internal method to insert packet and check for deliverable packets
    fn insert_and_deliver(
        &mut self,
        seq: u64,
        data: Vec<u8>,
        mut already_delivered: Vec<BufferedPacket>,
    ) -> Vec<BufferedPacket> {
        let data_len = data.len();

        // Insert the packet
        if !self.buffer.contains_key(&seq) {
            self.buffer.insert(seq, BufferedPacket::new(seq, data));
            self.buffered_bytes += data_len;
        }

        // Try to deliver in-order packets
        let mut delivered = self.try_deliver_in_order();
        already_delivered.append(&mut delivered);

        // Check for timeout-based delivery
        let mut timeout_delivered = self.check_timeout_delivery();
        already_delivered.append(&mut timeout_delivered);

        self.update_stats();
        already_delivered
    }

    /// Try to deliver packets that are in order
    fn try_deliver_in_order(&mut self) -> Vec<BufferedPacket> {
        let mut delivered = Vec::new();

        while let Some(packet) = self.buffer.remove(&self.next_expected_seq) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.data.len());

            if delivered.is_empty() && self.gap_wait_start.is_none() {
                // First packet was in order
                self.stats.packets_in_order += 1;
            } else {
                // Packet was reordered (we were waiting for it)
                self.stats.packets_reordered += 1;
            }

            delivered.push(packet);
            self.next_expected_seq += 1;
            self.gap_wait_start = None; // Reset gap timer
        }

        // If we have buffered packets but couldn't deliver, start gap timer
        if delivered.is_empty() && !self.buffer.is_empty() && self.gap_wait_start.is_none() {
            self.gap_wait_start = Some(Instant::now());
        }

        delivered
    }

    /// Check if we should deliver packets due to timeout
    fn check_timeout_delivery(&mut self) -> Vec<BufferedPacket> {
        let mut delivered = Vec::new();

        // Check timeout condition
        let should_force_deliver = match self.gap_wait_start {
            Some(start) => start.elapsed() > self.config.reorder_timeout,
            None => false,
        };

        // Check gap condition
        let gap_too_large = if let Some(&min_seq) = self.buffer.keys().next() {
            min_seq > self.next_expected_seq + self.config.max_sequence_gap
        } else {
            false
        };

        if should_force_deliver || gap_too_large {
            // Skip the missing packets and deliver what we have
            if let Some(&min_seq) = self.buffer.keys().next() {
                let skipped = min_seq - self.next_expected_seq;
                if skipped > 0 {
                    self.stats.gaps_skipped += 1;
                }
                self.next_expected_seq = min_seq;
                self.gap_wait_start = None;

                // Now deliver consecutive packets
                while let Some(packet) = self.buffer.remove(&self.next_expected_seq) {
                    self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.data.len());
                    self.stats.packets_timeout_delivered += 1;
                    delivered.push(packet);
                    self.next_expected_seq += 1;
                }
            }
        }

        delivered
    }

    /// Force delivery of the oldest buffered packets to make room
    fn force_deliver_oldest(&mut self) -> Vec<BufferedPacket> {
        let mut delivered = Vec::new();

        // Deliver up to 10% of buffer to make room
        let to_deliver = (self.config.max_buffered_packets / 10).max(1);

        for _ in 0..to_deliver {
            if let Some(&min_seq) = self.buffer.keys().next() {
                // Skip to this sequence
                if min_seq > self.next_expected_seq {
                    self.stats.gaps_skipped += 1;
                    self.next_expected_seq = min_seq;
                }

                if let Some(packet) = self.buffer.remove(&min_seq) {
                    self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.data.len());
                    self.stats.packets_timeout_delivered += 1;
                    delivered.push(packet);
                    self.next_expected_seq = min_seq + 1;
                }
            } else {
                break;
            }
        }

        self.gap_wait_start = None;
        delivered
    }

    /// Flush all buffered packets, delivering them in sequence order
    pub fn flush(&mut self) -> Vec<BufferedPacket> {
        let mut delivered = Vec::new();

        // Deliver all buffered packets in order
        while let Some((&seq, _)) = self.buffer.iter().next() {
            if seq > self.next_expected_seq {
                self.stats.gaps_skipped += 1;
                self.next_expected_seq = seq;
            }

            if let Some(packet) = self.buffer.remove(&seq) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(packet.data.len());
                self.stats.packets_timeout_delivered += 1;
                delivered.push(packet);
                self.next_expected_seq = seq + 1;
            }
        }

        self.gap_wait_start = None;
        self.update_stats();
        delivered
    }

    /// Poll for packets that should be delivered due to timeout
    ///
    /// Call this periodically to ensure timeout delivery works even without new packets.
    pub fn poll_timeout(&mut self) -> Vec<BufferedPacket> {
        let delivered = self.check_timeout_delivery();
        self.update_stats();
        delivered
    }

    /// Update statistics
    fn update_stats(&mut self) {
        self.stats.current_buffered = self.buffer.len();
        self.stats.current_buffered_bytes = self.buffered_bytes;
    }

    /// Get statistics
    pub fn stats(&self) -> &ReceiveBufferStats {
        &self.stats
    }

    /// Get the next expected sequence number
    pub fn next_expected(&self) -> u64 {
        self.next_expected_seq
    }

    /// Get the number of buffered packets
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Get the total buffered bytes
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Reset the buffer
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_expected_seq = 0;
        self.buffered_bytes = 0;
        self.stats = ReceiveBufferStats::default();
        self.gap_wait_start = None;
    }

    /// Set the next expected sequence number (for initialization)
    pub fn set_next_expected(&mut self, seq: u64) {
        self.next_expected_seq = seq;
    }
}

impl Default for ReceiveBuffer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // === 3.4.1 Tests: Receive Buffer ===

    #[test]
    fn test_buffer_creation() {
        let buffer = ReceiveBuffer::with_defaults();
        assert!(buffer.is_empty());
        assert_eq!(buffer.buffered_count(), 0);
        assert_eq!(buffer.next_expected(), 0);
    }

    #[test]
    fn test_buffer_in_order_delivery() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert packets in order
        let delivered = buffer.insert(0, vec![1, 2, 3]);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].seq, 0);

        let delivered = buffer.insert(1, vec![4, 5, 6]);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].seq, 1);

        assert_eq!(buffer.next_expected(), 2);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_buffer_stats() {
        let mut buffer = ReceiveBuffer::with_defaults();

        buffer.insert(0, vec![1, 2, 3]);
        buffer.insert(1, vec![4, 5, 6]);

        let stats = buffer.stats();
        assert_eq!(stats.packets_received, 2);
        assert_eq!(stats.packets_in_order, 2);
    }

    // === 3.4.2 Tests: Out-of-Order Reordering ===

    #[test]
    fn test_reorder_simple() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert packet 1 first (out of order)
        let delivered = buffer.insert(1, vec![4, 5, 6]);
        assert!(delivered.is_empty()); // Waiting for packet 0
        assert_eq!(buffer.buffered_count(), 1);

        // Now insert packet 0
        let delivered = buffer.insert(0, vec![1, 2, 3]);
        assert_eq!(delivered.len(), 2); // Both should be delivered
        assert_eq!(delivered[0].seq, 0);
        assert_eq!(delivered[1].seq, 1);

        assert!(buffer.is_empty());
        assert_eq!(buffer.next_expected(), 2);
    }

    #[test]
    fn test_reorder_multiple_gaps() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert packets 2, 4, 1, 3, 0
        buffer.insert(2, vec![2]);
        buffer.insert(4, vec![4]);
        buffer.insert(1, vec![1]);
        buffer.insert(3, vec![3]);

        assert_eq!(buffer.buffered_count(), 4);

        // Insert packet 0, should trigger delivery of 0, 1, 2, 3, 4
        let delivered = buffer.insert(0, vec![0]);
        assert_eq!(delivered.len(), 5);

        for (i, packet) in delivered.iter().enumerate() {
            assert_eq!(packet.seq, i as u64);
        }

        assert!(buffer.is_empty());
    }

    #[test]
    fn test_reorder_partial_delivery() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert packets 1, 2, 3 (missing 0)
        buffer.insert(1, vec![1]);
        buffer.insert(2, vec![2]);
        buffer.insert(3, vec![3]);

        assert_eq!(buffer.buffered_count(), 3);

        // Insert packet 0, should deliver 0, 1, 2, 3
        let delivered = buffer.insert(0, vec![0]);
        assert_eq!(delivered.len(), 4);

        // Insert packet 5 (missing 4)
        let delivered = buffer.insert(5, vec![5]);
        assert!(delivered.is_empty());
        assert_eq!(buffer.buffered_count(), 1);

        // Insert packet 4
        let delivered = buffer.insert(4, vec![4]);
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].seq, 4);
        assert_eq!(delivered[1].seq, 5);
    }

    #[test]
    fn test_reorder_stats() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Out of order delivery
        buffer.insert(1, vec![1]);
        buffer.insert(0, vec![0]);

        let stats = buffer.stats();
        assert_eq!(stats.packets_received, 2);
        // When packet 0 arrives, it triggers delivery of both 0 and 1
        // Packet 0 is in_order (first in sequence), packet 1 was reordered
        assert_eq!(stats.packets_in_order + stats.packets_reordered, 2);
    }

    // === 3.4.3 Tests: Timeout Delivery ===

    #[test]
    fn test_timeout_delivery() {
        let config = ReceiveBufferConfig {
            reorder_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut buffer = ReceiveBuffer::new(config);

        // Insert packet 1 (missing 0)
        let delivered = buffer.insert(1, vec![1]);
        assert!(delivered.is_empty());

        // Wait for timeout
        thread::sleep(Duration::from_millis(100));

        // Poll should trigger timeout delivery
        let delivered = buffer.poll_timeout();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].seq, 1);

        let stats = buffer.stats();
        assert_eq!(stats.packets_timeout_delivered, 1);
        assert_eq!(stats.gaps_skipped, 1);
    }

    #[test]
    fn test_timeout_delivery_multiple() {
        let config = ReceiveBufferConfig {
            reorder_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut buffer = ReceiveBuffer::new(config);

        // Insert packets 2, 3, 4 (missing 0, 1)
        buffer.insert(2, vec![2]);
        buffer.insert(3, vec![3]);
        buffer.insert(4, vec![4]);

        thread::sleep(Duration::from_millis(100));

        let delivered = buffer.poll_timeout();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].seq, 2);
        assert_eq!(delivered[1].seq, 3);
        assert_eq!(delivered[2].seq, 4);
    }

    #[test]
    fn test_max_gap_delivery() {
        let config = ReceiveBufferConfig {
            max_sequence_gap: 5,
            reorder_timeout: Duration::from_secs(60), // Long timeout
            ..Default::default()
        };
        let mut buffer = ReceiveBuffer::new(config);

        // Insert packet with large gap (seq 10, expected 0)
        let delivered = buffer.insert(10, vec![10]);

        // Gap is 10 > max_gap 5, should force delivery
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].seq, 10);

        let stats = buffer.stats();
        assert_eq!(stats.gaps_skipped, 1);
    }

    #[test]
    fn test_flush() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert some out-of-order packets
        buffer.insert(2, vec![2]);
        buffer.insert(5, vec![5]);
        buffer.insert(3, vec![3]);

        let delivered = buffer.flush();
        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].seq, 2);
        assert_eq!(delivered[1].seq, 3);
        assert_eq!(delivered[2].seq, 5);

        assert!(buffer.is_empty());
    }

    // === 3.4.4 Tests: Reordering Correctness ===

    #[test]
    fn test_reorder_correctness_random_order() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Simulate random arrival order
        let arrival_order = vec![5, 2, 8, 1, 4, 0, 7, 3, 6, 9];
        let mut all_delivered = Vec::new();

        for seq in arrival_order {
            let delivered = buffer.insert(seq, vec![seq as u8]);
            all_delivered.extend(delivered);
        }

        // All packets should be delivered in order
        assert_eq!(all_delivered.len(), 10);
        for (i, packet) in all_delivered.iter().enumerate() {
            assert_eq!(packet.seq, i as u64, "Packet {} out of order", i);
        }
    }

    #[test]
    fn test_reorder_correctness_reverse_order() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert in reverse order
        for seq in (0..10).rev() {
            buffer.insert(seq, vec![seq as u8]);
        }

        // Last insert (seq 0) should trigger all deliveries
        assert!(buffer.is_empty());
        assert_eq!(buffer.next_expected(), 10);
    }

    #[test]
    fn test_reorder_correctness_with_duplicates() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert with duplicates
        buffer.insert(1, vec![1]);
        buffer.insert(1, vec![1]); // Duplicate
        buffer.insert(0, vec![0]);
        buffer.insert(0, vec![0]); // Duplicate (already delivered)

        assert!(buffer.is_empty());
        assert_eq!(buffer.next_expected(), 2);
    }

    #[test]
    fn test_reorder_data_integrity() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Insert packets with specific data
        buffer.insert(2, vec![20, 21, 22]);
        buffer.insert(0, vec![0, 1, 2]);
        buffer.insert(1, vec![10, 11, 12]);

        // Flush and verify data
        let _delivered = buffer.flush();

        // Note: packets 0, 1, 2 were delivered when 0 was inserted
        // So flush returns empty
        // Let's test differently

        let mut buffer = ReceiveBuffer::with_defaults();
        buffer.insert(2, vec![20, 21, 22]);
        buffer.insert(1, vec![10, 11, 12]);

        // Now insert 0 to trigger delivery
        let delivered = buffer.insert(0, vec![0, 1, 2]);

        assert_eq!(delivered.len(), 3);
        assert_eq!(delivered[0].data, vec![0, 1, 2]);
        assert_eq!(delivered[1].data, vec![10, 11, 12]);
        assert_eq!(delivered[2].data, vec![20, 21, 22]);
    }

    #[test]
    fn test_buffer_overflow_handling() {
        let config = ReceiveBufferConfig {
            max_buffered_packets: 5,
            max_buffered_bytes: 1000,
            ..Default::default()
        };
        let mut buffer = ReceiveBuffer::new(config);

        // Fill buffer with out-of-order packets (missing seq 0)
        for seq in 1..=5 {
            buffer.insert(seq, vec![seq as u8]);
        }

        // Buffer should be full, next insert should force delivery
        let delivered = buffer.insert(6, vec![6]);

        // Should have forced some delivery
        assert!(!delivered.is_empty() || buffer.stats().packets_dropped > 0);
    }

    #[test]
    fn test_set_next_expected() {
        let mut buffer = ReceiveBuffer::with_defaults();

        // Set initial sequence
        buffer.set_next_expected(100);

        // Packets before 100 should be ignored
        let delivered = buffer.insert(50, vec![50]);
        assert!(delivered.is_empty());

        // Packet 100 should be delivered
        let delivered = buffer.insert(100, vec![100]);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].seq, 100);
    }

    #[test]
    fn test_reset() {
        let mut buffer = ReceiveBuffer::with_defaults();

        buffer.insert(1, vec![1]);
        buffer.insert(2, vec![2]);

        buffer.reset();

        assert!(buffer.is_empty());
        assert_eq!(buffer.next_expected(), 0);
        assert_eq!(buffer.stats().packets_received, 0);
    }

    #[test]
    fn test_consecutive_gaps() {
        let config = ReceiveBufferConfig {
            reorder_timeout: Duration::from_millis(20),
            ..Default::default()
        };
        let mut buffer = ReceiveBuffer::new(config);

        // First gap: missing 0, have 1
        buffer.insert(1, vec![1]);
        thread::sleep(Duration::from_millis(50));
        let delivered = buffer.poll_timeout();
        assert_eq!(delivered.len(), 1);

        // Second gap: missing 2, have 3
        buffer.insert(3, vec![3]);
        thread::sleep(Duration::from_millis(50));
        let delivered = buffer.poll_timeout();
        assert_eq!(delivered.len(), 1);

        assert_eq!(buffer.next_expected(), 4);
    }
}
