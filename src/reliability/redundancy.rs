//! Redundancy Strategy Module
//!
//! Implements multi-packet redundancy strategies for reliable transmission
//! over lossy networks. The core idea is to send multiple copies of each
//! packet to increase delivery probability without relying on retransmission.

use std::collections::VecDeque;

/// Trait for redundancy strategies that determine how many copies of a packet to send
pub trait RedundancyStrategy: Send + Sync {
    /// Returns the number of copies to send for a packet
    ///
    /// # Arguments
    /// * `packet_id` - Unique identifier for the packet (e.g., sequence number)
    ///
    /// # Returns
    /// The number of copies to send (minimum 1)
    fn get_redundancy_count(&self, packet_id: u64) -> usize;

    /// Update the strategy based on feedback (e.g., packet loss detected)
    ///
    /// # Arguments
    /// * `packet_id` - The packet that was acknowledged or lost
    /// * `was_received` - Whether the packet was successfully received
    fn update(&mut self, packet_id: u64, was_received: bool);

    /// Get the current multiplier value (for monitoring/debugging)
    fn current_multiplier(&self) -> f64;

    /// Reset the strategy to its initial state
    fn reset(&mut self);
}

/// Fixed multiplier redundancy strategy
///
/// Sends a fixed number of copies for every packet regardless of network conditions.
/// Simple and predictable, suitable for networks with known, stable loss rates.
#[derive(Debug, Clone)]
pub struct FixedMultiplierStrategy {
    /// Number of copies to send (1 = no redundancy, 2 = 2x, 3 = 3x, etc.)
    multiplier: usize,
}

impl FixedMultiplierStrategy {
    /// Create a new fixed multiplier strategy
    ///
    /// # Arguments
    /// * `multiplier` - Number of copies to send (clamped to 1..=10)
    pub fn new(multiplier: usize) -> Self {
        Self {
            multiplier: multiplier.clamp(1, 10),
        }
    }

    /// Create a 2x redundancy strategy
    pub fn double() -> Self {
        Self::new(2)
    }

    /// Create a 3x redundancy strategy
    pub fn triple() -> Self {
        Self::new(3)
    }

    /// Get the current multiplier
    pub fn multiplier(&self) -> usize {
        self.multiplier
    }

    /// Set a new multiplier value
    pub fn set_multiplier(&mut self, multiplier: usize) {
        self.multiplier = multiplier.clamp(1, 10);
    }
}

impl Default for FixedMultiplierStrategy {
    fn default() -> Self {
        Self::new(2)
    }
}

impl RedundancyStrategy for FixedMultiplierStrategy {
    fn get_redundancy_count(&self, _packet_id: u64) -> usize {
        self.multiplier
    }

    fn update(&mut self, _packet_id: u64, _was_received: bool) {
        // Fixed strategy doesn't adapt
    }

    fn current_multiplier(&self) -> f64 {
        self.multiplier as f64
    }

    fn reset(&mut self) {
        // Nothing to reset for fixed strategy
    }
}

/// Tracks packet loss statistics for adaptive strategies
#[derive(Debug, Clone)]
pub struct PacketLossTracker {
    /// Window of recent packet outcomes (true = received, false = lost)
    window: VecDeque<bool>,
    /// Maximum window size
    window_size: usize,
    /// Number of packets lost in the current window
    lost_count: usize,
}

impl PacketLossTracker {
    /// Create a new packet loss tracker
    ///
    /// # Arguments
    /// * `window_size` - Number of recent packets to track (clamped to 10..=1000)
    pub fn new(window_size: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size: window_size.clamp(10, 1000),
            lost_count: 0,
        }
    }

    /// Record a packet outcome
    pub fn record(&mut self, was_received: bool) {
        // If window is full, remove oldest entry
        if self.window.len() >= self.window_size {
            if let Some(oldest) = self.window.pop_front() {
                if !oldest {
                    self.lost_count = self.lost_count.saturating_sub(1);
                }
            }
        }

        // Add new entry
        if !was_received {
            self.lost_count += 1;
        }
        self.window.push_back(was_received);
    }

    /// Get the current packet loss rate (0.0 to 1.0)
    pub fn loss_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        self.lost_count as f64 / self.window.len() as f64
    }

    /// Get the number of samples in the window
    pub fn sample_count(&self) -> usize {
        self.window.len()
    }

    /// Check if we have enough samples for reliable statistics
    pub fn has_enough_samples(&self) -> bool {
        self.window.len() >= self.window_size / 2
    }

    /// Clear all tracked data
    pub fn clear(&mut self) {
        self.window.clear();
        self.lost_count = 0;
    }
}

impl Default for PacketLossTracker {
    fn default() -> Self {
        Self::new(100)
    }
}

/// Adaptive redundancy strategy
///
/// Dynamically adjusts the number of packet copies based on observed packet loss rate.
/// Uses a sliding window to track recent packet outcomes and adjusts redundancy accordingly.
#[derive(Debug, Clone)]
pub struct AdaptiveStrategy {
    /// Packet loss tracker
    tracker: PacketLossTracker,
    /// Minimum multiplier (floor)
    min_multiplier: usize,
    /// Maximum multiplier (ceiling)
    max_multiplier: usize,
    /// Current calculated multiplier
    current: f64,
    /// Loss rate threshold for increasing redundancy
    increase_threshold: f64,
    /// Loss rate threshold for decreasing redundancy
    decrease_threshold: f64,
    /// How aggressively to adjust (0.0 to 1.0)
    adjustment_rate: f64,
}

impl AdaptiveStrategy {
    /// Create a new adaptive strategy with default parameters
    pub fn new() -> Self {
        Self {
            tracker: PacketLossTracker::new(100),
            min_multiplier: 1,
            max_multiplier: 5,
            current: 2.0,
            increase_threshold: 0.10, // Increase if loss > 10%
            decrease_threshold: 0.02, // Decrease if loss < 2%
            adjustment_rate: 0.1,
        }
    }

    /// Create an adaptive strategy with custom parameters
    ///
    /// # Arguments
    /// * `min_multiplier` - Minimum number of copies (floor)
    /// * `max_multiplier` - Maximum number of copies (ceiling)
    /// * `window_size` - Number of packets to track for loss calculation
    pub fn with_params(min_multiplier: usize, max_multiplier: usize, window_size: usize) -> Self {
        let min = min_multiplier.clamp(1, 10);
        let max = max_multiplier.clamp(min, 10);
        Self {
            tracker: PacketLossTracker::new(window_size),
            min_multiplier: min,
            max_multiplier: max,
            current: min as f64,
            increase_threshold: 0.10,
            decrease_threshold: 0.02,
            adjustment_rate: 0.1,
        }
    }

    /// Set the thresholds for adjusting redundancy
    ///
    /// # Arguments
    /// * `increase_threshold` - Loss rate above which to increase redundancy
    /// * `decrease_threshold` - Loss rate below which to decrease redundancy
    pub fn set_thresholds(&mut self, increase_threshold: f64, decrease_threshold: f64) {
        self.increase_threshold = increase_threshold.clamp(0.0, 1.0);
        self.decrease_threshold = decrease_threshold.clamp(0.0, self.increase_threshold);
    }

    /// Set the adjustment rate (how quickly to adapt)
    pub fn set_adjustment_rate(&mut self, rate: f64) {
        self.adjustment_rate = rate.clamp(0.01, 1.0);
    }

    /// Get the current loss rate
    pub fn loss_rate(&self) -> f64 {
        self.tracker.loss_rate()
    }

    /// Get the packet loss tracker for inspection
    pub fn tracker(&self) -> &PacketLossTracker {
        &self.tracker
    }

    /// Recalculate the multiplier based on current loss rate
    fn recalculate(&mut self) {
        if !self.tracker.has_enough_samples() {
            return;
        }

        let loss_rate = self.tracker.loss_rate();
        let target = if loss_rate > self.increase_threshold {
            // High loss: increase redundancy
            // Formula: target = 1 / (1 - loss_rate), capped at max
            let ideal = 1.0 / (1.0 - loss_rate).max(0.1);
            ideal.min(self.max_multiplier as f64)
        } else if loss_rate < self.decrease_threshold {
            // Low loss: decrease redundancy
            self.min_multiplier as f64
        } else {
            // In the middle: maintain current
            self.current
        };

        // Smooth adjustment
        self.current += (target - self.current) * self.adjustment_rate;
        self.current = self.current.clamp(self.min_multiplier as f64, self.max_multiplier as f64);
    }
}

impl Default for AdaptiveStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl RedundancyStrategy for AdaptiveStrategy {
    fn get_redundancy_count(&self, _packet_id: u64) -> usize {
        // Round to nearest integer, minimum 1
        (self.current.round() as usize).max(1)
    }

    fn update(&mut self, _packet_id: u64, was_received: bool) {
        self.tracker.record(was_received);
        self.recalculate();
    }

    fn current_multiplier(&self) -> f64 {
        self.current
    }

    fn reset(&mut self) {
        self.tracker.clear();
        self.current = self.min_multiplier as f64;
    }
}

/// Generate redundant packets from a single packet
///
/// # Arguments
/// * `packet` - The original packet data
/// * `count` - Number of copies to generate
///
/// # Returns
/// A vector containing `count` copies of the packet
pub fn generate_redundant_packets(packet: &[u8], count: usize) -> Vec<Vec<u8>> {
    let count = count.max(1);
    (0..count).map(|_| packet.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // === 3.1.1 Tests: RedundancyStrategy trait ===

    #[test]
    fn test_trait_object_safety() {
        // Verify trait can be used as trait object
        let strategies: Vec<Box<dyn RedundancyStrategy>> = vec![
            Box::new(FixedMultiplierStrategy::new(2)),
            Box::new(AdaptiveStrategy::new()),
        ];

        for strategy in &strategies {
            assert!(strategy.get_redundancy_count(0) >= 1);
            assert!(strategy.current_multiplier() >= 1.0);
        }
    }

    // === 3.1.2 Tests: Fixed Multiplier Strategy ===

    #[test]
    fn test_fixed_strategy_creation() {
        let strategy = FixedMultiplierStrategy::new(3);
        assert_eq!(strategy.multiplier(), 3);

        let strategy = FixedMultiplierStrategy::double();
        assert_eq!(strategy.multiplier(), 2);

        let strategy = FixedMultiplierStrategy::triple();
        assert_eq!(strategy.multiplier(), 3);
    }

    #[test]
    fn test_fixed_strategy_clamping() {
        let strategy = FixedMultiplierStrategy::new(0);
        assert_eq!(strategy.multiplier(), 1);

        let strategy = FixedMultiplierStrategy::new(100);
        assert_eq!(strategy.multiplier(), 10);
    }

    #[test]
    fn test_fixed_strategy_redundancy_count() {
        let strategy = FixedMultiplierStrategy::new(3);

        // Should always return the same count regardless of packet_id
        assert_eq!(strategy.get_redundancy_count(0), 3);
        assert_eq!(strategy.get_redundancy_count(100), 3);
        assert_eq!(strategy.get_redundancy_count(u64::MAX), 3);
    }

    #[test]
    fn test_fixed_strategy_update_no_change() {
        let mut strategy = FixedMultiplierStrategy::new(2);

        // Updates should not change the multiplier
        strategy.update(0, true);
        assert_eq!(strategy.multiplier(), 2);

        strategy.update(1, false);
        assert_eq!(strategy.multiplier(), 2);
    }

    #[test]
    fn test_fixed_strategy_set_multiplier() {
        let mut strategy = FixedMultiplierStrategy::new(2);

        strategy.set_multiplier(4);
        assert_eq!(strategy.multiplier(), 4);

        strategy.set_multiplier(0);
        assert_eq!(strategy.multiplier(), 1);
    }

    #[test]
    fn test_fixed_strategy_current_multiplier() {
        let strategy = FixedMultiplierStrategy::new(3);
        assert_eq!(strategy.current_multiplier(), 3.0);
    }

    // === 3.1.3 Tests: Adaptive Strategy ===

    #[test]
    fn test_adaptive_strategy_creation() {
        let strategy = AdaptiveStrategy::new();
        assert!(strategy.current_multiplier() >= 1.0);
    }

    #[test]
    fn test_adaptive_strategy_with_params() {
        let strategy = AdaptiveStrategy::with_params(2, 4, 50);
        assert!(strategy.current_multiplier() >= 2.0);
    }

    #[test]
    fn test_adaptive_strategy_increases_on_loss() {
        let mut strategy = AdaptiveStrategy::with_params(1, 5, 20);
        strategy.set_adjustment_rate(0.5); // Faster adjustment for testing

        let initial = strategy.current_multiplier();

        // Simulate high packet loss (50%)
        for i in 0..40 {
            strategy.update(i, i % 2 == 0); // 50% loss
        }

        let after_loss = strategy.current_multiplier();
        assert!(after_loss > initial, "Multiplier should increase with high loss");
    }

    #[test]
    fn test_adaptive_strategy_decreases_on_success() {
        let mut strategy = AdaptiveStrategy::with_params(1, 5, 20);
        strategy.set_adjustment_rate(0.5);

        // First, simulate some loss to increase multiplier
        for i in 0..30 {
            strategy.update(i, i % 2 == 0);
        }

        let after_loss = strategy.current_multiplier();

        // Now simulate perfect delivery
        for i in 30..80 {
            strategy.update(i, true);
        }

        let after_success = strategy.current_multiplier();
        assert!(after_success < after_loss, "Multiplier should decrease with no loss");
    }

    #[test]
    fn test_adaptive_strategy_respects_bounds() {
        let mut strategy = AdaptiveStrategy::with_params(2, 4, 10);
        strategy.set_adjustment_rate(1.0); // Maximum adjustment

        // Simulate extreme loss
        for i in 0..100 {
            strategy.update(i, false);
        }

        assert!(strategy.current_multiplier() <= 4.0, "Should not exceed max");

        // Simulate perfect delivery
        for i in 100..200 {
            strategy.update(i, true);
        }

        assert!(strategy.current_multiplier() >= 2.0, "Should not go below min");
    }

    #[test]
    fn test_adaptive_strategy_reset() {
        let mut strategy = AdaptiveStrategy::with_params(1, 5, 20);

        // Build up some state
        for i in 0..30 {
            strategy.update(i, i % 3 == 0);
        }

        strategy.reset();

        assert_eq!(strategy.loss_rate(), 0.0);
        assert_eq!(strategy.tracker().sample_count(), 0);
    }

    // === 3.1.4 Tests: Redundant Packet Generation ===

    #[test]
    fn test_generate_redundant_packets_basic() {
        let packet = vec![1, 2, 3, 4, 5];
        let copies = generate_redundant_packets(&packet, 3);

        assert_eq!(copies.len(), 3);
        for copy in &copies {
            assert_eq!(copy, &packet);
        }
    }

    #[test]
    fn test_generate_redundant_packets_single() {
        let packet = vec![1, 2, 3];
        let copies = generate_redundant_packets(&packet, 1);

        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0], packet);
    }

    #[test]
    fn test_generate_redundant_packets_zero_becomes_one() {
        let packet = vec![1, 2, 3];
        let copies = generate_redundant_packets(&packet, 0);

        assert_eq!(copies.len(), 1);
    }

    #[test]
    fn test_generate_redundant_packets_empty() {
        let packet: Vec<u8> = vec![];
        let copies = generate_redundant_packets(&packet, 2);

        assert_eq!(copies.len(), 2);
        assert!(copies[0].is_empty());
        assert!(copies[1].is_empty());
    }

    #[test]
    fn test_generate_redundant_packets_independence() {
        let packet = vec![1, 2, 3];
        let mut copies = generate_redundant_packets(&packet, 2);

        // Modify one copy
        copies[0][0] = 99;

        // Other copy should be unaffected (they are independent allocations)
        assert_eq!(copies[1][0], 1);
    }

    // === 3.1.5 Tests: Strategy Switching ===

    #[test]
    fn test_strategy_switching() {
        let mut current_strategy: Box<dyn RedundancyStrategy> =
            Box::new(FixedMultiplierStrategy::new(2));

        assert_eq!(current_strategy.get_redundancy_count(0), 2);

        // Switch to adaptive
        current_strategy = Box::new(AdaptiveStrategy::new());
        assert!(current_strategy.get_redundancy_count(0) >= 1);

        // Switch back to fixed with different multiplier
        current_strategy = Box::new(FixedMultiplierStrategy::new(3));
        assert_eq!(current_strategy.get_redundancy_count(0), 3);
    }

    #[test]
    fn test_strategy_switching_preserves_behavior() {
        let packet = vec![1, 2, 3, 4, 5];

        // Use fixed strategy
        let fixed = FixedMultiplierStrategy::new(2);
        let count1 = fixed.get_redundancy_count(0);
        let copies1 = generate_redundant_packets(&packet, count1);
        assert_eq!(copies1.len(), 2);

        // Use adaptive strategy
        let adaptive = AdaptiveStrategy::new();
        let count2 = adaptive.get_redundancy_count(0);
        let copies2 = generate_redundant_packets(&packet, count2);
        assert!(copies2.len() >= 1);
    }

    // === Packet Loss Tracker Tests ===

    #[test]
    fn test_packet_loss_tracker_basic() {
        let mut tracker = PacketLossTracker::new(10);

        assert_eq!(tracker.loss_rate(), 0.0);
        assert_eq!(tracker.sample_count(), 0);
    }

    #[test]
    fn test_packet_loss_tracker_recording() {
        let mut tracker = PacketLossTracker::new(10);

        tracker.record(true);  // received
        tracker.record(false); // lost
        tracker.record(true);  // received
        tracker.record(false); // lost

        assert_eq!(tracker.sample_count(), 4);
        assert_eq!(tracker.loss_rate(), 0.5);
    }

    #[test]
    fn test_packet_loss_tracker_window_sliding() {
        let mut tracker = PacketLossTracker::new(10);

        // Fill window with losses
        for _ in 0..10 {
            tracker.record(false);
        }
        assert_eq!(tracker.loss_rate(), 1.0);

        // Add successes, pushing out losses
        for _ in 0..10 {
            tracker.record(true);
        }
        assert_eq!(tracker.loss_rate(), 0.0);
    }

    #[test]
    fn test_packet_loss_tracker_clear() {
        let mut tracker = PacketLossTracker::new(10);

        for _ in 0..5 {
            tracker.record(false);
        }

        tracker.clear();

        assert_eq!(tracker.sample_count(), 0);
        assert_eq!(tracker.loss_rate(), 0.0);
    }

    #[test]
    fn test_packet_loss_tracker_has_enough_samples() {
        let mut tracker = PacketLossTracker::new(10);

        assert!(!tracker.has_enough_samples());

        for _ in 0..4 {
            tracker.record(true);
        }
        assert!(!tracker.has_enough_samples());

        tracker.record(true);
        assert!(tracker.has_enough_samples()); // 5 >= 10/2
    }
}
