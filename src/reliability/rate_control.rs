//! Fixed Rate Control Module
//!
//! Implements fixed-rate packet transmission that does NOT back off on packet loss.
//! This is a key differentiator from traditional TCP congestion control.
//! The rate remains constant regardless of network conditions, relying on
//! redundancy for reliability instead of rate adaptation.

use std::time::{Duration, Instant};

/// Configuration for rate control
#[derive(Debug, Clone)]
pub struct RateControlConfig {
    /// Target packets per second
    pub packets_per_second: u64,
    /// Burst size (max packets to send at once)
    pub burst_size: usize,
    /// Minimum interval between sends (derived from packets_per_second)
    min_interval: Duration,
}

impl RateControlConfig {
    /// Create a new rate control configuration
    ///
    /// # Arguments
    /// * `packets_per_second` - Target send rate (clamped to 1..=1_000_000)
    /// * `burst_size` - Maximum packets to send in a burst (clamped to 1..=1000)
    pub fn new(packets_per_second: u64, burst_size: usize) -> Self {
        let pps = packets_per_second.clamp(1, 1_000_000);
        let interval_nanos = 1_000_000_000 / pps;

        Self {
            packets_per_second: pps,
            burst_size: burst_size.clamp(1, 1000),
            min_interval: Duration::from_nanos(interval_nanos),
        }
    }

    /// Create a configuration for a specific bitrate
    ///
    /// # Arguments
    /// * `bits_per_second` - Target bitrate
    /// * `packet_size` - Average packet size in bytes
    pub fn from_bitrate(bits_per_second: u64, packet_size: usize) -> Self {
        let bytes_per_second = bits_per_second / 8;
        let packets_per_second = bytes_per_second / packet_size.max(1) as u64;
        Self::new(packets_per_second.max(1), 16)
    }

    /// Get the minimum interval between packet sends
    pub fn min_interval(&self) -> Duration {
        self.min_interval
    }
}

impl Default for RateControlConfig {
    fn default() -> Self {
        Self::new(10000, 16) // 10k pps, burst of 16
    }
}

/// Statistics for rate control
#[derive(Debug, Clone, Default)]
pub struct RateControlStats {
    /// Total packets allowed through
    pub packets_allowed: u64,
    /// Total packets throttled (rate limited)
    pub packets_throttled: u64,
    /// Total bytes allowed through
    pub bytes_allowed: u64,
    /// Current measured rate (packets per second)
    pub current_rate: f64,
    /// Time spent throttled
    pub throttle_time: Duration,
}

impl RateControlStats {
    /// Get the throttle rate (0.0 to 1.0)
    pub fn throttle_rate(&self) -> f64 {
        let total = self.packets_allowed + self.packets_throttled;
        if total == 0 {
            return 0.0;
        }
        self.packets_throttled as f64 / total as f64
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Maximum tokens (bucket capacity)
    max_tokens: f64,
    /// Tokens added per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: usize, rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            max_tokens: capacity as f64,
            refill_rate: rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn try_consume(&mut self, count: f64) -> bool {
        self.refill();
        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }

    fn time_until_available(&self, count: f64) -> Duration {
        if self.tokens >= count {
            return Duration::ZERO;
        }
        let needed = count - self.tokens;
        let seconds = needed / self.refill_rate;
        Duration::from_secs_f64(seconds)
    }
}

/// Fixed rate controller
///
/// Key characteristics:
/// - Rate is FIXED and does NOT decrease on packet loss
/// - Uses token bucket algorithm for smooth rate limiting
/// - Supports burst transmission for efficiency
/// - Designed for consistent throughput regardless of network conditions
#[derive(Debug)]
pub struct RateController {
    /// Configuration
    config: RateControlConfig,
    /// Token bucket for rate limiting
    bucket: TokenBucket,
    /// Statistics
    stats: RateControlStats,
    /// Last send time (for rate calculation)
    last_send: Option<Instant>,
    /// Packets sent in current measurement window
    window_packets: u64,
    /// Window start time
    window_start: Instant,
}

impl RateController {
    /// Create a new rate controller with the given configuration
    pub fn new(config: RateControlConfig) -> Self {
        Self {
            bucket: TokenBucket::new(
                config.burst_size,
                config.packets_per_second as f64,
            ),
            stats: RateControlStats::default(),
            last_send: None,
            window_packets: 0,
            window_start: Instant::now(),
            config,
        }
    }

    /// Create a rate controller with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RateControlConfig::default())
    }

    /// Create a rate controller for a specific packets-per-second rate
    pub fn with_rate(packets_per_second: u64) -> Self {
        Self::new(RateControlConfig::new(packets_per_second, 16))
    }

    /// Check if a packet can be sent now
    ///
    /// Returns true if the rate limit allows sending, false otherwise.
    /// This does NOT consume a token - use `consume()` after actually sending.
    pub fn can_send(&mut self) -> bool {
        self.bucket.refill();
        self.bucket.tokens >= 1.0
    }

    /// Try to send a packet
    ///
    /// Returns true if the packet was allowed, false if rate limited.
    /// Updates statistics accordingly.
    pub fn try_send(&mut self) -> bool {
        self.update_rate_measurement();

        if self.bucket.try_consume(1.0) {
            self.stats.packets_allowed += 1;
            self.last_send = Some(Instant::now());
            self.window_packets += 1;
            true
        } else {
            self.stats.packets_throttled += 1;
            false
        }
    }

    /// Try to send a packet with a specific size (for byte-based accounting)
    pub fn try_send_bytes(&mut self, bytes: usize) -> bool {
        if self.try_send() {
            self.stats.bytes_allowed += bytes as u64;
            true
        } else {
            false
        }
    }

    /// Get the time until the next packet can be sent
    pub fn time_until_ready(&mut self) -> Duration {
        self.bucket.refill();
        self.bucket.time_until_available(1.0)
    }

    /// Wait until a packet can be sent (blocking)
    ///
    /// Returns the actual wait duration.
    pub fn wait_until_ready(&mut self) -> Duration {
        let wait_time = self.time_until_ready();
        if !wait_time.is_zero() {
            std::thread::sleep(wait_time);
            self.stats.throttle_time += wait_time;
        }
        wait_time
    }

    /// Send a packet, waiting if necessary (blocking)
    ///
    /// Always succeeds after waiting for rate limit.
    pub fn send_blocking(&mut self) -> Duration {
        let waited = self.wait_until_ready();
        let _ = self.try_send();
        waited
    }

    /// Update rate measurement
    fn update_rate_measurement(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs_f64();

        // Update rate every second
        if elapsed >= 1.0 {
            self.stats.current_rate = self.window_packets as f64 / elapsed;
            self.window_packets = 0;
            self.window_start = now;
        }
    }

    /// Get the configured rate (packets per second)
    pub fn configured_rate(&self) -> u64 {
        self.config.packets_per_second
    }

    /// Get the current measured rate (packets per second)
    pub fn current_rate(&self) -> f64 {
        self.stats.current_rate
    }

    /// Get statistics
    pub fn stats(&self) -> &RateControlStats {
        &self.stats
    }

    /// Reset the rate controller
    pub fn reset(&mut self) {
        self.bucket = TokenBucket::new(
            self.config.burst_size,
            self.config.packets_per_second as f64,
        );
        self.stats = RateControlStats::default();
        self.last_send = None;
        self.window_packets = 0;
        self.window_start = Instant::now();
    }

    /// Update the rate (does NOT decrease due to loss - this is intentional)
    ///
    /// This method allows increasing the rate but the rate controller
    /// will NEVER automatically decrease the rate due to packet loss.
    pub fn set_rate(&mut self, packets_per_second: u64) {
        self.config = RateControlConfig::new(packets_per_second, self.config.burst_size);
        self.bucket = TokenBucket::new(
            self.config.burst_size,
            self.config.packets_per_second as f64,
        );
    }

    /// Report packet loss (intentionally does nothing)
    ///
    /// This is a NO-OP by design. The rate controller does NOT back off
    /// on packet loss. This method exists for API compatibility and to
    /// make the design decision explicit.
    #[inline]
    pub fn report_loss(&mut self, _count: usize) {
        // Intentionally empty - NO BACKOFF ON LOSS
        // This is a key design decision for this VPN protocol
    }

    /// Report successful delivery (intentionally does nothing to rate)
    ///
    /// This is a NO-OP by design. The rate remains fixed regardless
    /// of delivery success.
    #[inline]
    pub fn report_success(&mut self, _count: usize) {
        // Intentionally empty - rate is fixed
    }
}

impl Default for RateController {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Leaky bucket rate limiter (alternative implementation)
///
/// Provides smoother rate limiting compared to token bucket.
#[derive(Debug)]
pub struct LeakyBucket {
    /// Bucket capacity
    capacity: usize,
    /// Current water level
    level: f64,
    /// Leak rate (units per second)
    leak_rate: f64,
    /// Last update time
    last_update: Instant,
}

impl LeakyBucket {
    /// Create a new leaky bucket
    pub fn new(capacity: usize, rate: f64) -> Self {
        Self {
            capacity,
            level: 0.0,
            leak_rate: rate,
            last_update: Instant::now(),
        }
    }

    /// Update the bucket (leak water)
    fn update(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.level = (self.level - elapsed * self.leak_rate).max(0.0);
        self.last_update = now;
    }

    /// Try to add water (send a packet)
    pub fn try_add(&mut self, amount: f64) -> bool {
        self.update();
        if self.level + amount <= self.capacity as f64 {
            self.level += amount;
            true
        } else {
            false
        }
    }

    /// Check if bucket can accept more
    pub fn can_accept(&mut self, amount: f64) -> bool {
        self.update();
        self.level + amount <= self.capacity as f64
    }

    /// Get current fill level (0.0 to 1.0)
    pub fn fill_level(&mut self) -> f64 {
        self.update();
        self.level / self.capacity as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_controller_creation() {
        let controller = RateController::with_rate(1000);
        assert_eq!(controller.configured_rate(), 1000);
    }

    #[test]
    fn test_can_send_initially() {
        let mut controller = RateController::with_rate(1000);
        assert!(controller.can_send());
    }

    #[test]
    fn test_try_send() {
        let mut controller = RateController::with_rate(1000);
        assert!(controller.try_send());
        assert_eq!(controller.stats().packets_allowed, 1);
    }

    #[test]
    fn test_burst_allowed() {
        let config = RateControlConfig::new(1000, 10);
        let mut controller = RateController::new(config);

        // Should allow burst of 10
        for _ in 0..10 {
            assert!(controller.try_send());
        }
    }

    #[test]
    fn test_rate_limiting() {
        let config = RateControlConfig::new(100, 2); // 100 pps, burst of 2
        let mut controller = RateController::new(config);

        // Exhaust burst
        assert!(controller.try_send());
        assert!(controller.try_send());

        // Should be throttled now
        assert!(!controller.try_send());
        assert_eq!(controller.stats().packets_throttled, 1);
    }

    #[test]
    fn test_no_backoff_on_loss() {
        let mut controller = RateController::with_rate(1000);
        let initial_rate = controller.configured_rate();

        // Report loss - rate should NOT change
        controller.report_loss(100);
        assert_eq!(controller.configured_rate(), initial_rate);

        // Report more loss - still no change
        controller.report_loss(1000);
        assert_eq!(controller.configured_rate(), initial_rate);
    }

    #[test]
    fn test_rate_stays_fixed() {
        let mut controller = RateController::with_rate(5000);

        // Simulate heavy loss scenario
        for _ in 0..100 {
            controller.report_loss(10);
        }

        // Rate must remain at 5000 - this is the KEY invariant
        assert_eq!(controller.configured_rate(), 5000);
    }

    #[test]
    fn test_manual_rate_change() {
        let mut controller = RateController::with_rate(1000);
        controller.set_rate(2000);
        assert_eq!(controller.configured_rate(), 2000);
    }

    #[test]
    fn test_stats() {
        let config = RateControlConfig::new(100, 2);
        let mut controller = RateController::new(config);

        controller.try_send();
        controller.try_send();
        controller.try_send(); // This should be throttled

        let stats = controller.stats();
        assert_eq!(stats.packets_allowed, 2);
        assert_eq!(stats.packets_throttled, 1);
    }

    #[test]
    fn test_leaky_bucket() {
        let mut bucket = LeakyBucket::new(10, 100.0);

        // Should accept initially
        assert!(bucket.try_add(5.0));
        assert!(bucket.try_add(5.0));

        // Should reject when full
        assert!(!bucket.try_add(1.0));
    }

    #[test]
    fn test_config_from_bitrate() {
        // 10 Mbps with 1000 byte packets = 1250 pps
        let config = RateControlConfig::from_bitrate(10_000_000, 1000);
        assert_eq!(config.packets_per_second, 1250);
    }

    #[test]
    fn test_time_until_ready() {
        let config = RateControlConfig::new(100, 1); // 100 pps, burst of 1
        let mut controller = RateController::new(config);

        // First packet should be immediate
        assert!(controller.try_send());

        // Next packet should require waiting
        let wait = controller.time_until_ready();
        assert!(wait > Duration::ZERO);
        assert!(wait <= Duration::from_millis(11)); // ~10ms for 100 pps
    }
}
