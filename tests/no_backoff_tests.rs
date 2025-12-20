//! Pressure Tests for No-Backoff Transmission
//!
//! Tests that verify the core design principle: the send window and rate
//! controller do NOT back off when packet loss occurs.

use fast_tcp_vpn::reliability::{
    RateControlConfig, RateController, RedundancyStrategy, SendWindow, SendWindowConfig,
    FixedMultiplierStrategy, AdaptiveStrategy,
};
use std::time::{Duration, Instant};

/// Simulates a lossy network channel
struct LossyChannel {
    loss_rate: f64,
    packets_sent: u64,
    packets_lost: u64,
    packets_delivered: u64,
}

impl LossyChannel {
    fn new(loss_rate: f64) -> Self {
        Self {
            loss_rate: loss_rate.clamp(0.0, 1.0),
            packets_sent: 0,
            packets_lost: 0,
            packets_delivered: 0,
        }
    }

    /// Simulate sending a packet through the lossy channel
    /// Returns true if the packet was delivered, false if lost
    fn send(&mut self, _data: &[u8]) -> bool {
        self.packets_sent += 1;

        // Use a simple deterministic pattern for reproducibility
        // Every N packets, lose one based on loss rate
        let should_lose = if self.loss_rate > 0.0 {
            let period = (1.0 / self.loss_rate) as u64;
            if period > 0 {
                self.packets_sent.is_multiple_of(period)
            } else {
                true
            }
        } else {
            false
        };

        if should_lose {
            self.packets_lost += 1;
            false
        } else {
            self.packets_delivered += 1;
            true
        }
    }

    fn actual_loss_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_lost as f64 / self.packets_sent as f64
    }
}

/// Test: Send window size remains constant under 30% packet loss
#[test]
fn test_send_window_no_shrink_under_30_percent_loss() {
    let config = SendWindowConfig {
        window_size: 64,
        max_packet_size: 1400,
        packet_timeout: Duration::from_millis(100),
    };
    let mut window = SendWindow::new(config);
    let mut channel = LossyChannel::new(0.30);

    let initial_window_size = window.window_size();
    let mut max_window_utilization = 0;

    // Simulate sending 1000 packets
    for i in 0..1000u64 {
        // Try to send
        if let Some(seq) = window.try_send(vec![i as u8; 100]) {
            let delivered = channel.send(&[i as u8; 100]);
            if delivered {
                window.acknowledge(seq);
            }
            // Note: We do NOT shrink window on loss - this is the key behavior
        }

        max_window_utilization = max_window_utilization.max(window.in_flight());

        // Periodic cleanup
        if i % 10 == 0 {
            window.cleanup_acked();
        }

        // CRITICAL ASSERTION: Window size must NEVER shrink
        assert_eq!(
            window.window_size(),
            initial_window_size,
            "Window size must remain constant at {} (was {})",
            initial_window_size,
            window.window_size()
        );
    }

    // Verify we actually had significant loss
    let actual_loss = channel.actual_loss_rate();
    assert!(
        actual_loss >= 0.25,
        "Test requires at least 25% loss, got {:.1}%",
        actual_loss * 100.0
    );

    // Verify window was actually utilized
    assert!(
        max_window_utilization > 0,
        "Window should have been utilized"
    );

    println!(
        "Send window test passed: window_size={}, loss_rate={:.1}%, packets_sent={}",
        initial_window_size,
        actual_loss * 100.0,
        channel.packets_sent
    );
}

/// Test: Rate controller maintains fixed rate under 30% packet loss
#[test]
fn test_rate_controller_no_backoff_under_30_percent_loss() {
    let config = RateControlConfig::new(10000, 100); // 10k pps, burst of 100
    let mut controller = RateController::new(config);
    let mut channel = LossyChannel::new(0.30);

    let initial_rate = controller.configured_rate();

    // Simulate sending packets and reporting loss
    for _ in 0..1000 {
        if controller.try_send() {
            let delivered = channel.send(&[0u8; 100]);
            if !delivered {
                // Report loss - rate should NOT change
                controller.report_loss(1);
            } else {
                controller.report_success(1);
            }
        }

        // CRITICAL ASSERTION: Rate must NEVER decrease due to loss
        assert_eq!(
            controller.configured_rate(),
            initial_rate,
            "Rate must remain constant at {} (was {})",
            initial_rate,
            controller.configured_rate()
        );
    }

    // Verify we actually had significant loss
    let actual_loss = channel.actual_loss_rate();
    assert!(
        actual_loss >= 0.25,
        "Test requires at least 25% loss, got {:.1}%",
        actual_loss * 100.0
    );

    println!(
        "Rate controller test passed: rate={} pps, loss_rate={:.1}%",
        initial_rate,
        actual_loss * 100.0
    );
}

/// Test: Combined system maintains fixed window and rate under 30% loss with redundancy
#[test]
fn test_combined_system_30_percent_loss_with_redundancy() {
    // Setup: 3x redundancy to overcome 30% loss
    let redundancy = FixedMultiplierStrategy::triple();
    let mut window = SendWindow::with_window_size(64);
    let mut rate_controller = RateController::with_rate(10000);
    let mut channel = LossyChannel::new(0.30);

    let initial_window_size = window.window_size();
    let initial_rate = rate_controller.configured_rate();

    // Simulate sending packets with redundancy
    for i in 0..200u64 {
        let copies = redundancy.get_redundancy_count(i);

        for _copy in 0..copies {
            // Clean up to make room
            window.cleanup_acked();

            if let Some(seq) = window.try_send(vec![i as u8; 100]) {
                rate_controller.try_send();

                // Simulate transmission through lossy channel
                let delivered = channel.send(&[i as u8; 100]);

                if delivered {
                    window.acknowledge(seq);
                } else {
                    // Report loss - this should NOT affect rate
                    rate_controller.report_loss(1);
                }
            }
        }

        // CRITICAL: Neither window nor rate should have changed
        assert_eq!(
            window.window_size(),
            initial_window_size,
            "Window size must not change due to loss"
        );
        assert_eq!(
            rate_controller.configured_rate(),
            initial_rate,
            "Rate must not change due to loss"
        );
    }

    let actual_loss = channel.actual_loss_rate();
    println!(
        "Combined system test passed: window={}, rate={}, loss={:.1}%",
        initial_window_size,
        initial_rate,
        actual_loss * 100.0
    );

    // Verify we actually had significant loss
    assert!(
        actual_loss >= 0.25,
        "Test requires at least 25% loss, got {:.1}%",
        actual_loss * 100.0
    );
}

/// Test: Adaptive strategy increases redundancy under loss but rate stays fixed
#[test]
fn test_adaptive_redundancy_with_fixed_rate() {
    let mut strategy = AdaptiveStrategy::with_params(1, 5, 50);
    let mut rate_controller = RateController::with_rate(5000);

    let initial_rate = rate_controller.configured_rate();

    // Simulate high loss scenario
    for i in 0..200 {
        let was_received = i % 3 != 0; // ~33% loss
        strategy.update(i, was_received);

        if !was_received {
            rate_controller.report_loss(1);
        }

        // Rate must stay fixed
        assert_eq!(
            rate_controller.configured_rate(),
            initial_rate,
            "Rate must not change due to loss"
        );
    }

    // Adaptive strategy should have increased redundancy
    let final_multiplier = strategy.current_multiplier();
    assert!(
        final_multiplier > 1.5,
        "Adaptive strategy should increase redundancy under loss, got {:.2}",
        final_multiplier
    );

    println!(
        "Adaptive redundancy test: rate={} (unchanged), redundancy={:.2}x",
        rate_controller.configured_rate(),
        final_multiplier
    );
}

/// Stress test: High volume transmission under 30% loss
#[test]
fn stress_test_high_volume_30_percent_loss() {
    let mut window = SendWindow::with_window_size(128);
    let mut rate_controller = RateController::with_rate(50000);
    let mut channel = LossyChannel::new(0.30);

    let initial_window_size = window.window_size();
    let initial_rate = rate_controller.configured_rate();

    let start = Instant::now();
    let mut packets_attempted = 0u64;

    // Run for a simulated high-volume scenario
    while packets_attempted < 10000 {
        if rate_controller.can_send() {
            if let Some(seq) = window.try_send(vec![0u8; 1000]) {
                rate_controller.try_send();
                packets_attempted += 1;

                let delivered = channel.send(&[0u8; 1000]);
                if delivered {
                    window.acknowledge(seq);
                } else {
                    rate_controller.report_loss(1);
                }
            }
        }

        // Cleanup periodically
        if packets_attempted.is_multiple_of(100) {
            window.cleanup_acked();
        }

        // Invariant checks
        assert_eq!(window.window_size(), initial_window_size);
        assert_eq!(rate_controller.configured_rate(), initial_rate);
    }

    let elapsed = start.elapsed();
    let actual_loss = channel.actual_loss_rate();

    println!(
        "Stress test completed: {} packets in {:?}, loss={:.1}%",
        packets_attempted,
        elapsed,
        actual_loss * 100.0
    );

    // Final invariant check
    assert_eq!(window.window_size(), initial_window_size);
    assert_eq!(rate_controller.configured_rate(), initial_rate);
}

/// Test: Window and rate remain stable even with 50% loss
#[test]
fn test_extreme_loss_50_percent() {
    let mut window = SendWindow::with_window_size(32);
    let mut rate_controller = RateController::with_rate(1000);
    let mut channel = LossyChannel::new(0.50);

    let initial_window_size = window.window_size();
    let initial_rate = rate_controller.configured_rate();

    for i in 0..500 {
        if let Some(seq) = window.try_send(vec![i as u8; 100]) {
            let delivered = channel.send(&[i as u8; 100]);
            if delivered {
                window.acknowledge(seq);
            } else {
                rate_controller.report_loss(1);
            }
        }

        if i % 10 == 0 {
            window.cleanup_acked();
        }

        // Even under 50% loss, these must not change
        assert_eq!(window.window_size(), initial_window_size);
        assert_eq!(rate_controller.configured_rate(), initial_rate);
    }

    let actual_loss = channel.actual_loss_rate();
    assert!(
        actual_loss >= 0.45,
        "Test requires at least 45% loss, got {:.1}%",
        actual_loss * 100.0
    );

    println!(
        "Extreme loss test passed: window={}, rate={}, loss={:.1}%",
        initial_window_size,
        initial_rate,
        actual_loss * 100.0
    );
}
