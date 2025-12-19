//! TCP Sequence Number Management
//!
//! Implements sequence number generation (ISN) and comparison with wraparound handling.
//! Based on RFC 793 and RFC 6528 for secure ISN generation.

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Sub};
use std::time::{SystemTime, UNIX_EPOCH};

/// TCP sequence number with wraparound-aware arithmetic and comparison.
///
/// TCP sequence numbers are 32-bit unsigned integers that wrap around at 2^32.
/// This type provides correct comparison and arithmetic operations that handle
/// the wraparound case according to RFC 793.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SeqNum(u32);

impl SeqNum {
    /// Create a new sequence number from a raw u32 value.
    #[inline]
    pub const fn new(value: u32) -> Self {
        SeqNum(value)
    }

    /// Get the raw u32 value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Add an offset to the sequence number (with wraparound).
    #[inline]
    pub const fn wrapping_add(self, offset: u32) -> Self {
        SeqNum(self.0.wrapping_add(offset))
    }

    /// Subtract an offset from the sequence number (with wraparound).
    #[inline]
    pub const fn wrapping_sub(self, offset: u32) -> Self {
        SeqNum(self.0.wrapping_sub(offset))
    }

    /// Calculate the difference between two sequence numbers.
    /// Returns a signed value representing the distance from self to other.
    ///
    /// Positive result means `other` is ahead of `self`.
    /// Negative result means `other` is behind `self`.
    #[inline]
    pub fn diff(self, other: SeqNum) -> i32 {
        other.0.wrapping_sub(self.0) as i32
    }

    /// Check if this sequence number is before another (with wraparound handling).
    ///
    /// Uses the standard TCP sequence number comparison: a sequence number S1
    /// is considered "before" S2 if (S2 - S1) interpreted as signed is positive.
    #[inline]
    pub fn is_before(self, other: SeqNum) -> bool {
        self.diff(other) > 0
    }

    /// Check if this sequence number is after another (with wraparound handling).
    #[inline]
    pub fn is_after(self, other: SeqNum) -> bool {
        self.diff(other) < 0
    }

    /// Check if this sequence number is before or equal to another.
    #[inline]
    pub fn is_before_or_eq(self, other: SeqNum) -> bool {
        self.diff(other) >= 0
    }

    /// Check if this sequence number is after or equal to another.
    #[inline]
    pub fn is_after_or_eq(self, other: SeqNum) -> bool {
        self.diff(other) <= 0
    }

    /// Check if a sequence number falls within a range [start, end).
    ///
    /// This handles wraparound correctly. The range is half-open: start is
    /// included, end is excluded.
    pub fn in_range(self, start: SeqNum, end: SeqNum) -> bool {
        // Handle the case where start == end (empty range)
        if start == end {
            return false;
        }
        start.is_before_or_eq(self) && self.is_before(end)
    }
}

impl fmt::Debug for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SeqNum({})", self.0)
    }
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for SeqNum {
    #[inline]
    fn from(value: u32) -> Self {
        SeqNum(value)
    }
}

impl From<SeqNum> for u32 {
    #[inline]
    fn from(seq: SeqNum) -> Self {
        seq.0
    }
}

impl Add<u32> for SeqNum {
    type Output = SeqNum;

    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        self.wrapping_add(rhs)
    }
}

impl Sub<u32> for SeqNum {
    type Output = SeqNum;

    #[inline]
    fn sub(self, rhs: u32) -> Self::Output {
        self.wrapping_sub(rhs)
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeqNum {
    fn cmp(&self, other: &Self) -> Ordering {
        let diff = self.diff(*other);
        match diff {
            d if d > 0 => Ordering::Less,
            d if d < 0 => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
}

/// Initial Sequence Number (ISN) Generator.
///
/// Generates secure initial sequence numbers for TCP connections.
/// Based on RFC 6528 recommendations for ISN generation.
pub struct IsnGenerator {
    /// Secret key for ISN generation (should be random and kept secret)
    secret: [u8; 16],
    /// Counter that increments with each ISN generation
    counter: u32,
}

impl IsnGenerator {
    /// Create a new ISN generator with a random secret.
    pub fn new() -> Self {
        let mut secret = [0u8; 16];
        // Use system time and counter as entropy source
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let nanos = now.as_nanos() as u64;

        // Fill secret with time-based entropy
        secret[0..8].copy_from_slice(&nanos.to_le_bytes());
        secret[8..16].copy_from_slice(&(nanos.wrapping_mul(0x517cc1b727220a95)).to_le_bytes());

        IsnGenerator {
            secret,
            counter: (nanos & 0xFFFFFFFF) as u32,
        }
    }

    /// Create an ISN generator with a specific secret (for testing or deterministic behavior).
    pub fn with_secret(secret: [u8; 16]) -> Self {
        IsnGenerator {
            secret,
            counter: 0,
        }
    }

    /// Generate an Initial Sequence Number.
    ///
    /// The ISN is generated using a combination of:
    /// - A time-based component (to ensure uniqueness over time)
    /// - A secret-based hash (to prevent prediction)
    /// - Connection-specific data (source/dest IP and ports)
    ///
    /// This follows RFC 6528 recommendations for secure ISN generation.
    pub fn generate(&mut self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> SeqNum {
        // Increment counter for each generation
        self.counter = self.counter.wrapping_add(1);

        // Get current time component (microseconds since epoch, truncated to 32 bits)
        let time_component = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u32;

        // Simple hash combining all inputs
        // In production, this should use a cryptographic hash like SipHash or MD5
        let mut hash: u32 = 0;

        // Mix in the secret
        for chunk in self.secret.chunks(4) {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            hash = hash.wrapping_add(val);
            hash = hash.rotate_left(7);
        }

        // Mix in connection tuple
        hash = hash.wrapping_add(src_ip);
        hash = hash.rotate_left(5);
        hash = hash.wrapping_add(dst_ip);
        hash = hash.rotate_left(5);
        hash = hash.wrapping_add((src_port as u32) << 16 | (dst_port as u32));
        hash = hash.rotate_left(5);

        // Mix in counter
        hash = hash.wrapping_add(self.counter);
        hash = hash.rotate_left(7);

        // Final mixing
        hash ^= hash >> 16;
        hash = hash.wrapping_mul(0x85ebca6b);
        hash ^= hash >> 13;
        hash = hash.wrapping_mul(0xc2b2ae35);
        hash ^= hash >> 16;

        // Add time component (RFC 793 style timer)
        // The time component ensures ISN increases over time
        SeqNum::new(hash.wrapping_add(time_component))
    }

    /// Generate a simple ISN without connection-specific data.
    /// Useful for testing or when connection details are not yet known.
    pub fn generate_simple(&mut self) -> SeqNum {
        self.generate(0, 0, 0, 0)
    }
}

impl Default for IsnGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === 2.2.1 单元测试: ISN 生成器 ===

    #[test]
    fn test_isn_generator_creates_different_values() {
        let mut gen = IsnGenerator::new();
        // Use hex representation for IP addresses: 192.168.1.1 = 0xC0A80101
        let isn1 = gen.generate(0xC0A80101, 0xC0A80102, 12345, 80);
        let isn2 = gen.generate(0xC0A80101, 0xC0A80102, 12345, 80);

        // Even for same connection tuple, ISNs should differ due to counter/time
        assert_ne!(isn1, isn2);
    }

    #[test]
    fn test_isn_generator_different_connections() {
        let mut gen = IsnGenerator::with_secret([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let isn1 = gen.generate(0x0A000001, 0x0A000002, 1234, 80);
        let isn2 = gen.generate(0x0A000001, 0x0A000003, 1234, 80);

        // Different destinations should produce different ISNs
        assert_ne!(isn1, isn2);
    }

    #[test]
    fn test_isn_generator_simple() {
        let mut gen = IsnGenerator::new();
        let isn1 = gen.generate_simple();
        let isn2 = gen.generate_simple();

        assert_ne!(isn1, isn2);
    }

    #[test]
    fn test_isn_generator_with_secret() {
        let secret = [0u8; 16];
        let gen = IsnGenerator::with_secret(secret);
        assert_eq!(gen.counter, 0);
    }

    // === 2.2.2 单元测试: 序列号比较 ===

    #[test]
    fn test_seqnum_basic_comparison() {
        let a = SeqNum::new(100);
        let b = SeqNum::new(200);

        assert!(a.is_before(b));
        assert!(b.is_after(a));
        assert!(!a.is_after(b));
        assert!(!b.is_before(a));
    }

    #[test]
    fn test_seqnum_equality() {
        let a = SeqNum::new(100);
        let b = SeqNum::new(100);

        assert_eq!(a, b);
        assert!(a.is_before_or_eq(b));
        assert!(a.is_after_or_eq(b));
        assert!(!a.is_before(b));
        assert!(!a.is_after(b));
    }

    #[test]
    fn test_seqnum_diff() {
        let a = SeqNum::new(100);
        let b = SeqNum::new(200);

        assert_eq!(a.diff(b), 100);
        assert_eq!(b.diff(a), -100);
    }

    // === 2.2.3 单元测试: 序列号回绕边界 ===

    #[test]
    fn test_seqnum_wraparound_comparison() {
        // Test near the wraparound point
        let near_max = SeqNum::new(u32::MAX - 10);
        let after_wrap = SeqNum::new(10);

        // after_wrap should be considered "after" near_max due to wraparound
        assert!(near_max.is_before(after_wrap));
        assert!(after_wrap.is_after(near_max));
    }

    #[test]
    fn test_seqnum_wraparound_at_boundary() {
        let max = SeqNum::new(u32::MAX);
        let zero = SeqNum::new(0);

        // 0 is one step after MAX
        assert!(max.is_before(zero));
        assert!(zero.is_after(max));
        assert_eq!(max.diff(zero), 1);
    }

    #[test]
    fn test_seqnum_wraparound_arithmetic() {
        let near_max = SeqNum::new(u32::MAX - 5);
        let result = near_max.wrapping_add(10);

        // Should wrap around to 4
        assert_eq!(result.raw(), 4);
    }

    #[test]
    fn test_seqnum_wraparound_subtraction() {
        let small = SeqNum::new(5);
        let result = small.wrapping_sub(10);

        // Should wrap around to MAX - 4
        assert_eq!(result.raw(), u32::MAX - 4);
    }

    #[test]
    fn test_seqnum_large_gap_comparison() {
        // When the gap is exactly half of u32::MAX, comparison is ambiguous
        // But for gaps less than half, comparison should work correctly
        let a = SeqNum::new(0);
        let b = SeqNum::new(i32::MAX as u32); // Just under half

        assert!(a.is_before(b));
        assert!(b.is_after(a));
    }

    #[test]
    fn test_seqnum_half_range_boundary() {
        // At exactly half range, the comparison becomes ambiguous
        // This tests behavior at the boundary
        let a = SeqNum::new(0);
        let half = SeqNum::new(0x80000000); // 2^31

        // At exactly half range, diff is i32::MIN which is negative
        // So half is considered "before" a (they're equidistant)
        let diff = a.diff(half);
        assert_eq!(diff, i32::MIN);
    }

    #[test]
    fn test_seqnum_in_range_basic() {
        let start = SeqNum::new(100);
        let end = SeqNum::new(200);

        assert!(SeqNum::new(100).in_range(start, end)); // start is included
        assert!(SeqNum::new(150).in_range(start, end));
        assert!(!SeqNum::new(200).in_range(start, end)); // end is excluded
        assert!(!SeqNum::new(50).in_range(start, end));
        assert!(!SeqNum::new(250).in_range(start, end));
    }

    #[test]
    fn test_seqnum_in_range_wraparound() {
        // Range that wraps around
        let start = SeqNum::new(u32::MAX - 10);
        let end = SeqNum::new(10);

        assert!(SeqNum::new(u32::MAX - 5).in_range(start, end));
        assert!(SeqNum::new(0).in_range(start, end));
        assert!(SeqNum::new(5).in_range(start, end));
        assert!(!SeqNum::new(10).in_range(start, end)); // end excluded
        assert!(!SeqNum::new(100).in_range(start, end));
    }

    #[test]
    fn test_seqnum_in_range_empty() {
        let start = SeqNum::new(100);
        let end = SeqNum::new(100);

        // Empty range contains nothing
        assert!(!SeqNum::new(100).in_range(start, end));
        assert!(!SeqNum::new(50).in_range(start, end));
    }

    #[test]
    fn test_seqnum_ord_trait() {
        let a = SeqNum::new(100);
        let b = SeqNum::new(200);
        let c = SeqNum::new(100);

        assert!(a < b);
        assert!(b > a);
        assert!(a <= c);
        assert!(a >= c);
    }

    #[test]
    fn test_seqnum_ord_wraparound() {
        let near_max = SeqNum::new(u32::MAX - 10);
        let after_wrap = SeqNum::new(10);

        // Using Ord trait
        assert!(near_max < after_wrap);
    }

    #[test]
    fn test_seqnum_add_sub_operators() {
        let seq = SeqNum::new(100);

        assert_eq!((seq + 50).raw(), 150);
        assert_eq!((seq - 50).raw(), 50);

        // Wraparound
        let near_max = SeqNum::new(u32::MAX - 5);
        assert_eq!((near_max + 10).raw(), 4);
    }

    #[test]
    fn test_seqnum_from_into() {
        let seq: SeqNum = 12345u32.into();
        assert_eq!(seq.raw(), 12345);

        let val: u32 = seq.into();
        assert_eq!(val, 12345);
    }

    #[test]
    fn test_seqnum_display_debug() {
        let seq = SeqNum::new(12345);
        assert_eq!(format!("{}", seq), "12345");
        assert_eq!(format!("{:?}", seq), "SeqNum(12345)");
    }

    #[test]
    fn test_seqnum_default() {
        let seq: SeqNum = Default::default();
        assert_eq!(seq.raw(), 0);
    }

    #[test]
    fn test_seqnum_const_new() {
        const SEQ: SeqNum = SeqNum::new(42);
        assert_eq!(SEQ.raw(), 42);
    }
}
