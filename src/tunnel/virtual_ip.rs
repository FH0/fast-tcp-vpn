//! Virtual IP Management for VPN Tunnel
//!
//! Implements virtual IP address allocation, pool management,
//! and IP reclamation for VPN clients.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// Virtual IP address value object
///
/// Represents a virtual IP address assigned to a VPN client.
/// This is a value object - immutable and compared by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualIP {
    addr: Ipv4Addr,
}

impl VirtualIP {
    /// Create a new VirtualIP from an Ipv4Addr
    pub fn new(addr: Ipv4Addr) -> Self {
        Self { addr }
    }

    /// Create a new VirtualIP from octets
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            addr: Ipv4Addr::new(a, b, c, d),
        }
    }

    /// Get the underlying Ipv4Addr
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// Get the octets of the IP address
    pub fn octets(&self) -> [u8; 4] {
        self.addr.octets()
    }

    /// Convert to u32 for arithmetic operations
    pub fn to_u32(&self) -> u32 {
        u32::from(self.addr)
    }

    /// Create from u32
    pub fn from_u32(value: u32) -> Self {
        Self {
            addr: Ipv4Addr::from(value),
        }
    }

    /// Check if this is a valid host address (not network or broadcast)
    pub fn is_valid_host(&self) -> bool {
        let octets = self.addr.octets();
        // Not 0.0.0.0 and not x.x.x.0 or x.x.x.255 (common network/broadcast)
        octets[3] != 0 && octets[3] != 255
    }
}

impl std::fmt::Display for VirtualIP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl From<Ipv4Addr> for VirtualIP {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new(addr)
    }
}

impl From<VirtualIP> for Ipv4Addr {
    fn from(vip: VirtualIP) -> Self {
        vip.addr
    }
}

impl From<[u8; 4]> for VirtualIP {
    fn from(octets: [u8; 4]) -> Self {
        Self::from_octets(octets[0], octets[1], octets[2], octets[3])
    }
}

/// Error types for IP pool operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPoolError {
    /// IP pool is exhausted, no more addresses available
    PoolExhausted,
    /// The requested IP is not in the pool range
    OutOfRange,
    /// The IP is already allocated
    AlreadyAllocated,
    /// The IP is not allocated (cannot release)
    NotAllocated,
    /// Invalid pool configuration
    InvalidConfig(String),
}

impl std::fmt::Display for IpPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPoolError::PoolExhausted => write!(f, "IP pool exhausted"),
            IpPoolError::OutOfRange => write!(f, "IP address out of pool range"),
            IpPoolError::AlreadyAllocated => write!(f, "IP address already allocated"),
            IpPoolError::NotAllocated => write!(f, "IP address not allocated"),
            IpPoolError::InvalidConfig(msg) => write!(f, "Invalid pool config: {}", msg),
        }
    }
}

impl std::error::Error for IpPoolError {}

/// IP Pool Allocator
///
/// Manages a pool of virtual IP addresses for VPN clients.
/// Supports allocation, release, and tracking of IP assignments.
#[derive(Debug)]
pub struct IpPool {
    /// Start of the IP range (inclusive)
    start: VirtualIP,
    /// End of the IP range (inclusive)
    end: VirtualIP,
    /// Set of allocated IPs
    allocated: HashSet<VirtualIP>,
    /// Reserved IPs (cannot be allocated)
    reserved: HashSet<VirtualIP>,
    /// Next IP to try for allocation (optimization)
    next_candidate: u32,
}

impl IpPool {
    /// Create a new IP pool with the given range
    ///
    /// # Arguments
    /// * `start` - First IP in the range (inclusive)
    /// * `end` - Last IP in the range (inclusive)
    ///
    /// # Returns
    /// * `Ok(IpPool)` - A new IP pool
    /// * `Err(IpPoolError)` - If the range is invalid
    pub fn new(start: VirtualIP, end: VirtualIP) -> Result<Self, IpPoolError> {
        let start_u32 = start.to_u32();
        let end_u32 = end.to_u32();

        if start_u32 > end_u32 {
            return Err(IpPoolError::InvalidConfig(
                "Start IP must be <= end IP".to_string(),
            ));
        }

        Ok(Self {
            start,
            end,
            allocated: HashSet::new(),
            reserved: HashSet::new(),
            next_candidate: start_u32,
        })
    }

    /// Create a new IP pool from CIDR notation
    ///
    /// # Arguments
    /// * `network` - Network address
    /// * `prefix_len` - CIDR prefix length (e.g., 24 for /24)
    ///
    /// # Returns
    /// * `Ok(IpPool)` - A new IP pool (excluding network and broadcast addresses)
    /// * `Err(IpPoolError)` - If the configuration is invalid
    pub fn from_cidr(network: Ipv4Addr, prefix_len: u8) -> Result<Self, IpPoolError> {
        if prefix_len > 30 {
            return Err(IpPoolError::InvalidConfig(
                "Prefix length must be <= 30 for usable host range".to_string(),
            ));
        }

        let network_u32 = u32::from(network);
        let host_bits = 32 - prefix_len;
        let host_mask = (1u32 << host_bits) - 1;

        // Network address (all host bits 0)
        let network_addr = network_u32 & !host_mask;
        // Broadcast address (all host bits 1)
        let broadcast_addr = network_addr | host_mask;

        // First and last usable host addresses
        let start = VirtualIP::from_u32(network_addr + 1);
        let end = VirtualIP::from_u32(broadcast_addr - 1);

        Self::new(start, end)
    }

    /// Get the total capacity of the pool
    pub fn capacity(&self) -> u32 {
        self.end.to_u32() - self.start.to_u32() + 1
    }

    /// Get the number of available (unallocated) IPs
    pub fn available(&self) -> u32 {
        self.capacity() - self.allocated.len() as u32 - self.reserved.len() as u32
    }

    /// Get the number of allocated IPs
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Check if the pool is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.available() == 0
    }

    /// Check if an IP is in the pool range
    pub fn is_in_range(&self, ip: VirtualIP) -> bool {
        let ip_u32 = ip.to_u32();
        ip_u32 >= self.start.to_u32() && ip_u32 <= self.end.to_u32()
    }

    /// Check if an IP is allocated
    pub fn is_allocated(&self, ip: VirtualIP) -> bool {
        self.allocated.contains(&ip)
    }

    /// Check if an IP is reserved
    pub fn is_reserved(&self, ip: VirtualIP) -> bool {
        self.reserved.contains(&ip)
    }

    /// Reserve an IP address (prevent it from being allocated)
    pub fn reserve(&mut self, ip: VirtualIP) -> Result<(), IpPoolError> {
        if !self.is_in_range(ip) {
            return Err(IpPoolError::OutOfRange);
        }
        if self.is_allocated(ip) {
            return Err(IpPoolError::AlreadyAllocated);
        }
        self.reserved.insert(ip);
        Ok(())
    }

    /// Unreserve an IP address
    pub fn unreserve(&mut self, ip: VirtualIP) -> Result<(), IpPoolError> {
        if !self.reserved.remove(&ip) {
            return Err(IpPoolError::NotAllocated);
        }
        Ok(())
    }

    /// Allocate the next available IP address
    pub fn allocate(&mut self) -> Result<VirtualIP, IpPoolError> {
        let start_u32 = self.start.to_u32();
        let end_u32 = self.end.to_u32();
        let range_size = end_u32 - start_u32 + 1;

        // Try from next_candidate, wrapping around
        for offset in 0..range_size {
            let candidate_u32 = start_u32 + ((self.next_candidate - start_u32 + offset) % range_size);
            let candidate = VirtualIP::from_u32(candidate_u32);

            if !self.allocated.contains(&candidate) && !self.reserved.contains(&candidate) {
                self.allocated.insert(candidate);
                self.next_candidate = candidate_u32 + 1;
                if self.next_candidate > end_u32 {
                    self.next_candidate = start_u32;
                }
                return Ok(candidate);
            }
        }

        Err(IpPoolError::PoolExhausted)
    }

    /// Allocate a specific IP address
    pub fn allocate_specific(&mut self, ip: VirtualIP) -> Result<(), IpPoolError> {
        if !self.is_in_range(ip) {
            return Err(IpPoolError::OutOfRange);
        }
        if self.is_allocated(ip) {
            return Err(IpPoolError::AlreadyAllocated);
        }
        if self.is_reserved(ip) {
            return Err(IpPoolError::AlreadyAllocated);
        }

        self.allocated.insert(ip);
        Ok(())
    }

    /// Release an allocated IP address back to the pool
    pub fn release(&mut self, ip: VirtualIP) -> Result<(), IpPoolError> {
        if !self.allocated.remove(&ip) {
            return Err(IpPoolError::NotAllocated);
        }
        Ok(())
    }

    /// Get all allocated IPs
    pub fn allocated_ips(&self) -> impl Iterator<Item = &VirtualIP> {
        self.allocated.iter()
    }

    /// Clear all allocations (but keep reservations)
    pub fn clear_allocations(&mut self) {
        self.allocated.clear();
        self.next_candidate = self.start.to_u32();
    }

    /// Get the start of the IP range
    pub fn start(&self) -> VirtualIP {
        self.start
    }

    /// Get the end of the IP range
    pub fn end(&self) -> VirtualIP {
        self.end
    }
}

/// IP Assignment Manager
///
/// Tracks IP assignments to session IDs, providing bidirectional lookup.
#[derive(Debug, Default)]
pub struct IpAssignmentManager {
    /// Map from session ID to assigned IP
    session_to_ip: HashMap<u64, VirtualIP>,
    /// Map from IP to session ID
    ip_to_session: HashMap<VirtualIP, u64>,
}

impl IpAssignmentManager {
    /// Create a new IP assignment manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign an IP to a session
    pub fn assign(&mut self, session_id: u64, ip: VirtualIP) {
        // Remove any existing assignment for this session
        if let Some(old_ip) = self.session_to_ip.remove(&session_id) {
            self.ip_to_session.remove(&old_ip);
        }
        // Remove any existing assignment for this IP
        if let Some(old_session) = self.ip_to_session.remove(&ip) {
            self.session_to_ip.remove(&old_session);
        }

        self.session_to_ip.insert(session_id, ip);
        self.ip_to_session.insert(ip, session_id);
    }

    /// Remove assignment by session ID
    pub fn remove_by_session(&mut self, session_id: u64) -> Option<VirtualIP> {
        if let Some(ip) = self.session_to_ip.remove(&session_id) {
            self.ip_to_session.remove(&ip);
            Some(ip)
        } else {
            None
        }
    }

    /// Remove assignment by IP
    pub fn remove_by_ip(&mut self, ip: VirtualIP) -> Option<u64> {
        if let Some(session_id) = self.ip_to_session.remove(&ip) {
            self.session_to_ip.remove(&session_id);
            Some(session_id)
        } else {
            None
        }
    }

    /// Get IP by session ID
    pub fn get_ip(&self, session_id: u64) -> Option<VirtualIP> {
        self.session_to_ip.get(&session_id).copied()
    }

    /// Get session ID by IP
    pub fn get_session(&self, ip: VirtualIP) -> Option<u64> {
        self.ip_to_session.get(&ip).copied()
    }

    /// Get the number of assignments
    pub fn len(&self) -> usize {
        self.session_to_ip.len()
    }

    /// Check if there are no assignments
    pub fn is_empty(&self) -> bool {
        self.session_to_ip.is_empty()
    }

    /// Clear all assignments
    pub fn clear(&mut self) {
        self.session_to_ip.clear();
        self.ip_to_session.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === 4.2.1 Tests: VirtualIP Value Object ===

    #[test]
    fn test_virtual_ip_creation() {
        let ip = VirtualIP::new(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.addr(), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.octets(), [10, 0, 0, 1]);
    }

    #[test]
    fn test_virtual_ip_from_octets() {
        let ip = VirtualIP::from_octets(192, 168, 1, 100);
        assert_eq!(ip.addr(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_virtual_ip_u32_conversion() {
        let ip = VirtualIP::from_octets(10, 0, 0, 1);
        let u32_val = ip.to_u32();
        let ip2 = VirtualIP::from_u32(u32_val);
        assert_eq!(ip, ip2);
    }

    #[test]
    fn test_virtual_ip_display() {
        let ip = VirtualIP::from_octets(10, 0, 0, 1);
        assert_eq!(format!("{}", ip), "10.0.0.1");
    }

    #[test]
    fn test_virtual_ip_equality() {
        let ip1 = VirtualIP::from_octets(10, 0, 0, 1);
        let ip2 = VirtualIP::from_octets(10, 0, 0, 1);
        let ip3 = VirtualIP::from_octets(10, 0, 0, 2);

        assert_eq!(ip1, ip2);
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_virtual_ip_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VirtualIP::from_octets(10, 0, 0, 1));
        set.insert(VirtualIP::from_octets(10, 0, 0, 2));
        set.insert(VirtualIP::from_octets(10, 0, 0, 1)); // Duplicate

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_virtual_ip_is_valid_host() {
        assert!(VirtualIP::from_octets(10, 0, 0, 1).is_valid_host());
        assert!(VirtualIP::from_octets(10, 0, 0, 254).is_valid_host());
        assert!(!VirtualIP::from_octets(10, 0, 0, 0).is_valid_host());
        assert!(!VirtualIP::from_octets(10, 0, 0, 255).is_valid_host());
    }

    #[test]
    fn test_virtual_ip_from_ipv4addr() {
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let ip: VirtualIP = addr.into();
        assert_eq!(ip.addr(), addr);
    }

    #[test]
    fn test_virtual_ip_into_ipv4addr() {
        let ip = VirtualIP::from_octets(10, 0, 0, 1);
        let addr: Ipv4Addr = ip.into();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_virtual_ip_from_octets_array() {
        let octets: [u8; 4] = [10, 0, 0, 1];
        let ip: VirtualIP = octets.into();
        assert_eq!(ip.octets(), [10, 0, 0, 1]);
    }

    // === 4.2.2 Tests: IP Pool Allocator ===

    #[test]
    fn test_ip_pool_creation() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 10);
        let pool = IpPool::new(start, end).unwrap();

        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.available(), 10);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn test_ip_pool_invalid_range() {
        let start = VirtualIP::from_octets(10, 0, 0, 10);
        let end = VirtualIP::from_octets(10, 0, 0, 1);
        let result = IpPool::new(start, end);

        assert!(matches!(result, Err(IpPoolError::InvalidConfig(_))));
    }

    #[test]
    fn test_ip_pool_from_cidr() {
        let pool = IpPool::from_cidr(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap();

        // /24 has 256 addresses, minus network and broadcast = 254 usable
        assert_eq!(pool.capacity(), 254);
        assert_eq!(pool.start(), VirtualIP::from_octets(10, 0, 0, 1));
        assert_eq!(pool.end(), VirtualIP::from_octets(10, 0, 0, 254));
    }

    #[test]
    fn test_ip_pool_from_cidr_small() {
        let pool = IpPool::from_cidr(Ipv4Addr::new(10, 0, 0, 0), 30).unwrap();

        // /30 has 4 addresses, minus network and broadcast = 2 usable
        assert_eq!(pool.capacity(), 2);
    }

    #[test]
    fn test_ip_pool_from_cidr_too_small() {
        let result = IpPool::from_cidr(Ipv4Addr::new(10, 0, 0, 0), 31);
        assert!(matches!(result, Err(IpPoolError::InvalidConfig(_))));
    }

    #[test]
    fn test_ip_pool_allocate() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        let ip1 = pool.allocate().unwrap();
        let ip2 = pool.allocate().unwrap();

        assert_ne!(ip1, ip2);
        assert!(pool.is_in_range(ip1));
        assert!(pool.is_in_range(ip2));
        assert!(pool.is_allocated(ip1));
        assert!(pool.is_allocated(ip2));
        assert_eq!(pool.allocated_count(), 2);
        assert_eq!(pool.available(), 3);
    }

    #[test]
    fn test_ip_pool_allocate_specific() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 10);
        let mut pool = IpPool::new(start, end).unwrap();

        let specific = VirtualIP::from_octets(10, 0, 0, 5);
        pool.allocate_specific(specific).unwrap();

        assert!(pool.is_allocated(specific));
        assert_eq!(pool.allocated_count(), 1);
    }

    #[test]
    fn test_ip_pool_allocate_specific_out_of_range() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 10);
        let mut pool = IpPool::new(start, end).unwrap();

        let out_of_range = VirtualIP::from_octets(10, 0, 0, 100);
        let result = pool.allocate_specific(out_of_range);

        assert!(matches!(result, Err(IpPoolError::OutOfRange)));
    }

    #[test]
    fn test_ip_pool_allocate_specific_already_allocated() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 10);
        let mut pool = IpPool::new(start, end).unwrap();

        let specific = VirtualIP::from_octets(10, 0, 0, 5);
        pool.allocate_specific(specific).unwrap();
        let result = pool.allocate_specific(specific);

        assert!(matches!(result, Err(IpPoolError::AlreadyAllocated)));
    }

    // === 4.2.3 Tests: IP Reclamation ===

    #[test]
    fn test_ip_pool_release() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        let ip = pool.allocate().unwrap();
        assert!(pool.is_allocated(ip));

        pool.release(ip).unwrap();
        assert!(!pool.is_allocated(ip));
        assert_eq!(pool.available(), 5);
    }

    #[test]
    fn test_ip_pool_release_not_allocated() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        let ip = VirtualIP::from_octets(10, 0, 0, 3);
        let result = pool.release(ip);

        assert!(matches!(result, Err(IpPoolError::NotAllocated)));
    }

    #[test]
    fn test_ip_pool_release_and_reallocate() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 2);
        let mut pool = IpPool::new(start, end).unwrap();

        let ip1 = pool.allocate().unwrap();
        pool.allocate().unwrap();

        assert!(pool.is_exhausted());

        pool.release(ip1).unwrap();
        assert!(!pool.is_exhausted());

        let ip3 = pool.allocate().unwrap();
        assert_eq!(ip3, ip1); // Should get the released IP back
    }

    #[test]
    fn test_ip_pool_reserve() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        let reserved = VirtualIP::from_octets(10, 0, 0, 3);
        pool.reserve(reserved).unwrap();

        assert!(pool.is_reserved(reserved));
        assert_eq!(pool.available(), 4);

        // Reserved IP should not be allocated
        for _ in 0..4 {
            let ip = pool.allocate().unwrap();
            assert_ne!(ip, reserved);
        }
    }

    #[test]
    fn test_ip_pool_unreserve() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        let reserved = VirtualIP::from_octets(10, 0, 0, 3);
        pool.reserve(reserved).unwrap();
        pool.unreserve(reserved).unwrap();

        assert!(!pool.is_reserved(reserved));
        assert_eq!(pool.available(), 5);
    }

    #[test]
    fn test_ip_pool_clear_allocations() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        pool.allocate().unwrap();
        pool.allocate().unwrap();
        pool.reserve(VirtualIP::from_octets(10, 0, 0, 5)).unwrap();

        pool.clear_allocations();

        assert_eq!(pool.allocated_count(), 0);
        assert_eq!(pool.available(), 4); // Reservations kept
    }

    // === 4.2.4 Tests: IP Allocation/Reclamation ===

    #[test]
    fn test_ip_assignment_manager() {
        let mut manager = IpAssignmentManager::new();
        let ip = VirtualIP::from_octets(10, 0, 0, 1);
        let session_id = 12345u64;

        manager.assign(session_id, ip);

        assert_eq!(manager.get_ip(session_id), Some(ip));
        assert_eq!(manager.get_session(ip), Some(session_id));
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_ip_assignment_manager_remove_by_session() {
        let mut manager = IpAssignmentManager::new();
        let ip = VirtualIP::from_octets(10, 0, 0, 1);
        let session_id = 12345u64;

        manager.assign(session_id, ip);
        let removed_ip = manager.remove_by_session(session_id);

        assert_eq!(removed_ip, Some(ip));
        assert_eq!(manager.get_ip(session_id), None);
        assert_eq!(manager.get_session(ip), None);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_ip_assignment_manager_remove_by_ip() {
        let mut manager = IpAssignmentManager::new();
        let ip = VirtualIP::from_octets(10, 0, 0, 1);
        let session_id = 12345u64;

        manager.assign(session_id, ip);
        let removed_session = manager.remove_by_ip(ip);

        assert_eq!(removed_session, Some(session_id));
        assert_eq!(manager.get_ip(session_id), None);
        assert_eq!(manager.get_session(ip), None);
    }

    #[test]
    fn test_ip_assignment_manager_reassign() {
        let mut manager = IpAssignmentManager::new();
        let ip1 = VirtualIP::from_octets(10, 0, 0, 1);
        let ip2 = VirtualIP::from_octets(10, 0, 0, 2);
        let session_id = 12345u64;

        manager.assign(session_id, ip1);
        manager.assign(session_id, ip2);

        assert_eq!(manager.get_ip(session_id), Some(ip2));
        assert_eq!(manager.get_session(ip1), None);
        assert_eq!(manager.get_session(ip2), Some(session_id));
        assert_eq!(manager.len(), 1);
    }

    // === 4.2.5 Tests: IP Pool Exhaustion Handling ===

    #[test]
    fn test_ip_pool_exhaustion() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 3);
        let mut pool = IpPool::new(start, end).unwrap();

        pool.allocate().unwrap();
        pool.allocate().unwrap();
        pool.allocate().unwrap();

        assert!(pool.is_exhausted());

        let result = pool.allocate();
        assert!(matches!(result, Err(IpPoolError::PoolExhausted)));
    }

    #[test]
    fn test_ip_pool_exhaustion_with_reservations() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 3);
        let mut pool = IpPool::new(start, end).unwrap();

        pool.reserve(VirtualIP::from_octets(10, 0, 0, 1)).unwrap();
        pool.allocate().unwrap();
        pool.allocate().unwrap();

        assert!(pool.is_exhausted());

        let result = pool.allocate();
        assert!(matches!(result, Err(IpPoolError::PoolExhausted)));
    }

    #[test]
    fn test_ip_pool_recovery_after_exhaustion() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 2);
        let mut pool = IpPool::new(start, end).unwrap();

        let ip1 = pool.allocate().unwrap();
        pool.allocate().unwrap();

        assert!(pool.is_exhausted());

        pool.release(ip1).unwrap();
        assert!(!pool.is_exhausted());

        let ip3 = pool.allocate().unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_ip_pool_allocated_ips_iterator() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 5);
        let mut pool = IpPool::new(start, end).unwrap();

        let ip1 = pool.allocate().unwrap();
        let ip2 = pool.allocate().unwrap();

        let allocated: Vec<_> = pool.allocated_ips().copied().collect();
        assert_eq!(allocated.len(), 2);
        assert!(allocated.contains(&ip1));
        assert!(allocated.contains(&ip2));
    }

    #[test]
    fn test_ip_pool_is_in_range() {
        let start = VirtualIP::from_octets(10, 0, 0, 1);
        let end = VirtualIP::from_octets(10, 0, 0, 10);
        let pool = IpPool::new(start, end).unwrap();

        assert!(pool.is_in_range(VirtualIP::from_octets(10, 0, 0, 1)));
        assert!(pool.is_in_range(VirtualIP::from_octets(10, 0, 0, 5)));
        assert!(pool.is_in_range(VirtualIP::from_octets(10, 0, 0, 10)));
        assert!(!pool.is_in_range(VirtualIP::from_octets(10, 0, 0, 0)));
        assert!(!pool.is_in_range(VirtualIP::from_octets(10, 0, 0, 11)));
        assert!(!pool.is_in_range(VirtualIP::from_octets(192, 168, 1, 1)));
    }

    #[test]
    fn test_ip_pool_large_range() {
        // Test with a /16 network (65534 usable addresses)
        let pool = IpPool::from_cidr(Ipv4Addr::new(10, 0, 0, 0), 16).unwrap();

        assert_eq!(pool.capacity(), 65534);
        assert_eq!(pool.start(), VirtualIP::from_octets(10, 0, 0, 1));
        assert_eq!(pool.end(), VirtualIP::from_octets(10, 0, 255, 254));
    }
}
