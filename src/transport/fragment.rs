//! Data Fragmentation Module
//!
//! Implements MTU-based fragmentation and reassembly for large data packets.
//! This module handles splitting large payloads into MTU-sized fragments
//! and reassembling them back into the original data.

use std::collections::BTreeMap;

/// Default MTU size (typical Ethernet MTU minus IP/TCP headers)
pub const DEFAULT_MTU: usize = 1400;

/// Minimum allowed MTU
pub const MIN_MTU: usize = 576;

/// Maximum allowed MTU
pub const MAX_MTU: usize = 65535;

/// Fragment header size (fragment_id: u32, fragment_index: u16, total_fragments: u16, data_len: u16)
pub const FRAGMENT_HEADER_SIZE: usize = 10;

/// A single fragment of data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Unique identifier for the original packet
    pub fragment_id: u32,
    /// Index of this fragment (0-based)
    pub fragment_index: u16,
    /// Total number of fragments
    pub total_fragments: u16,
    /// Fragment payload
    pub data: Vec<u8>,
}

impl Fragment {
    /// Create a new fragment
    pub fn new(fragment_id: u32, fragment_index: u16, total_fragments: u16, data: Vec<u8>) -> Self {
        Self {
            fragment_id,
            fragment_index,
            total_fragments,
            data,
        }
    }

    /// Serialize fragment to bytes (header + data)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAGMENT_HEADER_SIZE + self.data.len());
        bytes.extend_from_slice(&self.fragment_id.to_be_bytes());
        bytes.extend_from_slice(&self.fragment_index.to_be_bytes());
        bytes.extend_from_slice(&self.total_fragments.to_be_bytes());
        bytes.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize fragment from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FragmentError> {
        if bytes.len() < FRAGMENT_HEADER_SIZE {
            return Err(FragmentError::InvalidHeader);
        }

        let fragment_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fragment_index = u16::from_be_bytes([bytes[4], bytes[5]]);
        let total_fragments = u16::from_be_bytes([bytes[6], bytes[7]]);
        let data_len = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;

        if bytes.len() < FRAGMENT_HEADER_SIZE + data_len {
            return Err(FragmentError::InvalidDataLength);
        }

        let data = bytes[FRAGMENT_HEADER_SIZE..FRAGMENT_HEADER_SIZE + data_len].to_vec();

        Ok(Self {
            fragment_id,
            fragment_index,
            total_fragments,
            data,
        })
    }

    /// Check if this is the last fragment
    pub fn is_last(&self) -> bool {
        self.fragment_index == self.total_fragments - 1
    }
}

/// Errors that can occur during fragmentation/reassembly
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentError {
    /// Data is empty
    EmptyData,
    /// MTU is too small
    MtuTooSmall,
    /// Invalid fragment header
    InvalidHeader,
    /// Invalid data length in header
    InvalidDataLength,
    /// Fragment index out of range
    IndexOutOfRange,
    /// Duplicate fragment received
    DuplicateFragment,
    /// Fragment ID mismatch
    IdMismatch,
    /// Total fragments mismatch
    TotalMismatch,
    /// Reassembly incomplete
    Incomplete,
}

impl std::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FragmentError::EmptyData => write!(f, "Data is empty"),
            FragmentError::MtuTooSmall => write!(f, "MTU is too small"),
            FragmentError::InvalidHeader => write!(f, "Invalid fragment header"),
            FragmentError::InvalidDataLength => write!(f, "Invalid data length"),
            FragmentError::IndexOutOfRange => write!(f, "Fragment index out of range"),
            FragmentError::DuplicateFragment => write!(f, "Duplicate fragment"),
            FragmentError::IdMismatch => write!(f, "Fragment ID mismatch"),
            FragmentError::TotalMismatch => write!(f, "Total fragments mismatch"),
            FragmentError::Incomplete => write!(f, "Reassembly incomplete"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// MTU Fragmenter - splits large data into MTU-sized fragments
#[derive(Debug, Clone)]
pub struct Fragmenter {
    /// Maximum transmission unit (payload size per fragment)
    mtu: usize,
    /// Next fragment ID to use
    next_id: u32,
}

impl Fragmenter {
    /// Create a new fragmenter with the specified MTU
    pub fn new(mtu: usize) -> Self {
        let mtu = mtu.clamp(MIN_MTU, MAX_MTU);
        Self { mtu, next_id: 0 }
    }

    /// Create a new fragmenter with default MTU
    pub fn with_default_mtu() -> Self {
        Self::new(DEFAULT_MTU)
    }

    /// Get the current MTU
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Set a new MTU value
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu.clamp(MIN_MTU, MAX_MTU);
    }

    /// Get the maximum payload size per fragment (MTU minus header)
    pub fn max_payload_size(&self) -> usize {
        self.mtu.saturating_sub(FRAGMENT_HEADER_SIZE)
    }

    /// Calculate the number of fragments needed for the given data size
    pub fn fragment_count(&self, data_len: usize) -> usize {
        if data_len == 0 {
            return 0;
        }
        let payload_size = self.max_payload_size();
        (data_len + payload_size - 1) / payload_size
    }

    /// Check if data needs fragmentation
    pub fn needs_fragmentation(&self, data_len: usize) -> bool {
        data_len > self.max_payload_size()
    }

    /// Fragment data into MTU-sized pieces
    pub fn fragment(&mut self, data: &[u8]) -> Result<Vec<Fragment>, FragmentError> {
        if data.is_empty() {
            return Err(FragmentError::EmptyData);
        }

        let payload_size = self.max_payload_size();
        if payload_size == 0 {
            return Err(FragmentError::MtuTooSmall);
        }

        let fragment_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let total_fragments = self.fragment_count(data.len());
        if total_fragments > u16::MAX as usize {
            return Err(FragmentError::MtuTooSmall);
        }

        let mut fragments = Vec::with_capacity(total_fragments);

        for (index, chunk) in data.chunks(payload_size).enumerate() {
            fragments.push(Fragment::new(
                fragment_id,
                index as u16,
                total_fragments as u16,
                chunk.to_vec(),
            ));
        }

        Ok(fragments)
    }

    /// Fragment data with a specific fragment ID (useful for retransmission)
    pub fn fragment_with_id(
        &self,
        data: &[u8],
        fragment_id: u32,
    ) -> Result<Vec<Fragment>, FragmentError> {
        if data.is_empty() {
            return Err(FragmentError::EmptyData);
        }

        let payload_size = self.max_payload_size();
        if payload_size == 0 {
            return Err(FragmentError::MtuTooSmall);
        }

        let total_fragments = self.fragment_count(data.len());
        if total_fragments > u16::MAX as usize {
            return Err(FragmentError::MtuTooSmall);
        }

        let mut fragments = Vec::with_capacity(total_fragments);

        for (index, chunk) in data.chunks(payload_size).enumerate() {
            fragments.push(Fragment::new(
                fragment_id,
                index as u16,
                total_fragments as u16,
                chunk.to_vec(),
            ));
        }

        Ok(fragments)
    }
}

impl Default for Fragmenter {
    fn default() -> Self {
        Self::with_default_mtu()
    }
}

/// Reassembly buffer for a single fragmented packet
#[derive(Debug)]
struct ReassemblyBuffer {
    /// Fragment ID
    fragment_id: u32,
    /// Total number of fragments expected
    total_fragments: u16,
    /// Received fragments (index -> data)
    fragments: BTreeMap<u16, Vec<u8>>,
    /// Total bytes received
    bytes_received: usize,
}

impl ReassemblyBuffer {
    fn new(fragment_id: u32, total_fragments: u16) -> Self {
        Self {
            fragment_id,
            total_fragments,
            fragments: BTreeMap::new(),
            bytes_received: 0,
        }
    }

    fn add_fragment(&mut self, fragment: Fragment) -> Result<(), FragmentError> {
        if fragment.fragment_id != self.fragment_id {
            return Err(FragmentError::IdMismatch);
        }
        if fragment.total_fragments != self.total_fragments {
            return Err(FragmentError::TotalMismatch);
        }
        if fragment.fragment_index >= self.total_fragments {
            return Err(FragmentError::IndexOutOfRange);
        }
        if self.fragments.contains_key(&fragment.fragment_index) {
            return Err(FragmentError::DuplicateFragment);
        }

        self.bytes_received += fragment.data.len();
        self.fragments.insert(fragment.fragment_index, fragment.data);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total_fragments as usize
    }

    fn reassemble(self) -> Result<Vec<u8>, FragmentError> {
        if !self.is_complete() {
            return Err(FragmentError::Incomplete);
        }

        let mut data = Vec::with_capacity(self.bytes_received);
        for (_index, fragment_data) in self.fragments {
            data.extend_from_slice(&fragment_data);
        }
        Ok(data)
    }
}

/// Fragment Reassembler - reassembles fragments back into original data
#[derive(Debug)]
pub struct Reassembler {
    /// Active reassembly buffers (fragment_id -> buffer)
    buffers: BTreeMap<u32, ReassemblyBuffer>,
    /// Maximum number of concurrent reassembly buffers
    max_buffers: usize,
}

impl Reassembler {
    /// Create a new reassembler
    pub fn new() -> Self {
        Self {
            buffers: BTreeMap::new(),
            max_buffers: 256,
        }
    }

    /// Create a new reassembler with a custom buffer limit
    pub fn with_max_buffers(max_buffers: usize) -> Self {
        Self {
            buffers: BTreeMap::new(),
            max_buffers,
        }
    }

    /// Get the number of active reassembly buffers
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }

    /// Add a fragment and attempt reassembly
    ///
    /// Returns `Some(data)` if reassembly is complete, `None` if more fragments needed
    pub fn add_fragment(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, FragmentError> {
        let fragment_id = fragment.fragment_id;
        let total_fragments = fragment.total_fragments;

        // Single fragment case - no reassembly needed
        if total_fragments == 1 {
            return Ok(Some(fragment.data));
        }

        // Evict oldest buffer if at capacity (before borrowing for entry)
        if !self.buffers.contains_key(&fragment_id) && self.buffers.len() >= self.max_buffers {
            if let Some(&oldest_id) = self.buffers.keys().next() {
                self.buffers.remove(&oldest_id);
            }
        }

        // Get or create reassembly buffer
        let buffer = self
            .buffers
            .entry(fragment_id)
            .or_insert_with(|| ReassemblyBuffer::new(fragment_id, total_fragments));

        // Add fragment to buffer
        buffer.add_fragment(fragment)?;

        // Check if reassembly is complete
        if buffer.is_complete() {
            let buffer = self.buffers.remove(&fragment_id).unwrap();
            Ok(Some(buffer.reassemble()?))
        } else {
            Ok(None)
        }
    }

    /// Clear all reassembly buffers
    pub fn clear(&mut self) {
        self.buffers.clear();
    }

    /// Remove a specific reassembly buffer
    pub fn remove_buffer(&mut self, fragment_id: u32) {
        self.buffers.remove(&fragment_id);
    }

    /// Check if a fragment ID has an active reassembly buffer
    pub fn has_buffer(&self, fragment_id: u32) -> bool {
        self.buffers.contains_key(&fragment_id)
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === 2.4.1 Tests: MTU Fragmenter ===

    #[test]
    fn test_fragmenter_creation() {
        let frag = Fragmenter::new(1500);
        assert_eq!(frag.mtu(), 1500);

        let frag = Fragmenter::with_default_mtu();
        assert_eq!(frag.mtu(), DEFAULT_MTU);
    }

    #[test]
    fn test_fragmenter_mtu_clamping() {
        let frag = Fragmenter::new(100); // Below MIN_MTU
        assert_eq!(frag.mtu(), MIN_MTU);

        let frag = Fragmenter::new(100000); // Above MAX_MTU
        assert_eq!(frag.mtu(), MAX_MTU);
    }

    #[test]
    fn test_max_payload_size() {
        let frag = Fragmenter::new(1000);
        assert_eq!(frag.max_payload_size(), 1000 - FRAGMENT_HEADER_SIZE);
    }

    #[test]
    fn test_fragment_count() {
        let frag = Fragmenter::new(1000);
        let payload_size = frag.max_payload_size();

        assert_eq!(frag.fragment_count(0), 0);
        assert_eq!(frag.fragment_count(1), 1);
        assert_eq!(frag.fragment_count(payload_size), 1);
        assert_eq!(frag.fragment_count(payload_size + 1), 2);
        assert_eq!(frag.fragment_count(payload_size * 3), 3);
        assert_eq!(frag.fragment_count(payload_size * 3 + 1), 4);
    }

    #[test]
    fn test_needs_fragmentation() {
        let frag = Fragmenter::new(1000);
        let payload_size = frag.max_payload_size();

        assert!(!frag.needs_fragmentation(payload_size));
        assert!(frag.needs_fragmentation(payload_size + 1));
    }

    #[test]
    fn test_fragment_small_data() {
        let mut frag = Fragmenter::new(1000);
        let data = vec![1, 2, 3, 4, 5];

        let fragments = frag.fragment(&data).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].fragment_index, 0);
        assert_eq!(fragments[0].total_fragments, 1);
        assert_eq!(fragments[0].data, data);
    }

    #[test]
    fn test_fragment_large_data() {
        let mut frag = Fragmenter::new(1000);
        let payload_size = frag.max_payload_size();
        let data: Vec<u8> = (0..payload_size * 3 + 100).map(|i| i as u8).collect();

        let fragments = frag.fragment(&data).unwrap();
        assert_eq!(fragments.len(), 4);

        for (i, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.fragment_index, i as u16);
            assert_eq!(fragment.total_fragments, 4);
        }

        // First 3 fragments should be full size
        assert_eq!(fragments[0].data.len(), payload_size);
        assert_eq!(fragments[1].data.len(), payload_size);
        assert_eq!(fragments[2].data.len(), payload_size);
        // Last fragment should have remaining data
        assert_eq!(fragments[3].data.len(), 100);
    }

    #[test]
    fn test_fragment_empty_data() {
        let mut frag = Fragmenter::new(1000);
        let result = frag.fragment(&[]);
        assert!(matches!(result, Err(FragmentError::EmptyData)));
    }

    #[test]
    fn test_fragment_id_increments() {
        let mut frag = Fragmenter::new(1000);
        let data = vec![1, 2, 3];

        let fragments1 = frag.fragment(&data).unwrap();
        let fragments2 = frag.fragment(&data).unwrap();

        assert_eq!(fragments1[0].fragment_id, 0);
        assert_eq!(fragments2[0].fragment_id, 1);
    }

    #[test]
    fn test_fragment_with_specific_id() {
        let frag = Fragmenter::new(1000);
        let data = vec![1, 2, 3];

        let fragments = frag.fragment_with_id(&data, 42).unwrap();
        assert_eq!(fragments[0].fragment_id, 42);
    }

    // === Fragment Serialization Tests ===

    #[test]
    fn test_fragment_serialization() {
        let fragment = Fragment::new(12345, 2, 5, vec![1, 2, 3, 4, 5]);
        let bytes = fragment.to_bytes();

        assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE + 5);

        let parsed = Fragment::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, fragment);
    }

    #[test]
    fn test_fragment_from_invalid_bytes() {
        // Too short
        let result = Fragment::from_bytes(&[1, 2, 3]);
        assert!(matches!(result, Err(FragmentError::InvalidHeader)));

        // Data length mismatch
        let mut bytes = vec![0u8; FRAGMENT_HEADER_SIZE];
        bytes[8] = 0;
        bytes[9] = 10; // Claims 10 bytes of data
        let result = Fragment::from_bytes(&bytes);
        assert!(matches!(result, Err(FragmentError::InvalidDataLength)));
    }

    #[test]
    fn test_fragment_is_last() {
        let fragment = Fragment::new(0, 4, 5, vec![]);
        assert!(fragment.is_last());

        let fragment = Fragment::new(0, 3, 5, vec![]);
        assert!(!fragment.is_last());
    }

    // === 2.4.2 Tests: Reassembler ===

    #[test]
    fn test_reassembler_creation() {
        let reassembler = Reassembler::new();
        assert_eq!(reassembler.active_buffers(), 0);
    }

    #[test]
    fn test_reassemble_single_fragment() {
        let mut reassembler = Reassembler::new();
        let fragment = Fragment::new(0, 0, 1, vec![1, 2, 3, 4, 5]);

        let result = reassembler.add_fragment(fragment).unwrap();
        assert_eq!(result, Some(vec![1, 2, 3, 4, 5]));
        assert_eq!(reassembler.active_buffers(), 0);
    }

    #[test]
    fn test_reassemble_multiple_fragments_in_order() {
        let mut reassembler = Reassembler::new();

        let frag0 = Fragment::new(0, 0, 3, vec![1, 2, 3]);
        let frag1 = Fragment::new(0, 1, 3, vec![4, 5, 6]);
        let frag2 = Fragment::new(0, 2, 3, vec![7, 8, 9]);

        assert_eq!(reassembler.add_fragment(frag0).unwrap(), None);
        assert_eq!(reassembler.active_buffers(), 1);

        assert_eq!(reassembler.add_fragment(frag1).unwrap(), None);
        assert_eq!(reassembler.active_buffers(), 1);

        let result = reassembler.add_fragment(frag2).unwrap();
        assert_eq!(result, Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));
        assert_eq!(reassembler.active_buffers(), 0);
    }

    #[test]
    fn test_reassemble_multiple_fragments_out_of_order() {
        let mut reassembler = Reassembler::new();

        let frag0 = Fragment::new(0, 0, 3, vec![1, 2, 3]);
        let frag1 = Fragment::new(0, 1, 3, vec![4, 5, 6]);
        let frag2 = Fragment::new(0, 2, 3, vec![7, 8, 9]);

        // Add out of order: 2, 0, 1
        assert_eq!(reassembler.add_fragment(frag2).unwrap(), None);
        assert_eq!(reassembler.add_fragment(frag0).unwrap(), None);

        let result = reassembler.add_fragment(frag1).unwrap();
        assert_eq!(result, Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));
    }

    #[test]
    fn test_reassemble_duplicate_fragment() {
        let mut reassembler = Reassembler::new();

        let frag0 = Fragment::new(0, 0, 2, vec![1, 2, 3]);
        let frag0_dup = Fragment::new(0, 0, 2, vec![1, 2, 3]);

        reassembler.add_fragment(frag0).unwrap();
        let result = reassembler.add_fragment(frag0_dup);
        assert!(matches!(result, Err(FragmentError::DuplicateFragment)));
    }

    #[test]
    fn test_reassemble_index_out_of_range() {
        let mut reassembler = Reassembler::new();

        let frag = Fragment::new(0, 5, 3, vec![1, 2, 3]); // index 5 >= total 3
        let result = reassembler.add_fragment(frag);
        assert!(matches!(result, Err(FragmentError::IndexOutOfRange)));
    }

    #[test]
    fn test_reassemble_total_mismatch() {
        let mut reassembler = Reassembler::new();

        let frag0 = Fragment::new(0, 0, 3, vec![1, 2, 3]);
        let frag1 = Fragment::new(0, 1, 4, vec![4, 5, 6]); // Different total

        reassembler.add_fragment(frag0).unwrap();
        let result = reassembler.add_fragment(frag1);
        assert!(matches!(result, Err(FragmentError::TotalMismatch)));
    }

    #[test]
    fn test_reassemble_multiple_packets() {
        let mut reassembler = Reassembler::new();

        // Interleave fragments from two different packets
        let pkt1_frag0 = Fragment::new(1, 0, 2, vec![1, 2]);
        let pkt2_frag0 = Fragment::new(2, 0, 2, vec![10, 20]);
        let pkt1_frag1 = Fragment::new(1, 1, 2, vec![3, 4]);
        let pkt2_frag1 = Fragment::new(2, 1, 2, vec![30, 40]);

        assert_eq!(reassembler.add_fragment(pkt1_frag0).unwrap(), None);
        assert_eq!(reassembler.add_fragment(pkt2_frag0).unwrap(), None);
        assert_eq!(reassembler.active_buffers(), 2);

        let result1 = reassembler.add_fragment(pkt1_frag1).unwrap();
        assert_eq!(result1, Some(vec![1, 2, 3, 4]));
        assert_eq!(reassembler.active_buffers(), 1);

        let result2 = reassembler.add_fragment(pkt2_frag1).unwrap();
        assert_eq!(result2, Some(vec![10, 20, 30, 40]));
        assert_eq!(reassembler.active_buffers(), 0);
    }

    #[test]
    fn test_reassembler_clear() {
        let mut reassembler = Reassembler::new();

        let frag = Fragment::new(0, 0, 2, vec![1, 2, 3]);
        reassembler.add_fragment(frag).unwrap();
        assert_eq!(reassembler.active_buffers(), 1);

        reassembler.clear();
        assert_eq!(reassembler.active_buffers(), 0);
    }

    #[test]
    fn test_reassembler_remove_buffer() {
        let mut reassembler = Reassembler::new();

        let frag = Fragment::new(42, 0, 2, vec![1, 2, 3]);
        reassembler.add_fragment(frag).unwrap();
        assert!(reassembler.has_buffer(42));

        reassembler.remove_buffer(42);
        assert!(!reassembler.has_buffer(42));
    }

    // === 2.4.3 Tests: Fragment/Reassemble Round-trip ===

    #[test]
    fn test_roundtrip_small_data() {
        let mut fragmenter = Fragmenter::new(1000);
        let mut reassembler = Reassembler::new();

        let original = vec![1, 2, 3, 4, 5];
        let fragments = fragmenter.fragment(&original).unwrap();

        let mut result = None;
        for fragment in fragments {
            result = reassembler.add_fragment(fragment).unwrap();
        }

        assert_eq!(result, Some(original));
    }

    #[test]
    fn test_roundtrip_large_data() {
        let mut fragmenter = Fragmenter::new(1000);
        let mut reassembler = Reassembler::new();

        // Create data larger than MTU
        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        let fragments = fragmenter.fragment(&original).unwrap();

        assert!(fragments.len() > 1);

        let mut result = None;
        for fragment in fragments {
            result = reassembler.add_fragment(fragment).unwrap();
        }

        assert_eq!(result, Some(original));
    }

    #[test]
    fn test_roundtrip_exact_mtu_boundary() {
        let mut fragmenter = Fragmenter::new(1000);
        let mut reassembler = Reassembler::new();

        let payload_size = fragmenter.max_payload_size();

        // Exactly one fragment
        let original: Vec<u8> = (0..payload_size).map(|i| i as u8).collect();
        let fragments = fragmenter.fragment(&original).unwrap();
        assert_eq!(fragments.len(), 1);

        let result = reassembler.add_fragment(fragments.into_iter().next().unwrap()).unwrap();
        assert_eq!(result, Some(original));
    }

    #[test]
    fn test_roundtrip_with_serialization() {
        let mut fragmenter = Fragmenter::new(1000);
        let mut reassembler = Reassembler::new();

        let original: Vec<u8> = (0..3000).map(|i| i as u8).collect();
        let fragments = fragmenter.fragment(&original).unwrap();

        // Serialize and deserialize each fragment
        let mut result = None;
        for fragment in fragments {
            let bytes = fragment.to_bytes();
            let parsed = Fragment::from_bytes(&bytes).unwrap();
            result = reassembler.add_fragment(parsed).unwrap();
        }

        assert_eq!(result, Some(original));
    }

    #[test]
    fn test_roundtrip_out_of_order() {
        let mut fragmenter = Fragmenter::new(1000);
        let mut reassembler = Reassembler::new();

        let original: Vec<u8> = (0..3000).map(|i| i as u8).collect();
        let mut fragments = fragmenter.fragment(&original).unwrap();

        // Reverse order
        fragments.reverse();

        let mut result = None;
        for fragment in fragments {
            result = reassembler.add_fragment(fragment).unwrap();
        }

        assert_eq!(result, Some(original));
    }

    #[test]
    fn test_roundtrip_random_order() {
        let mut fragmenter = Fragmenter::new(1000);
        let mut reassembler = Reassembler::new();

        let original: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        let mut fragments = fragmenter.fragment(&original).unwrap();

        // Shuffle: swap pairs
        let len = fragments.len();
        for i in 0..len / 2 {
            fragments.swap(i, len - 1 - i);
        }

        let mut result = None;
        for fragment in fragments {
            result = reassembler.add_fragment(fragment).unwrap();
        }

        assert_eq!(result, Some(original));
    }
}
