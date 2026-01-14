//! Deep Buffer and ACK management for qrelay.
//!
//! This module provides buffers for managing unacknowledged data during
//! proxy-to-proxy communication, enabling reconnection support.

use bytes::Bytes;
use std::collections::{BTreeMap, VecDeque};
use thiserror::Error;

/// Default maximum buffer size (64MB).
pub const DEFAULT_MAX_BUFFER_BYTES: u64 = 64 * 1024 * 1024;

/// Buffer error types.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BufferError {
    /// Buffer limit exceeded.
    #[error("buffer full")]
    BufferFull,
    /// Invalid offset (already acknowledged data).
    #[error("invalid offset")]
    InvalidOffset,
}

/// Result type for buffer operations.
pub type BufferResult<T> = std::result::Result<T, BufferError>;

/// Session state for proxy connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state before connection.
    Init,
    /// Active connection.
    Active,
    /// Disconnected, waiting for reconnection.
    Disconnected,
    /// Resuming connection.
    Resuming,
    /// Connection closed.
    Closed,
}

/// An entry in the send buffer.
#[derive(Debug, Clone)]
struct SendEntry {
    /// Starting offset of this chunk.
    offset: u64,
    /// Data bytes.
    data: Bytes,
}

impl SendEntry {
    /// Returns the end offset (exclusive) of this entry.
    fn end_offset(&self) -> u64 {
        self.offset + self.data.len() as u64
    }
}

/// Send buffer for holding unacknowledged data.
///
/// The sender uses this buffer to store data that has been sent but not yet
/// acknowledged. This enables retransmission after reconnection.
#[derive(Debug)]
pub struct SendBuffer {
    /// Maximum bytes to buffer.
    max_bytes: u64,
    /// Current buffered bytes.
    buffered_bytes: u64,
    /// Next offset to assign.
    next_offset: u64,
    /// Highest acknowledged offset.
    acked_offset: u64,
    /// Queue of unacknowledged entries.
    entries: VecDeque<SendEntry>,
}

impl SendBuffer {
    /// Create a new SendBuffer with the specified maximum size.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            buffered_bytes: 0,
            next_offset: 0,
            acked_offset: 0,
            entries: VecDeque::new(),
        }
    }

    /// Get the next offset to be assigned.
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Push data to the buffer.
    ///
    /// Returns the assigned offset for this data.
    pub fn push(&mut self, data: Bytes) -> BufferResult<u64> {
        // Handle empty data - return current offset without creating an entry
        if data.is_empty() {
            return Ok(self.next_offset);
        }

        let data_len = data.len() as u64;

        // Check if adding this data would exceed the buffer limit
        if self.buffered_bytes + data_len > self.max_bytes {
            return Err(BufferError::BufferFull);
        }

        let offset = self.next_offset;
        self.next_offset += data_len;
        self.buffered_bytes += data_len;

        self.entries.push_back(SendEntry { offset, data });

        Ok(offset)
    }

    /// Process an ACK, releasing all data up to and including the given offset.
    pub fn ack(&mut self, offset: u64) {
        // Ignore ACKs for already acknowledged data
        if offset <= self.acked_offset {
            return;
        }

        // Remove all entries that are fully acknowledged
        while let Some(entry) = self.entries.front() {
            if entry.end_offset() <= offset {
                let entry = self.entries.pop_front().unwrap();
                self.buffered_bytes -= entry.data.len() as u64;
            } else {
                break;
            }
        }

        self.acked_offset = offset;
    }

    /// Get data from the specified offset for retransmission.
    ///
    /// Returns a vector of (offset, data) pairs starting from the given offset.
    pub fn get_from(&self, offset: u64) -> Vec<(u64, Bytes)> {
        let mut result = Vec::new();

        for entry in &self.entries {
            if entry.end_offset() <= offset {
                // This entry is fully before the requested offset
                continue;
            }

            if entry.offset >= offset {
                // This entry starts at or after the requested offset
                result.push((entry.offset, entry.data.clone()));
            } else {
                // This entry partially overlaps with the requested offset
                let skip = (offset - entry.offset) as usize;
                let partial_data = entry.data.slice(skip..);
                result.push((offset, partial_data));
            }
        }

        result
    }

    /// Get the current buffered bytes count.
    pub fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }

    /// Get the highest acknowledged offset.
    pub fn acked_offset(&self) -> u64 {
        self.acked_offset
    }
}

/// Receive buffer for reordering out-of-order data.
///
/// The receiver uses this buffer to reassemble data that may arrive
/// out of order, ensuring in-order delivery to the application.
#[derive(Debug)]
pub struct RecvBuffer {
    /// Maximum bytes to buffer.
    max_bytes: u64,
    /// Current buffered bytes.
    buffered_bytes: u64,
    /// Next expected offset (consumed up to this point).
    consumed_offset: u64,
    /// Out-of-order entries, keyed by offset for O(log n) insertion.
    entries: BTreeMap<u64, Bytes>,
}

impl RecvBuffer {
    /// Create a new RecvBuffer with the specified maximum size.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            buffered_bytes: 0,
            consumed_offset: 0,
            entries: BTreeMap::new(),
        }
    }

    /// Insert data at the specified offset.
    ///
    /// Data that overlaps with already consumed data is trimmed.
    /// Duplicate data is ignored.
    pub fn insert(&mut self, offset: u64, data: Bytes) -> BufferResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let end_offset = offset + data.len() as u64;

        // If this data is fully before the consumed offset, ignore it
        if end_offset <= self.consumed_offset {
            return Ok(());
        }

        // Trim data that overlaps with already consumed portion
        let (actual_offset, actual_data) = if offset < self.consumed_offset {
            let skip = (self.consumed_offset - offset) as usize;
            (self.consumed_offset, data.slice(skip..))
        } else {
            (offset, data)
        };

        // Handle overlap with previous entry using BTreeMap range queries
        let (actual_offset, actual_data) = {
            // Find the entry with the largest offset <= actual_offset
            if let Some((&prev_offset, prev_data)) =
                self.entries.range(..=actual_offset).next_back()
            {
                let prev_end = prev_offset + prev_data.len() as u64;
                if prev_end > actual_offset {
                    // Overlaps with previous entry - skip the overlapping part
                    let skip = (prev_end - actual_offset) as usize;
                    if skip >= actual_data.len() {
                        // Fully covered by previous entry
                        return Ok(());
                    }
                    (prev_end, actual_data.slice(skip..))
                } else {
                    (actual_offset, actual_data)
                }
            } else {
                (actual_offset, actual_data)
            }
        };

        // Handle overlap with next entry
        let actual_data = {
            // Find the entry with the smallest offset > actual_offset
            if let Some((&next_offset, _)) = self.entries.range((actual_offset + 1)..).next() {
                let actual_end = actual_offset + actual_data.len() as u64;
                if actual_end > next_offset {
                    // Overlaps with next entry - trim the overlapping part
                    let keep = (next_offset - actual_offset) as usize;
                    if keep == 0 {
                        // Fully covered by next entry
                        return Ok(());
                    }
                    actual_data.slice(..keep)
                } else {
                    actual_data
                }
            } else {
                actual_data
            }
        };

        // After trimming, check if there's any data left
        if actual_data.is_empty() {
            return Ok(());
        }

        let data_len = actual_data.len() as u64;

        // Re-check buffer limit with potentially trimmed data
        if self.buffered_bytes + data_len > self.max_bytes {
            return Err(BufferError::BufferFull);
        }

        // BTreeMap::insert is O(log n) instead of VecDeque::insert which is O(n)
        self.entries.insert(actual_offset, actual_data);
        self.buffered_bytes += data_len;

        Ok(())
    }

    /// Read contiguous data from the buffer.
    ///
    /// Returns the data and the new consumed offset, or None if no
    /// contiguous data is available.
    pub fn read(&mut self) -> Option<(Bytes, u64)> {
        if self.entries.is_empty() {
            return None;
        }

        // Get the first entry (smallest offset due to BTreeMap ordering)
        let first_offset = *self.entries.first_key_value()?.0;

        // Check if the first entry is contiguous with consumed data
        if first_offset != self.consumed_offset {
            return None;
        }

        let data = self.entries.remove(&first_offset).unwrap();
        self.buffered_bytes -= data.len() as u64;
        self.consumed_offset = first_offset + data.len() as u64;

        Some((data, self.consumed_offset))
    }

    /// Get the consumed offset (for ACK purposes).
    pub fn acked_offset(&self) -> u64 {
        self.consumed_offset
    }

    /// Get the current buffered bytes count.
    pub fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SendBuffer tests

    #[test]
    fn test_send_buffer_new() {
        let buf = SendBuffer::new(1024);
        assert_eq!(buf.next_offset(), 0);
        assert_eq!(buf.acked_offset(), 0);
        assert_eq!(buf.buffered_bytes(), 0);
    }

    #[test]
    fn test_send_buffer_push() {
        let mut buf = SendBuffer::new(1024);

        let offset1 = buf.push(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(offset1, 0);
        assert_eq!(buf.next_offset(), 5);
        assert_eq!(buf.buffered_bytes(), 5);

        let offset2 = buf.push(Bytes::from_static(b"world")).unwrap();
        assert_eq!(offset2, 5);
        assert_eq!(buf.next_offset(), 10);
        assert_eq!(buf.buffered_bytes(), 10);
    }

    #[test]
    fn test_send_buffer_push_empty() {
        let mut buf = SendBuffer::new(1024);

        let offset = buf.push(Bytes::new()).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(buf.next_offset(), 0);
        assert_eq!(buf.buffered_bytes(), 0);
    }

    #[test]
    fn test_send_buffer_push_buffer_full() {
        let mut buf = SendBuffer::new(10);

        buf.push(Bytes::from_static(b"hello")).unwrap();
        let result = buf.push(Bytes::from_static(b"world!"));

        assert_eq!(result, Err(BufferError::BufferFull));
        assert_eq!(buf.buffered_bytes(), 5);
    }

    #[test]
    fn test_send_buffer_ack() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap(); // 0-5
        buf.push(Bytes::from_static(b"world")).unwrap(); // 5-10

        buf.ack(5);
        assert_eq!(buf.acked_offset(), 5);
        assert_eq!(buf.buffered_bytes(), 5);

        buf.ack(10);
        assert_eq!(buf.acked_offset(), 10);
        assert_eq!(buf.buffered_bytes(), 0);
    }

    #[test]
    fn test_send_buffer_ack_partial() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap(); // 0-5
        buf.push(Bytes::from_static(b"world")).unwrap(); // 5-10

        // ACK in the middle of an entry - only fully acked entries are removed
        buf.ack(3);
        assert_eq!(buf.acked_offset(), 3);
        assert_eq!(buf.buffered_bytes(), 10); // Both entries still present

        buf.ack(7);
        assert_eq!(buf.acked_offset(), 7);
        assert_eq!(buf.buffered_bytes(), 5); // First entry removed
    }

    #[test]
    fn test_send_buffer_ack_duplicate() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap();
        buf.ack(5);
        buf.ack(3); // Duplicate ACK for already acked data

        assert_eq!(buf.acked_offset(), 5);
    }

    #[test]
    fn test_send_buffer_get_from() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap(); // 0-5
        buf.push(Bytes::from_static(b"world")).unwrap(); // 5-10

        // Get all data
        let data = buf.get_from(0);
        assert_eq!(data.len(), 2);
        assert_eq!(data[0], (0, Bytes::from_static(b"hello")));
        assert_eq!(data[1], (5, Bytes::from_static(b"world")));

        // Get from middle
        let data = buf.get_from(5);
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], (5, Bytes::from_static(b"world")));

        // Get with partial overlap
        let data = buf.get_from(3);
        assert_eq!(data.len(), 2);
        assert_eq!(data[0], (3, Bytes::from_static(b"lo")));
        assert_eq!(data[1], (5, Bytes::from_static(b"world")));
    }

    #[test]
    fn test_send_buffer_get_from_after_ack() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap(); // 0-5
        buf.push(Bytes::from_static(b"world")).unwrap(); // 5-10

        buf.ack(5);

        let data = buf.get_from(0);
        // Only "world" remains, but requested from 0 so we get data from 5
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], (5, Bytes::from_static(b"world")));
    }

    #[test]
    fn test_send_buffer_get_from_empty() {
        let buf = SendBuffer::new(1024);
        let data = buf.get_from(0);
        assert!(data.is_empty());
    }

    #[test]
    fn test_send_buffer_get_from_beyond() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap();

        let data = buf.get_from(10);
        assert!(data.is_empty());
    }

    // RecvBuffer tests

    #[test]
    fn test_recv_buffer_new() {
        let buf = RecvBuffer::new(1024);
        assert_eq!(buf.acked_offset(), 0);
        assert_eq!(buf.buffered_bytes(), 0);
    }

    #[test]
    fn test_recv_buffer_insert_in_order() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5);

        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));
        assert_eq!(offset, 5);
        assert_eq!(buf.acked_offset(), 5);
    }

    #[test]
    fn test_recv_buffer_insert_empty() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::new()).unwrap();
        assert_eq!(buf.buffered_bytes(), 0);
        assert!(buf.read().is_none());
    }

    #[test]
    fn test_recv_buffer_insert_out_of_order() {
        let mut buf = RecvBuffer::new(1024);

        // Insert second chunk first
        buf.insert(5, Bytes::from_static(b"world")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5);

        // Cannot read yet - gap at offset 0
        assert!(buf.read().is_none());

        // Insert first chunk
        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(buf.buffered_bytes(), 10);

        // Now can read first chunk
        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));
        assert_eq!(offset, 5);

        // And second chunk
        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"world"));
        assert_eq!(offset, 10);
    }

    #[test]
    fn test_recv_buffer_insert_with_gap() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        buf.insert(10, Bytes::from_static(b"!")).unwrap(); // Gap at 5-10

        // Can read first chunk
        let (data, _) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));

        // Cannot read - gap exists
        assert!(buf.read().is_none());
        assert_eq!(buf.acked_offset(), 5);
    }

    #[test]
    fn test_recv_buffer_insert_buffer_full() {
        let mut buf = RecvBuffer::new(10);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        let result = buf.insert(5, Bytes::from_static(b"world!"));

        assert_eq!(result, Err(BufferError::BufferFull));
        assert_eq!(buf.buffered_bytes(), 5);
    }

    #[test]
    fn test_recv_buffer_insert_duplicate() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        buf.insert(0, Bytes::from_static(b"hello")).unwrap(); // Exact duplicate

        assert_eq!(buf.buffered_bytes(), 5);
    }

    #[test]
    fn test_recv_buffer_insert_already_consumed() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        buf.read().unwrap();

        // Insert data before consumed offset - should be ignored
        buf.insert(0, Bytes::from_static(b"old")).unwrap();
        assert_eq!(buf.buffered_bytes(), 0);
    }

    #[test]
    fn test_recv_buffer_insert_partial_overlap_with_consumed() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        buf.read().unwrap();
        assert_eq!(buf.acked_offset(), 5);

        // Insert data that partially overlaps with consumed region
        buf.insert(3, Bytes::from_static(b"loworld")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5); // Only "world" portion stored

        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"world"));
        assert_eq!(offset, 10);
    }

    #[test]
    fn test_recv_buffer_read_empty() {
        let mut buf = RecvBuffer::new(1024);
        assert!(buf.read().is_none());
    }

    #[test]
    fn test_recv_buffer_multiple_reads() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"a")).unwrap();
        buf.insert(1, Bytes::from_static(b"b")).unwrap();
        buf.insert(2, Bytes::from_static(b"c")).unwrap();

        assert_eq!(buf.read().unwrap().0, Bytes::from_static(b"a"));
        assert_eq!(buf.read().unwrap().0, Bytes::from_static(b"b"));
        assert_eq!(buf.read().unwrap().0, Bytes::from_static(b"c"));
        assert!(buf.read().is_none());

        assert_eq!(buf.acked_offset(), 3);
    }

    // SessionState tests

    #[test]
    fn test_session_state_values() {
        // Ensure all states are distinct
        assert_ne!(SessionState::Init, SessionState::Active);
        assert_ne!(SessionState::Active, SessionState::Disconnected);
        assert_ne!(SessionState::Disconnected, SessionState::Resuming);
        assert_ne!(SessionState::Resuming, SessionState::Closed);
    }

    #[test]
    fn test_session_state_copy() {
        let state = SessionState::Active;
        let copied = state;
        assert_eq!(state, copied);
    }

    // Edge case tests

    #[test]
    fn test_send_buffer_large_data() {
        let mut buf = SendBuffer::new(1024 * 1024); // 1MB

        let large_data = Bytes::from(vec![0u8; 100_000]);
        let offset = buf.push(large_data.clone()).unwrap();

        assert_eq!(offset, 0);
        assert_eq!(buf.buffered_bytes(), 100_000);

        let data = buf.get_from(0);
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].1.len(), 100_000);
    }

    #[test]
    fn test_recv_buffer_large_data() {
        let mut buf = RecvBuffer::new(1024 * 1024); // 1MB

        let large_data = Bytes::from(vec![0u8; 100_000]);
        buf.insert(0, large_data.clone()).unwrap();

        let (data, offset) = buf.read().unwrap();
        assert_eq!(data.len(), 100_000);
        assert_eq!(offset, 100_000);
    }

    #[test]
    fn test_send_buffer_exact_limit() {
        let mut buf = SendBuffer::new(10);

        buf.push(Bytes::from_static(b"hello")).unwrap();
        buf.push(Bytes::from_static(b"world")).unwrap(); // Exactly at limit

        assert_eq!(buf.buffered_bytes(), 10);

        // One more byte should fail
        let result = buf.push(Bytes::from_static(b"!"));
        assert_eq!(result, Err(BufferError::BufferFull));
    }

    #[test]
    fn test_recv_buffer_exact_limit() {
        let mut buf = RecvBuffer::new(10);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        buf.insert(5, Bytes::from_static(b"world")).unwrap(); // Exactly at limit

        assert_eq!(buf.buffered_bytes(), 10);

        // One more byte should fail
        let result = buf.insert(10, Bytes::from_static(b"!"));
        assert_eq!(result, Err(BufferError::BufferFull));
    }

    #[test]
    fn test_send_buffer_ack_allows_more_data() {
        let mut buf = SendBuffer::new(10);

        buf.push(Bytes::from_static(b"hello")).unwrap();
        buf.push(Bytes::from_static(b"world")).unwrap();

        // Buffer is full
        assert_eq!(buf.push(Bytes::from_static(b"!")), Err(BufferError::BufferFull));

        // ACK first chunk
        buf.ack(5);

        // Now we can push more
        buf.push(Bytes::from_static(b"!")).unwrap();
        assert_eq!(buf.buffered_bytes(), 6);
    }

    #[test]
    fn test_recv_buffer_read_frees_space() {
        let mut buf = RecvBuffer::new(10);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        buf.insert(5, Bytes::from_static(b"world")).unwrap();

        // Buffer is full
        assert_eq!(buf.insert(10, Bytes::from_static(b"!")), Err(BufferError::BufferFull));

        // Read first chunk
        buf.read().unwrap();

        // Now we can insert more
        buf.insert(10, Bytes::from_static(b"!")).unwrap();
        assert_eq!(buf.buffered_bytes(), 6);
    }

    // Partial overlap tests for RecvBuffer

    #[test]
    fn test_recv_buffer_partial_overlap_with_previous() {
        let mut buf = RecvBuffer::new(1024);

        // Insert first chunk
        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5);

        // Insert overlapping chunk - overlaps "lo" with previous
        buf.insert(3, Bytes::from_static(b"loworld")).unwrap();
        // Only "world" should be stored (skipping "lo")
        assert_eq!(buf.buffered_bytes(), 10);

        // Read and verify
        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));
        assert_eq!(offset, 5);

        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"world"));
        assert_eq!(offset, 10);
    }

    #[test]
    fn test_recv_buffer_partial_overlap_with_next() {
        let mut buf = RecvBuffer::new(1024);

        // Insert second chunk first
        buf.insert(5, Bytes::from_static(b"world")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5);

        // Insert overlapping chunk - extends into "world"
        buf.insert(0, Bytes::from_static(b"hellow")).unwrap();
        // Only "hello" should be stored (trimming the "w")
        assert_eq!(buf.buffered_bytes(), 10);

        // Read and verify
        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"hello"));
        assert_eq!(offset, 5);

        let (data, offset) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"world"));
        assert_eq!(offset, 10);
    }

    #[test]
    fn test_recv_buffer_partial_overlap_both_sides() {
        let mut buf = RecvBuffer::new(1024);

        // Insert first and third chunks
        buf.insert(0, Bytes::from_static(b"hel")).unwrap();
        buf.insert(7, Bytes::from_static(b"rld")).unwrap();
        assert_eq!(buf.buffered_bytes(), 6);

        // Insert chunk that overlaps with both - "ello wo"
        buf.insert(1, Bytes::from_static(b"ello wo")).unwrap();
        // Should be trimmed to "lo w" (skipping "el" and trimming "o")
        assert_eq!(buf.buffered_bytes(), 10);

        // Read and verify continuity
        let (data, _) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"hel"));

        let (data, _) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"lo w"));

        let (data, _) = buf.read().unwrap();
        assert_eq!(data, Bytes::from_static(b"rld"));
    }

    #[test]
    fn test_recv_buffer_fully_covered_by_previous() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5);

        // Insert chunk fully covered by previous
        buf.insert(1, Bytes::from_static(b"ell")).unwrap();
        // Should be ignored (no change in buffered bytes)
        assert_eq!(buf.buffered_bytes(), 5);
    }

    #[test]
    fn test_recv_buffer_fully_covered_by_next() {
        let mut buf = RecvBuffer::new(1024);

        buf.insert(0, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(buf.buffered_bytes(), 5);

        // Insert chunk at same position but shorter
        buf.insert(0, Bytes::from_static(b"hel")).unwrap();
        // Should be ignored (fully covered by existing entry)
        assert_eq!(buf.buffered_bytes(), 5);
    }

    #[test]
    fn test_send_buffer_push_empty_after_data() {
        let mut buf = SendBuffer::new(1024);

        buf.push(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(buf.next_offset(), 5);

        // Push empty data should return current offset without modifying state
        let offset = buf.push(Bytes::new()).unwrap();
        assert_eq!(offset, 5);
        assert_eq!(buf.next_offset(), 5);
        assert_eq!(buf.buffered_bytes(), 5);
    }
}
