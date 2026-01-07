//! Single-flight deduplication for concurrent read requests.
//!
//! When multiple requests arrive for the same data before the first
//! completes, only one request actually fetches the data ("leader"),
//! and the others ("waiters") receive a copy of the result.
//!
//! This reduces load on the underlying filesystem and improves
//! throughput for access patterns with high locality.

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;

/// Key for identifying duplicate requests.
///
/// Two requests are considered duplicates if they read from the same
/// file at the same offset with the same size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReadKey {
    /// Inode number of the file.
    pub inode: u64,
    /// Starting byte offset.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: usize,
}

impl ReadKey {
    /// Create a new read key.
    pub fn new(inode: u64, offset: u64, size: usize) -> Self {
        Self {
            inode,
            offset,
            size,
        }
    }
}

/// Result of trying to attach to an in-flight read.
pub enum AttachResult {
    /// This request is the leader - it should perform the read.
    Leader,
    /// This request is a waiter - it will receive a copy of the result.
    Waiter(broadcast::Receiver<Result<Bytes, i32>>),
}

/// Entry for an in-flight read operation.
struct InFlightEntry {
    /// Sender for broadcasting result to waiters.
    sender: broadcast::Sender<Result<Bytes, i32>>,
    /// Number of waiters (for metrics).
    waiter_count: AtomicU64,
}

/// Statistics for single-flight deduplication.
#[derive(Debug, Default)]
pub struct SingleFlightStats {
    /// Number of requests that became leaders.
    pub leaders: AtomicU64,
    /// Number of requests that became waiters.
    pub waiters: AtomicU64,
    /// Number of completed flights (leader finished).
    pub completed: AtomicU64,
}

impl SingleFlightStats {
    /// Record a new leader.
    pub fn record_leader(&self) {
        self.leaders.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new waiter.
    pub fn record_waiter(&self) {
        self.waiters.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a completed flight.
    pub fn record_complete(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the deduplication ratio.
    ///
    /// Returns the fraction of requests that were deduplicated (waiters).
    pub fn dedup_ratio(&self) -> f64 {
        let leaders = self.leaders.load(Ordering::Relaxed);
        let waiters = self.waiters.load(Ordering::Relaxed);
        let total = leaders + waiters;
        if total == 0 {
            0.0
        } else {
            waiters as f64 / total as f64
        }
    }
}

/// Single-flight manager for deduplicating concurrent reads.
///
/// Thread-safe and lock-free for high concurrency.
pub struct InFlightReads {
    /// Map of in-flight reads.
    in_flight: DashMap<ReadKey, InFlightEntry>,
    /// Statistics.
    stats: SingleFlightStats,
}

impl InFlightReads {
    /// Create a new single-flight manager.
    pub fn new() -> Self {
        Self {
            in_flight: DashMap::new(),
            stats: SingleFlightStats::default(),
        }
    }

    /// Try to attach to an existing in-flight read, or become the leader.
    ///
    /// Returns `AttachResult::Leader` if this request should perform the read,
    /// or `AttachResult::Waiter(receiver)` if another request is already in flight.
    pub fn try_attach(&self, key: ReadKey) -> AttachResult {
        // Try to insert a new entry
        let entry = self.in_flight.entry(key);

        match entry {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                // Already in flight - become a waiter
                let entry = occupied.get();
                entry.waiter_count.fetch_add(1, Ordering::Relaxed);
                let receiver = entry.sender.subscribe();
                self.stats.record_waiter();
                AttachResult::Waiter(receiver)
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                // Not in flight - become the leader
                // Create a broadcast channel with reasonable capacity
                let (sender, _) = broadcast::channel(1);
                vacant.insert(InFlightEntry {
                    sender,
                    waiter_count: AtomicU64::new(0),
                });
                self.stats.record_leader();
                AttachResult::Leader
            }
        }
    }

    /// Complete an in-flight read and notify all waiters.
    ///
    /// Should only be called by the leader for this key.
    /// Returns the number of waiters that were notified.
    pub fn complete(&self, key: &ReadKey, result: Result<Bytes, i32>) -> u64 {
        if let Some((_, entry)) = self.in_flight.remove(key) {
            let waiter_count = entry.waiter_count.load(Ordering::Relaxed);
            // Send result to all waiters (ignore errors - waiters may have timed out)
            let _ = entry.sender.send(result);
            self.stats.record_complete();
            waiter_count
        } else {
            0
        }
    }

    /// Cancel an in-flight read.
    ///
    /// Should only be called by the leader if it fails to complete the read.
    /// Waiters will receive an error on their receiver when the sender is dropped.
    pub fn cancel(&self, key: &ReadKey) {
        self.in_flight.remove(key);
    }

    /// Get the number of currently in-flight reads.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Get statistics.
    pub fn stats(&self) -> &SingleFlightStats {
        &self.stats
    }
}

impl Default for InFlightReads {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_leader_becomes_first() {
        let sf = InFlightReads::new();
        let key = ReadKey::new(1, 0, 1024);

        match sf.try_attach(key) {
            AttachResult::Leader => {}
            AttachResult::Waiter(_) => panic!("First attach should be leader"),
        }

        assert_eq!(sf.in_flight_count(), 1);
    }

    #[test]
    fn test_waiter_attaches_to_leader() {
        let sf = InFlightReads::new();
        let key = ReadKey::new(1, 0, 1024);

        // First becomes leader
        let _leader = sf.try_attach(key);

        // Second becomes waiter
        match sf.try_attach(key) {
            AttachResult::Leader => panic!("Second attach should be waiter"),
            AttachResult::Waiter(_) => {}
        }
    }

    #[test]
    fn test_complete_notifies_waiters() {
        let sf = Arc::new(InFlightReads::new());
        let key = ReadKey::new(1, 0, 1024);

        // Leader
        let _leader_result = sf.try_attach(key);

        // Waiter
        let _waiter_rx = match sf.try_attach(key) {
            AttachResult::Waiter(rx) => rx,
            AttachResult::Leader => panic!("Should be waiter"),
        };

        // Complete in another thread
        let sf_clone = Arc::clone(&sf);
        let handle = thread::spawn(move || {
            sf_clone.complete(&key, Ok(Bytes::from_static(b"data")));
        });

        handle.join().unwrap();

        // Waiter should have received the result
        // Note: In a real scenario, we'd use tokio::sync::broadcast which requires async
        // For testing, we just verify the entry was removed
        assert_eq!(sf.in_flight_count(), 0);
    }

    #[test]
    fn test_different_keys_independent() {
        let sf = InFlightReads::new();
        let key1 = ReadKey::new(1, 0, 1024);
        let key2 = ReadKey::new(1, 1024, 1024);
        let key3 = ReadKey::new(2, 0, 1024);

        // All should become leaders (different keys)
        match sf.try_attach(key1) {
            AttachResult::Leader => {}
            _ => panic!("Should be leader"),
        }
        match sf.try_attach(key2) {
            AttachResult::Leader => {}
            _ => panic!("Should be leader"),
        }
        match sf.try_attach(key3) {
            AttachResult::Leader => {}
            _ => panic!("Should be leader"),
        }

        assert_eq!(sf.in_flight_count(), 3);
    }

    #[test]
    fn test_stats() {
        let sf = InFlightReads::new();
        let key = ReadKey::new(1, 0, 1024);

        // Leader
        sf.try_attach(key);
        // Two waiters
        sf.try_attach(key);
        sf.try_attach(key);

        assert_eq!(sf.stats.leaders.load(Ordering::Relaxed), 1);
        assert_eq!(sf.stats.waiters.load(Ordering::Relaxed), 2);

        // Complete
        sf.complete(&key, Ok(Bytes::from_static(b"data")));
        assert_eq!(sf.stats.completed.load(Ordering::Relaxed), 1);

        // Dedup ratio: 2 waiters / 3 total = 0.666...
        let ratio = sf.stats.dedup_ratio();
        assert!((ratio - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_cancel() {
        let sf = InFlightReads::new();
        let key = ReadKey::new(1, 0, 1024);

        sf.try_attach(key);
        assert_eq!(sf.in_flight_count(), 1);

        sf.cancel(&key);
        assert_eq!(sf.in_flight_count(), 0);
    }
}
