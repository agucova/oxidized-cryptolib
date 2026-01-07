//! Deadline tracking for scheduler requests.
//!
//! Provides a min-heap of request deadlines that enables efficient
//! expiration checking. Uses generation counters to handle stale
//! entries from cancelled or completed requests.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Mutex;
use std::time::Instant;

use crate::scheduler::request::RequestId;

/// An entry in the deadline heap.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DeadlineEntry {
    /// When this request expires.
    deadline: Instant,
    /// The request ID.
    request_id: RequestId,
    /// Generation counter to detect stale entries.
    generation: u64,
}

impl Ord for DeadlineEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare by deadline (earliest first, hence Reverse)
        self.deadline.cmp(&other.deadline)
    }
}

impl PartialOrd for DeadlineEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Thread-safe deadline heap for tracking request expirations.
///
/// The heap is ordered by deadline (earliest first), enabling efficient
/// polling for expired requests. Generation counters handle stale entries
/// from cancelled or completed requests without requiring heap removal.
pub struct DeadlineHeap {
    /// Min-heap of deadlines (using Reverse for earliest-first ordering).
    heap: Mutex<BinaryHeap<Reverse<DeadlineEntry>>>,
    /// Current generation counter (monotonically increasing).
    generation: Mutex<u64>,
}

impl DeadlineHeap {
    /// Create a new empty deadline heap.
    pub fn new() -> Self {
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            generation: Mutex::new(0),
        }
    }

    /// Insert a deadline for a request.
    ///
    /// Returns the generation number assigned to this entry.
    /// The caller should store this generation to validate entries later.
    pub fn insert(&self, request_id: RequestId, deadline: Instant) -> u64 {
        let mut gen_guard = self.generation.lock().unwrap();
        let generation = *gen_guard;
        *gen_guard += 1;
        drop(gen_guard);

        let entry = DeadlineEntry {
            deadline,
            request_id,
            generation,
        };

        let mut heap = self.heap.lock().unwrap();
        heap.push(Reverse(entry));

        generation
    }

    /// Pop all expired requests from the heap.
    ///
    /// Returns a vector of (request_id, generation) pairs for requests
    /// whose deadlines have passed. The caller must verify the generation
    /// matches to ensure the entry is still valid.
    pub fn pop_expired(&self) -> Vec<(RequestId, u64)> {
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut heap = self.heap.lock().unwrap();

        while let Some(Reverse(entry)) = heap.peek() {
            if entry.deadline <= now {
                let Reverse(entry) = heap.pop().unwrap();
                expired.push((entry.request_id, entry.generation));
            } else {
                break;
            }
        }

        expired
    }

    /// Peek at the next deadline without removing it.
    ///
    /// Returns `None` if the heap is empty.
    pub fn peek_deadline(&self) -> Option<Instant> {
        let heap = self.heap.lock().unwrap();
        heap.peek().map(|Reverse(entry)| entry.deadline)
    }

    /// Get the number of entries in the heap.
    ///
    /// Note: This may include stale entries that haven't been cleaned up yet.
    pub fn len(&self) -> usize {
        self.heap.lock().unwrap().len()
    }

    /// Check if the heap is empty.
    pub fn is_empty(&self) -> bool {
        self.heap.lock().unwrap().is_empty()
    }

    /// Clear all entries from the heap.
    pub fn clear(&self) {
        self.heap.lock().unwrap().clear();
    }
}

impl Default for DeadlineHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_insert_and_pop_expired() {
        let heap = DeadlineHeap::new();
        let now = Instant::now();

        // Insert entries with deadlines in the past
        let past = now - Duration::from_millis(100);
        let gen1 = heap.insert(RequestId::new(1), past);
        let gen2 = heap.insert(RequestId::new(2), past);

        // Insert entry with deadline in the future
        let future = now + Duration::from_secs(60);
        let _gen3 = heap.insert(RequestId::new(3), future);

        // Pop expired should return the past deadlines
        let expired = heap.pop_expired();
        assert_eq!(expired.len(), 2);

        // Verify we got the right requests (order may vary)
        let ids: Vec<u64> = expired.iter().map(|(id, _)| id.raw()).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));

        // Verify generations
        for (id, generation) in &expired {
            if id.raw() == 1 {
                assert_eq!(*generation, gen1);
            } else if id.raw() == 2 {
                assert_eq!(*generation, gen2);
            }
        }

        // Future entry should still be in heap
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn test_ordering() {
        let heap = DeadlineHeap::new();
        let now = Instant::now();

        // Insert in reverse order
        heap.insert(RequestId::new(3), now + Duration::from_millis(300));
        heap.insert(RequestId::new(1), now + Duration::from_millis(100));
        heap.insert(RequestId::new(2), now + Duration::from_millis(200));

        // Peek should return earliest
        let next = heap.peek_deadline().unwrap();
        assert!(next < now + Duration::from_millis(150));
    }

    #[test]
    fn test_generation_counter() {
        let heap = DeadlineHeap::new();
        let now = Instant::now();

        let gen1 = heap.insert(RequestId::new(1), now);
        let gen2 = heap.insert(RequestId::new(2), now);
        let gen3 = heap.insert(RequestId::new(3), now);

        // Generations should be sequential
        assert_eq!(gen1, 0);
        assert_eq!(gen2, 1);
        assert_eq!(gen3, 2);
    }

    #[test]
    fn test_empty_heap() {
        let heap = DeadlineHeap::new();

        assert!(heap.is_empty());
        assert_eq!(heap.len(), 0);
        assert!(heap.peek_deadline().is_none());
        assert!(heap.pop_expired().is_empty());
    }

    #[test]
    fn test_clear() {
        let heap = DeadlineHeap::new();
        let now = Instant::now();

        heap.insert(RequestId::new(1), now);
        heap.insert(RequestId::new(2), now);
        assert_eq!(heap.len(), 2);

        heap.clear();
        assert!(heap.is_empty());
    }
}
