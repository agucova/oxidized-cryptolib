//! Per-lane bounded queues for FUSE request scheduling.
//!
//! Each lane has its own bounded queue, enabling:
//! - Independent admission control per lane
//! - Fail-fast when a specific lane is overloaded
//! - Fair scheduling across different operation types

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::scheduler::lane::{Lane, LaneCapacities};
use crate::scheduler::request::RequestId;

/// Error when admission is denied.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdmissionError {
    /// The lane queue is full.
    #[error("lane {lane:?} queue full (capacity: {capacity}, depth: {depth})")]
    QueueFull {
        lane: Lane,
        capacity: usize,
        depth: u64,
    },
    /// The scheduler is shut down.
    #[error("scheduler shut down")]
    Shutdown,
}

/// A request waiting in a lane queue.
pub struct QueuedRequest<T> {
    /// The request ID.
    pub id: RequestId,
    /// The lane this request belongs to.
    pub lane: Lane,
    /// The actual request data.
    pub data: T,
}

impl<T> std::fmt::Debug for QueuedRequest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedRequest")
            .field("id", &self.id)
            .field("lane", &self.lane)
            .finish_non_exhaustive()
    }
}

/// Statistics for a single lane.
#[derive(Debug, Default)]
pub struct LaneStats {
    /// Number of requests enqueued.
    pub enqueued: AtomicU64,
    /// Number of requests dequeued (dispatched).
    pub dequeued: AtomicU64,
    /// Number of requests rejected due to queue full.
    pub rejected: AtomicU64,
    /// Current queue depth.
    pub depth: AtomicU64,
}

impl LaneStats {
    /// Record an enqueue operation.
    pub fn record_enqueue(&self) {
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        self.depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a dequeue operation.
    pub fn record_dequeue(&self) {
        self.dequeued.fetch_add(1, Ordering::Relaxed);
        self.depth.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a rejection.
    pub fn record_reject(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current depth.
    pub fn current_depth(&self) -> u64 {
        self.depth.load(Ordering::Relaxed)
    }
}

/// A single lane's queue.
struct LaneQueue<T> {
    sender: Sender<QueuedRequest<T>>,
    receiver: Receiver<QueuedRequest<T>>,
    capacity: usize,
    stats: LaneStats,
}

impl<T> LaneQueue<T> {
    fn new(capacity: usize) -> Self {
        let (sender, receiver) = bounded(capacity);
        Self {
            sender,
            receiver,
            capacity,
            stats: LaneStats::default(),
        }
    }
}

/// Per-lane bounded queues for request scheduling.
///
/// Provides admission control and fair dequeuing across lanes.
pub struct LaneQueues<T> {
    /// Queue for L0 Control lane.
    control: LaneQueue<T>,
    /// Queue for L1 Metadata lane.
    metadata: LaneQueue<T>,
    /// Queue for L2 Read Foreground lane.
    read_foreground: LaneQueue<T>,
    /// Queue for L3 Write/Structural lane.
    write_structural: LaneQueue<T>,
    /// Queue for L4 Bulk lane.
    bulk: LaneQueue<T>,
}

impl<T> LaneQueues<T> {
    /// Create new lane queues with the given capacities.
    pub fn new(capacities: &LaneCapacities) -> Self {
        Self {
            control: LaneQueue::new(capacities.control),
            metadata: LaneQueue::new(capacities.metadata),
            read_foreground: LaneQueue::new(capacities.read_foreground),
            write_structural: LaneQueue::new(capacities.write_structural),
            bulk: LaneQueue::new(capacities.bulk),
        }
    }

    /// Get the queue for a specific lane.
    fn queue(&self, lane: Lane) -> &LaneQueue<T> {
        match lane {
            Lane::Control => &self.control,
            Lane::Metadata => &self.metadata,
            Lane::ReadForeground => &self.read_foreground,
            Lane::WriteStructural => &self.write_structural,
            Lane::Bulk => &self.bulk,
        }
    }

    /// Try to enqueue a request in the specified lane.
    ///
    /// Returns `Err(AdmissionError::QueueFull)` if the lane is at capacity.
    pub fn try_enqueue(
        &self,
        lane: Lane,
        id: RequestId,
        data: T,
    ) -> Result<(), AdmissionError> {
        let queue = self.queue(lane);
        let request = QueuedRequest { id, lane, data };

        match queue.sender.try_send(request) {
            Ok(()) => {
                queue.stats.record_enqueue();
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                queue.stats.record_reject();
                Err(AdmissionError::QueueFull {
                    lane,
                    capacity: queue.capacity,
                    depth: queue.stats.current_depth(),
                })
            }
            Err(TrySendError::Disconnected(_)) => Err(AdmissionError::Shutdown),
        }
    }

    /// Try to dequeue from a specific lane (non-blocking).
    ///
    /// Returns `None` if the queue is empty.
    pub fn try_dequeue(&self, lane: Lane) -> Option<QueuedRequest<T>> {
        let queue = self.queue(lane);
        match queue.receiver.try_recv() {
            Ok(request) => {
                queue.stats.record_dequeue();
                Some(request)
            }
            Err(_) => None,
        }
    }

    /// Get the current depth of a lane.
    pub fn depth(&self, lane: Lane) -> u64 {
        self.queue(lane).stats.current_depth()
    }

    /// Get the capacity of a lane.
    pub fn capacity(&self, lane: Lane) -> usize {
        self.queue(lane).capacity
    }

    /// Check if a lane is empty.
    pub fn is_empty(&self, lane: Lane) -> bool {
        self.queue(lane).receiver.is_empty()
    }

    /// Get statistics for a lane.
    pub fn stats(&self, lane: Lane) -> &LaneStats {
        &self.queue(lane).stats
    }

    /// Get aggregated statistics across all lanes.
    pub fn total_stats(&self) -> AggregatedLaneStats {
        AggregatedLaneStats {
            total_enqueued: self.control.stats.enqueued.load(Ordering::Relaxed)
                + self.metadata.stats.enqueued.load(Ordering::Relaxed)
                + self.read_foreground.stats.enqueued.load(Ordering::Relaxed)
                + self.write_structural.stats.enqueued.load(Ordering::Relaxed)
                + self.bulk.stats.enqueued.load(Ordering::Relaxed),
            total_dequeued: self.control.stats.dequeued.load(Ordering::Relaxed)
                + self.metadata.stats.dequeued.load(Ordering::Relaxed)
                + self.read_foreground.stats.dequeued.load(Ordering::Relaxed)
                + self.write_structural.stats.dequeued.load(Ordering::Relaxed)
                + self.bulk.stats.dequeued.load(Ordering::Relaxed),
            total_rejected: self.control.stats.rejected.load(Ordering::Relaxed)
                + self.metadata.stats.rejected.load(Ordering::Relaxed)
                + self.read_foreground.stats.rejected.load(Ordering::Relaxed)
                + self.write_structural.stats.rejected.load(Ordering::Relaxed)
                + self.bulk.stats.rejected.load(Ordering::Relaxed),
            total_depth: self.control.stats.depth.load(Ordering::Relaxed)
                + self.metadata.stats.depth.load(Ordering::Relaxed)
                + self.read_foreground.stats.depth.load(Ordering::Relaxed)
                + self.write_structural.stats.depth.load(Ordering::Relaxed)
                + self.bulk.stats.depth.load(Ordering::Relaxed),
        }
    }
}

/// Aggregated statistics across all lanes.
#[derive(Debug, Clone)]
pub struct AggregatedLaneStats {
    /// Total requests enqueued across all lanes.
    pub total_enqueued: u64,
    /// Total requests dequeued across all lanes.
    pub total_dequeued: u64,
    /// Total requests rejected across all lanes.
    pub total_rejected: u64,
    /// Total current depth across all lanes.
    pub total_depth: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lane_queue_basic() {
        let capacities = LaneCapacities::default();
        let queues: LaneQueues<String> = LaneQueues::new(&capacities);

        // Enqueue to metadata lane
        let id = RequestId::new(1);
        queues
            .try_enqueue(Lane::Metadata, id, "test".to_string())
            .unwrap();

        assert_eq!(queues.depth(Lane::Metadata), 1);
        assert!(!queues.is_empty(Lane::Metadata));

        // Dequeue
        let request = queues.try_dequeue(Lane::Metadata).unwrap();
        assert_eq!(request.id, id);
        assert_eq!(request.lane, Lane::Metadata);
        assert_eq!(request.data, "test");

        assert_eq!(queues.depth(Lane::Metadata), 0);
        assert!(queues.is_empty(Lane::Metadata));
    }

    #[test]
    fn test_lane_queue_full() {
        let capacities = LaneCapacities {
            control: 2,
            metadata: 2,
            read_foreground: 2,
            write_structural: 2,
            bulk: 2,
        };
        let queues: LaneQueues<u32> = LaneQueues::new(&capacities);

        // Fill the queue
        queues
            .try_enqueue(Lane::Metadata, RequestId::new(1), 1)
            .unwrap();
        queues
            .try_enqueue(Lane::Metadata, RequestId::new(2), 2)
            .unwrap();

        // Third should fail
        let result = queues.try_enqueue(Lane::Metadata, RequestId::new(3), 3);
        assert!(matches!(
            result,
            Err(AdmissionError::QueueFull {
                lane: Lane::Metadata,
                capacity: 2,
                ..
            })
        ));
    }

    #[test]
    fn test_lane_stats() {
        let capacities = LaneCapacities::default();
        let queues: LaneQueues<()> = LaneQueues::new(&capacities);

        // Enqueue
        queues
            .try_enqueue(Lane::ReadForeground, RequestId::new(1), ())
            .unwrap();
        queues
            .try_enqueue(Lane::ReadForeground, RequestId::new(2), ())
            .unwrap();

        let stats = queues.stats(Lane::ReadForeground);
        assert_eq!(stats.enqueued.load(Ordering::Relaxed), 2);
        assert_eq!(stats.current_depth(), 2);

        // Dequeue one
        queues.try_dequeue(Lane::ReadForeground);
        assert_eq!(stats.dequeued.load(Ordering::Relaxed), 1);
        assert_eq!(stats.current_depth(), 1);
    }

    #[test]
    fn test_aggregated_stats() {
        let capacities = LaneCapacities::default();
        let queues: LaneQueues<()> = LaneQueues::new(&capacities);

        queues
            .try_enqueue(Lane::Metadata, RequestId::new(1), ())
            .unwrap();
        queues
            .try_enqueue(Lane::ReadForeground, RequestId::new(2), ())
            .unwrap();
        queues
            .try_enqueue(Lane::WriteStructural, RequestId::new(3), ())
            .unwrap();

        let total = queues.total_stats();
        assert_eq!(total.total_enqueued, 3);
        assert_eq!(total.total_depth, 3);
    }

    #[test]
    fn test_all_lanes_independent() {
        let capacities = LaneCapacities {
            control: 1,
            metadata: 1,
            read_foreground: 1,
            write_structural: 1,
            bulk: 1,
        };
        let queues: LaneQueues<Lane> = LaneQueues::new(&capacities);

        // Each lane can hold one item
        for (i, lane) in [
            Lane::Control,
            Lane::Metadata,
            Lane::ReadForeground,
            Lane::WriteStructural,
            Lane::Bulk,
        ]
        .iter()
        .enumerate()
        {
            queues
                .try_enqueue(*lane, RequestId::new(i as u64), *lane)
                .unwrap();
        }

        // All lanes are full
        for lane in [
            Lane::Control,
            Lane::Metadata,
            Lane::ReadForeground,
            Lane::WriteStructural,
            Lane::Bulk,
        ] {
            assert!(queues.try_enqueue(lane, RequestId::new(100), lane).is_err());
        }

        // Dequeue from each lane
        for lane in [
            Lane::Control,
            Lane::Metadata,
            Lane::ReadForeground,
            Lane::WriteStructural,
            Lane::Bulk,
        ] {
            let request = queues.try_dequeue(lane).unwrap();
            assert_eq!(request.lane, lane);
            assert_eq!(request.data, lane);
        }
    }
}
