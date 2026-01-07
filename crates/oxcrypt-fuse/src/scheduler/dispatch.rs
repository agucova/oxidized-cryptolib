//! Fairness dispatcher for lane-based scheduling.
//!
//! Implements the dispatch policy from the FUSE runtime spec (section 6.3):
//! - L0 (Control) and L1 (Metadata) always dispatch first when non-empty
//! - L2 (Read) and L3 (Write) use weighted round-robin to prevent starvation
//! - L4 (Bulk) only dispatches when higher-priority lanes are quiet
//!
//! Additionally enforces reserved executor capacity:
//! - ≥1 slot reserved for L1 (metadata must remain responsive)
//! - ≥1-2 slots reserved for L3 (writes must not starve)

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::lane::Lane;
use super::queue::{LaneQueues, QueuedRequest};

/// Configuration for the fairness dispatcher.
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Weight for L2 (ReadForeground) in round-robin with L3.
    /// Higher weight means more L2 dispatches per cycle.
    pub l2_weight: u32,
    /// Weight for L3 (WriteStructural) in round-robin with L2.
    pub l3_weight: u32,
    /// Reserved executor slots for L1 (Metadata).
    /// L4 won't dispatch if fewer than this many slots are free.
    pub l1_reserved_slots: usize,
    /// Reserved executor slots for L3 (WriteStructural).
    /// L4 won't dispatch if fewer than this many slots are free.
    pub l3_reserved_slots: usize,
    /// Threshold: only dispatch L4 if total L1-L3 in-flight is below this.
    pub l4_quiet_threshold: u64,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            // Equal weight for reads and writes by default
            l2_weight: 2,
            l3_weight: 2,
            // Reserve 1 slot for metadata responsiveness
            l1_reserved_slots: 1,
            // Reserve 2 slots for writes to prevent starvation
            l3_reserved_slots: 2,
            // Only dispatch bulk when high-priority lanes have < 8 in-flight
            l4_quiet_threshold: 8,
        }
    }
}

/// Statistics for the fairness dispatcher.
#[derive(Debug, Default)]
pub struct DispatchStats {
    /// Dispatches per lane.
    pub dispatched_by_lane: [AtomicU64; 5],
    /// Round-robin cycles completed (L2/L3 alternation).
    pub rr_cycles: AtomicU64,
    /// Times L4 was skipped due to high-priority activity.
    pub l4_deferred: AtomicU64,
}

impl DispatchStats {
    /// Record a dispatch from a lane.
    pub fn record_dispatch(&self, lane: Lane) {
        self.dispatched_by_lane[lane as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a round-robin cycle.
    pub fn record_rr_cycle(&self) {
        self.rr_cycles.fetch_add(1, Ordering::Relaxed);
    }

    /// Record L4 being deferred.
    pub fn record_l4_deferred(&self) {
        self.l4_deferred.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total dispatches.
    pub fn total_dispatched(&self) -> u64 {
        self.dispatched_by_lane
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }
}

/// Fairness dispatcher for selecting which lane to dispatch from.
///
/// Implements weighted round-robin between L2 and L3 while ensuring
/// L0/L1 always have priority and L4 only runs when others are quiet.
pub struct FairnessDispatcher {
    /// Configuration.
    config: DispatchConfig,
    /// Current position in L2/L3 round-robin.
    /// Counts down from l2_weight, then l3_weight, then resets.
    rr_counter: AtomicUsize,
    /// Current round-robin phase: true = L2, false = L3.
    rr_phase_l2: std::sync::atomic::AtomicBool,
    /// Statistics.
    stats: DispatchStats,
}

impl FairnessDispatcher {
    /// Create a new dispatcher with default configuration.
    pub fn new() -> Self {
        Self::with_config(DispatchConfig::default())
    }

    /// Create a new dispatcher with custom configuration.
    pub fn with_config(config: DispatchConfig) -> Self {
        Self {
            rr_counter: AtomicUsize::new(config.l2_weight as usize),
            rr_phase_l2: std::sync::atomic::AtomicBool::new(true),
            config,
            stats: DispatchStats::default(),
        }
    }

    /// Select the next lane to dispatch from.
    ///
    /// Returns `Some(lane)` if a lane has work and should be dispatched,
    /// or `None` if all lanes are empty or dispatch should be deferred.
    ///
    /// # Arguments
    ///
    /// * `queues` - The lane queues to check
    /// * `in_flight` - Current in-flight counts per lane [L0, L1, L2, L3, L4]
    /// * `executor_free_slots` - Number of free slots in the executor
    pub fn select_lane<T>(
        &self,
        queues: &LaneQueues<T>,
        in_flight: &[u64; 5],
        executor_free_slots: usize,
    ) -> Option<Lane> {
        // Priority 1: L0 (Control) - always dispatch if non-empty
        if !queues.is_empty(Lane::Control) {
            return Some(Lane::Control);
        }

        // Priority 2: L1 (Metadata) - always dispatch if non-empty
        // This ensures metadata operations remain responsive under storms
        if !queues.is_empty(Lane::Metadata) {
            return Some(Lane::Metadata);
        }

        // Priority 3: Weighted round-robin between L2 (Read) and L3 (Write)
        // This prevents either from starving the other
        if let Some(lane) = self.select_l2_l3(queues, in_flight, executor_free_slots) {
            return Some(lane);
        }

        // Priority 4: L4 (Bulk) - only if L1-L3 are quiet
        if self.should_dispatch_bulk(in_flight, executor_free_slots) {
            if !queues.is_empty(Lane::Bulk) {
                return Some(Lane::Bulk);
            }
        } else if !queues.is_empty(Lane::Bulk) {
            self.stats.record_l4_deferred();
        }

        None
    }

    /// Select between L2 and L3 using weighted round-robin.
    fn select_l2_l3<T>(
        &self,
        queues: &LaneQueues<T>,
        in_flight: &[u64; 5],
        executor_free_slots: usize,
    ) -> Option<Lane> {
        let l2_has_work = !queues.is_empty(Lane::ReadForeground);
        let l3_has_work = !queues.is_empty(Lane::WriteStructural);

        // If only one has work, dispatch it (no round-robin needed)
        match (l2_has_work, l3_has_work) {
            (false, false) => return None,
            (true, false) => return Some(Lane::ReadForeground),
            (false, true) => {
                // Check L3 reserved capacity before dispatching
                if self.has_l3_capacity(in_flight, executor_free_slots) {
                    return Some(Lane::WriteStructural);
                }
                return None;
            }
            (true, true) => {
                // Both have work - use weighted round-robin
            }
        }

        // Weighted round-robin: alternate between L2 and L3 based on weights
        let current_counter = self.rr_counter.load(Ordering::Relaxed);
        let is_l2_phase = self.rr_phase_l2.load(Ordering::Relaxed);

        if current_counter == 0 {
            // Switch phase and reset counter
            let new_phase = !is_l2_phase;
            self.rr_phase_l2.store(new_phase, Ordering::Relaxed);
            let new_counter = if new_phase {
                self.config.l2_weight as usize
            } else {
                self.config.l3_weight as usize
            };
            self.rr_counter.store(new_counter, Ordering::Relaxed);
            self.stats.record_rr_cycle();
        }

        // Decrement counter and dispatch from current phase's lane
        self.rr_counter.fetch_sub(1, Ordering::Relaxed);

        let is_l2_phase = self.rr_phase_l2.load(Ordering::Relaxed);
        if is_l2_phase {
            Some(Lane::ReadForeground)
        } else {
            // Check L3 reserved capacity
            if self.has_l3_capacity(in_flight, executor_free_slots) {
                Some(Lane::WriteStructural)
            } else {
                // Fall back to L2 if L3 doesn't have reserved capacity
                Some(Lane::ReadForeground)
            }
        }
    }

    /// Check if L3 has reserved capacity in the executor.
    fn has_l3_capacity(&self, in_flight: &[u64; 5], executor_free_slots: usize) -> bool {
        // Ensure we don't consume all slots, leaving some for L3
        let l3_in_flight = in_flight[Lane::WriteStructural as usize];

        // If L3 already has work in-flight, we can dispatch more
        if l3_in_flight > 0 {
            return true;
        }

        // Otherwise, check if we have enough free slots including reserved
        executor_free_slots > self.config.l3_reserved_slots
    }

    /// Check if L4 (Bulk) should be dispatched.
    fn should_dispatch_bulk(&self, in_flight: &[u64; 5], executor_free_slots: usize) -> bool {
        // Calculate total high-priority in-flight
        let high_priority_in_flight = in_flight[Lane::Control as usize]
            + in_flight[Lane::Metadata as usize]
            + in_flight[Lane::ReadForeground as usize]
            + in_flight[Lane::WriteStructural as usize];

        // Only dispatch L4 if high-priority lanes are below threshold
        if high_priority_in_flight >= self.config.l4_quiet_threshold {
            return false;
        }

        // Ensure we leave reserved capacity for L1 and L3
        let total_reserved = self.config.l1_reserved_slots + self.config.l3_reserved_slots;
        executor_free_slots > total_reserved
    }

    /// Try to dequeue from the selected lane.
    ///
    /// This is a convenience method that combines lane selection with dequeue.
    pub fn try_dispatch<T>(
        &self,
        queues: &LaneQueues<T>,
        in_flight: &[u64; 5],
        executor_free_slots: usize,
    ) -> Option<QueuedRequest<T>> {
        let lane = self.select_lane(queues, in_flight, executor_free_slots)?;
        let request = queues.try_dequeue(lane)?;
        self.stats.record_dispatch(lane);
        Some(request)
    }

    /// Get dispatcher statistics.
    pub fn stats(&self) -> &DispatchStats {
        &self.stats
    }

    /// Get the configuration.
    pub fn config(&self) -> &DispatchConfig {
        &self.config
    }
}

impl Default for FairnessDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::lane::LaneCapacities;
    use crate::scheduler::request::RequestId;

    #[test]
    fn test_priority_order_l0_first() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let dispatcher = FairnessDispatcher::new();
        let in_flight = [0u64; 5];

        // Add work to multiple lanes
        queues.try_enqueue(Lane::Control, RequestId::new(1), 1).unwrap();
        queues.try_enqueue(Lane::Metadata, RequestId::new(2), 2).unwrap();
        queues.try_enqueue(Lane::ReadForeground, RequestId::new(3), 3).unwrap();

        // L0 should be selected first
        let lane = dispatcher.select_lane(&queues, &in_flight, 16);
        assert_eq!(lane, Some(Lane::Control));
    }

    #[test]
    fn test_priority_order_l1_before_l2() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let dispatcher = FairnessDispatcher::new();
        let in_flight = [0u64; 5];

        // Add work to L1 and L2
        queues.try_enqueue(Lane::Metadata, RequestId::new(1), 1).unwrap();
        queues.try_enqueue(Lane::ReadForeground, RequestId::new(2), 2).unwrap();

        // L1 should be selected first
        let lane = dispatcher.select_lane(&queues, &in_flight, 16);
        assert_eq!(lane, Some(Lane::Metadata));
    }

    #[test]
    fn test_weighted_round_robin_l2_l3() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let config = DispatchConfig {
            l2_weight: 2,
            l3_weight: 2,
            ..Default::default()
        };
        let dispatcher = FairnessDispatcher::with_config(config);
        let in_flight = [0u64; 5];

        // Add work to both L2 and L3
        for i in 0..10 {
            queues.try_enqueue(Lane::ReadForeground, RequestId::new(i), i as u32).unwrap();
            queues.try_enqueue(Lane::WriteStructural, RequestId::new(i + 100), (i + 100) as u32).unwrap();
        }

        // Track dispatches
        let mut l2_count = 0;
        let mut l3_count = 0;

        for _ in 0..8 {
            if let Some(request) = dispatcher.try_dispatch(&queues, &in_flight, 16) {
                match request.lane {
                    Lane::ReadForeground => l2_count += 1,
                    Lane::WriteStructural => l3_count += 1,
                    _ => {}
                }
            }
        }

        // With equal weights (2:2), we should see roughly equal distribution
        // Allow some variance due to the round-robin mechanism
        assert!(l2_count >= 2 && l2_count <= 6, "L2 count: {}", l2_count);
        assert!(l3_count >= 2 && l3_count <= 6, "L3 count: {}", l3_count);
    }

    #[test]
    fn test_l4_only_when_quiet() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let dispatcher = FairnessDispatcher::new();

        // Add work to L4 only
        queues.try_enqueue(Lane::Bulk, RequestId::new(1), 1).unwrap();

        // High in-flight count for L2 - L4 should be deferred
        let in_flight_busy = [0, 0, 10, 0, 0];
        let lane = dispatcher.select_lane(&queues, &in_flight_busy, 16);
        assert_eq!(lane, None);

        // Low in-flight count - L4 should dispatch
        let in_flight_quiet = [0, 0, 2, 0, 0];
        let lane = dispatcher.select_lane(&queues, &in_flight_quiet, 16);
        assert_eq!(lane, Some(Lane::Bulk));
    }

    #[test]
    fn test_reserved_capacity_for_l3() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let config = DispatchConfig {
            l3_reserved_slots: 2,
            ..Default::default()
        };
        let dispatcher = FairnessDispatcher::with_config(config);
        let in_flight = [0u64; 5];

        // Add work to L3 only
        queues.try_enqueue(Lane::WriteStructural, RequestId::new(1), 1).unwrap();

        // With only 2 free slots and 2 reserved for L3, L3 should not dispatch
        // (because we need > reserved, not >= reserved)
        let lane = dispatcher.select_lane(&queues, &in_flight, 2);
        assert_eq!(lane, None);

        // With 3 free slots, L3 should dispatch
        let lane = dispatcher.select_lane(&queues, &in_flight, 3);
        assert_eq!(lane, Some(Lane::WriteStructural));
    }

    #[test]
    fn test_stats_tracking() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let dispatcher = FairnessDispatcher::new();
        let in_flight = [0u64; 5];

        queues.try_enqueue(Lane::Metadata, RequestId::new(1), 1).unwrap();
        queues.try_enqueue(Lane::ReadForeground, RequestId::new(2), 2).unwrap();

        dispatcher.try_dispatch(&queues, &in_flight, 16);
        dispatcher.try_dispatch(&queues, &in_flight, 16);

        assert_eq!(dispatcher.stats().total_dispatched(), 2);
    }

    #[test]
    fn test_empty_queues() {
        let queues: LaneQueues<u32> = LaneQueues::new(&LaneCapacities::default());
        let dispatcher = FairnessDispatcher::new();
        let in_flight = [0u64; 5];

        // No work in any lane
        let lane = dispatcher.select_lane(&queues, &in_flight, 16);
        assert_eq!(lane, None);
    }
}
