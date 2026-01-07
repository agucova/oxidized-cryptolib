//! Lane-based operation classification for FUSE scheduler.
//!
//! Operations are classified into lanes based on their characteristics:
//! - **L0 Control**: Internal scheduler bookkeeping, shutdown coordination
//! - **L1 Metadata**: Foreground metadata ops (lookup, getattr, readdir, etc.)
//! - **L2 Read Foreground**: Small/interactive reads
//! - **L3 Write/Structural**: Writes, creates, deletes, renames
//! - **L4 Bulk**: Large sequential reads, read-ahead, background work
//!
//! This classification enables:
//! - Bounded admission per lane (fail-fast when queue full)
//! - Fairness policies (metadata always progresses, writes not starved by reads)
//! - Reserved executor capacity for critical lanes

use std::time::Duration;

/// Operation lane for scheduling and admission control.
///
/// Lanes provide categorical priority rather than a single global queue.
/// The scheduler dispatches based on lane, ensuring fairness and responsiveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Lane {
    /// L0: Internal control and lifecycle operations.
    ///
    /// Used for scheduler bookkeeping, shutdown coordination.
    /// Always processed with highest priority.
    Control = 0,

    /// L1: Foreground metadata operations.
    ///
    /// Includes: lookup, getattr, access, statfs, readlink, readdir, readdirplus.
    /// Must remain responsive even under I/O storms.
    Metadata = 1,

    /// L2: Foreground read operations.
    ///
    /// Small/interactive reads that need low latency.
    /// Classified based on read size (small reads go here).
    ReadForeground = 2,

    /// L3: Write and structural operations.
    ///
    /// Includes: create, mkdir, symlink, unlink, rmdir, rename,
    /// setattr (truncate), fallocate, copy_file_range, write (if non-trivial).
    /// Must not be starved by reads.
    WriteStructural = 3,

    /// L4: Bulk/background operations.
    ///
    /// Large sequential reads, read-ahead, prefetch, background revalidation.
    /// Lower priority than foreground operations.
    Bulk = 4,
}

impl Lane {
    /// Number of lanes in the system.
    pub const COUNT: usize = 5;

    /// Get lane index (0-4).
    pub fn index(self) -> usize {
        self as usize
    }

    /// Get lane from index.
    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Lane::Control),
            1 => Some(Lane::Metadata),
            2 => Some(Lane::ReadForeground),
            3 => Some(Lane::WriteStructural),
            4 => Some(Lane::Bulk),
            _ => None,
        }
    }

    /// Get display name for the lane.
    pub fn name(self) -> &'static str {
        match self {
            Lane::Control => "L0-Control",
            Lane::Metadata => "L1-Metadata",
            Lane::ReadForeground => "L2-ReadFg",
            Lane::WriteStructural => "L3-WriteFg",
            Lane::Bulk => "L4-Bulk",
        }
    }
}

/// Default queue capacities per lane.
///
/// These are conservative defaults from the spec (section 13).
#[derive(Debug, Clone)]
pub struct LaneCapacities {
    /// L0 Control queue capacity (internal, small).
    pub control: usize,
    /// L1 Metadata queue capacity.
    pub metadata: usize,
    /// L2 Read foreground queue capacity.
    pub read_foreground: usize,
    /// L3 Write/structural queue capacity.
    pub write_structural: usize,
    /// L4 Bulk queue capacity.
    pub bulk: usize,
}

impl Default for LaneCapacities {
    fn default() -> Self {
        Self {
            control: 256,        // Internal ops, small queue
            metadata: 1024,      // L1: 1024
            read_foreground: 2048, // L2: 2048
            write_structural: 1024, // L3: 1024
            bulk: 512,           // L4: 512
        }
    }
}

impl LaneCapacities {
    /// Get capacity for a specific lane.
    pub fn get(&self, lane: Lane) -> usize {
        match lane {
            Lane::Control => self.control,
            Lane::Metadata => self.metadata,
            Lane::ReadForeground => self.read_foreground,
            Lane::WriteStructural => self.write_structural,
            Lane::Bulk => self.bulk,
        }
    }
}

/// Default deadlines per lane.
///
/// Requests must be replied to by their deadline (success or error).
/// These are tuned below mount-death thresholds.
#[derive(Debug, Clone)]
pub struct LaneDeadlines {
    /// L0 Control deadline.
    pub control: Duration,
    /// L1 Metadata deadline (short for responsiveness).
    pub metadata: Duration,
    /// L2 Read foreground deadline.
    pub read_foreground: Duration,
    /// L3 Write/structural deadline.
    pub write_structural: Duration,
    /// L4 Bulk deadline (can be longer).
    pub bulk: Duration,
}

impl Default for LaneDeadlines {
    fn default() -> Self {
        Self {
            control: Duration::from_secs(5),       // Internal ops
            metadata: Duration::from_secs(2),      // L1: 2s (must be responsive)
            read_foreground: Duration::from_secs(10), // L2: 10s
            write_structural: Duration::from_secs(10), // L3: 10s
            bulk: Duration::from_secs(30),         // L4: longer for large ops
        }
    }
}

impl LaneDeadlines {
    /// Get deadline for a specific lane.
    pub fn get(&self, lane: Lane) -> Duration {
        match lane {
            Lane::Control => self.control,
            Lane::Metadata => self.metadata,
            Lane::ReadForeground => self.read_foreground,
            Lane::WriteStructural => self.write_structural,
            Lane::Bulk => self.bulk,
        }
    }
}

/// Threshold for classifying reads as bulk vs foreground.
///
/// Reads larger than this are classified as L4 (Bulk).
/// Default: 256 KiB (interactive reads are typically smaller).
pub const BULK_READ_THRESHOLD: usize = 256 * 1024;

/// Classify a read operation by size.
///
/// - Small reads (≤ threshold): L2 ReadForeground (interactive)
/// - Large reads (> threshold): L4 Bulk (sequential/background)
pub fn classify_read(size: usize) -> Lane {
    if size > BULK_READ_THRESHOLD {
        Lane::Bulk
    } else {
        Lane::ReadForeground
    }
}

/// Classify a metadata operation.
///
/// All metadata operations go to L1 Metadata lane.
/// Includes: lookup, getattr, access, statfs, readlink, readdir, readdirplus.
pub fn classify_metadata() -> Lane {
    Lane::Metadata
}

/// Classify a structural/write operation.
///
/// All structural operations go to L3 WriteStructural lane.
/// Includes: create, mkdir, symlink, unlink, rmdir, rename,
/// setattr, fallocate, copy_file_range, write.
pub fn classify_structural() -> Lane {
    Lane::WriteStructural
}

/// Reserved executor slots per lane.
///
/// Ensures critical lanes always have executor capacity available.
#[derive(Debug, Clone)]
pub struct LaneReservations {
    /// Minimum executor slots reserved for L1 Metadata.
    pub metadata_min: usize,
    /// Minimum executor slots reserved for L3 Write/Structural.
    pub write_structural_min: usize,
}

impl Default for LaneReservations {
    fn default() -> Self {
        Self {
            metadata_min: 1,        // ≥1 slot for metadata
            write_structural_min: 2, // ≥1-2 slots for writes/structural
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lane_index_roundtrip() {
        for i in 0..Lane::COUNT {
            let lane = Lane::from_index(i).unwrap();
            assert_eq!(lane.index(), i);
        }
    }

    #[test]
    fn test_lane_from_invalid_index() {
        assert!(Lane::from_index(5).is_none());
        assert!(Lane::from_index(100).is_none());
    }

    #[test]
    fn test_classify_read_small() {
        // Small reads go to L2
        assert_eq!(classify_read(1024), Lane::ReadForeground);
        assert_eq!(classify_read(64 * 1024), Lane::ReadForeground);
        assert_eq!(classify_read(BULK_READ_THRESHOLD), Lane::ReadForeground);
    }

    #[test]
    fn test_classify_read_large() {
        // Large reads go to L4
        assert_eq!(classify_read(BULK_READ_THRESHOLD + 1), Lane::Bulk);
        assert_eq!(classify_read(1024 * 1024), Lane::Bulk);
        assert_eq!(classify_read(10 * 1024 * 1024), Lane::Bulk);
    }

}
