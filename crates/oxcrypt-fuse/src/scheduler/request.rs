//! FUSE request types for scheduler-based async processing.
//!
//! These types capture the state needed to reply to a FUSE request
//! asynchronously. The `Reply*` types from `fuser` are `Send + Sync`,
//! so they can be safely moved to worker threads for delayed replies.

use bytes::Bytes;
use fuser::{ReplyData, ReplyWrite};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Unique identifier for a request in the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

impl RequestId {
    /// Create a new request ID from a raw value.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn raw(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "req-{}", self.0)
    }
}

/// Atomic request ID generator.
#[derive(Debug, Default)]
pub struct RequestIdGenerator {
    next: AtomicU64,
}

impl RequestIdGenerator {
    /// Create a new generator starting at 1.
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Generate the next request ID.
    pub fn next(&self) -> RequestId {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        RequestId(id)
    }
}

/// State tracking for request completion.
///
/// Used to ensure exactly-once reply semantics when both
/// completion and timeout may race.
#[derive(Debug)]
pub struct RequestState {
    /// Whether a reply has been sent.
    replied: AtomicBool,
    /// Whether the request was cancelled (e.g., by timeout).
    cancelled: AtomicBool,
}

impl RequestState {
    /// Create a new request state.
    pub fn new() -> Self {
        Self {
            replied: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Try to claim the right to reply.
    ///
    /// Returns `true` if this call successfully claimed the reply,
    /// `false` if a reply was already sent.
    ///
    /// This is atomic and ensures exactly-once semantics.
    pub fn claim_reply(&self) -> bool {
        // swap returns the previous value; if it was false, we got it
        !self.replied.swap(true, Ordering::AcqRel)
    }

    /// Check if a reply has been sent.
    pub fn has_replied(&self) -> bool {
        self.replied.load(Ordering::Acquire)
    }

    /// Mark the request as cancelled.
    pub fn mark_cancelled(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Check if the request was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Default for RequestState {
    fn default() -> Self {
        Self::new()
    }
}

/// A read request waiting for async completion.
pub struct ReadRequest {
    /// Unique request identifier.
    pub id: RequestId,
    /// File handle from FUSE.
    pub fh: u64,
    /// Byte offset to read from.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: u32,
    /// Deadline for this request.
    pub deadline: Instant,
    /// Reply handle - moved to worker for async reply.
    pub reply: ReplyData,
}

impl std::fmt::Debug for ReadRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadRequest")
            .field("id", &self.id)
            .field("fh", &self.fh)
            .field("offset", &self.offset)
            .field("size", &self.size)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Result of a completed read operation.
pub struct ReadResult {
    /// The request ID this result is for.
    pub id: RequestId,
    /// File handle ID for reader restoration.
    pub fh: u64,
    /// The read data, or error code.
    pub result: Result<Bytes, i32>,
    /// The reader to restore to the handle table.
    pub reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
}

impl std::fmt::Debug for ReadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadResult")
            .field("id", &self.id)
            .field("fh", &self.fh)
            .field("result", &self.result.as_ref().map(|b| b.len()).map_err(|e| *e))
            .finish_non_exhaustive()
    }
}

/// A copy_file_range request waiting for async completion.
pub struct CopyRangeRequest {
    /// Unique request identifier.
    pub id: RequestId,
    /// Source file handle.
    pub fh_in: u64,
    /// Source offset.
    pub offset_in: u64,
    /// Destination file handle.
    pub fh_out: u64,
    /// Destination offset.
    pub offset_out: u64,
    /// Number of bytes to copy.
    pub len: u64,
    /// Deadline for this request.
    pub deadline: Instant,
    /// Reply handle.
    pub reply: ReplyWrite,
}

impl std::fmt::Debug for CopyRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyRangeRequest")
            .field("id", &self.id)
            .field("fh_in", &self.fh_in)
            .field("offset_in", &self.offset_in)
            .field("fh_out", &self.fh_out)
            .field("offset_out", &self.offset_out)
            .field("len", &self.len)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Result of a completed copy operation.
#[derive(Debug)]
pub struct CopyRangeResult {
    /// The request ID this result is for.
    pub id: RequestId,
    /// Bytes copied, or error code.
    pub result: Result<u64, i32>,
}

/// Enumeration of all async FUSE requests.
///
/// This allows the scheduler to handle different request types
/// through a unified dispatch mechanism.
pub enum FuseRequest {
    /// A read request.
    Read(ReadRequest),
    /// A copy_file_range request.
    CopyRange(CopyRangeRequest),
}

impl FuseRequest {
    /// Get the request ID.
    pub fn id(&self) -> RequestId {
        match self {
            FuseRequest::Read(r) => r.id,
            FuseRequest::CopyRange(r) => r.id,
        }
    }

    /// Get the deadline.
    pub fn deadline(&self) -> Instant {
        match self {
            FuseRequest::Read(r) => r.deadline,
            FuseRequest::CopyRange(r) => r.deadline,
        }
    }
}

impl std::fmt::Debug for FuseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuseRequest::Read(r) => write!(f, "FuseRequest::Read({:?})", r),
            FuseRequest::CopyRange(r) => write!(f, "FuseRequest::CopyRange({:?})", r),
        }
    }
}

/// Enumeration of all async FUSE results.
pub enum FuseResult {
    /// Result of a read request.
    Read(ReadResult),
    /// Result of a copy_file_range request.
    CopyRange(CopyRangeResult),
}

impl FuseResult {
    /// Get the request ID.
    pub fn id(&self) -> RequestId {
        match self {
            FuseResult::Read(r) => r.id,
            FuseResult::CopyRange(r) => r.id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_generator() {
        let id_gen = RequestIdGenerator::new();
        let id1 = id_gen.next();
        let id2 = id_gen.next();
        let id3 = id_gen.next();

        assert_eq!(id1.raw(), 1);
        assert_eq!(id2.raw(), 2);
        assert_eq!(id3.raw(), 3);
    }

    #[test]
    fn test_request_state_claim_reply() {
        let state = RequestState::new();

        // First claim succeeds
        assert!(state.claim_reply());
        assert!(state.has_replied());

        // Second claim fails
        assert!(!state.claim_reply());
    }

    #[test]
    fn test_request_state_cancellation() {
        let state = RequestState::new();

        assert!(!state.is_cancelled());
        state.mark_cancelled();
        assert!(state.is_cancelled());
    }

    #[test]
    fn test_concurrent_claim_reply() {
        use std::sync::Arc;
        use std::thread;

        let state = Arc::new(RequestState::new());
        let mut handles = vec![];

        // Spawn 10 threads all trying to claim
        for _ in 0..10 {
            let state = Arc::clone(&state);
            handles.push(thread::spawn(move || state.claim_reply()));
        }

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Exactly one should succeed
        let success_count = results.iter().filter(|&&r| r).count();
        assert_eq!(success_count, 1);
    }
}
