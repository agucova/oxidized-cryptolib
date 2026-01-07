//! FUSE request types for scheduler-based async processing.
//!
//! These types capture the state needed to reply to a FUSE request
//! asynchronously. The `Reply*` types from `fuser` are `Send + Sync`,
//! so they can be safely moved to worker threads for delayed replies.

use bytes::Bytes;
use fuser::{FileAttr, ReplyAttr, ReplyCreate, ReplyData, ReplyEmpty, ReplyEntry, ReplyWrite};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use oxcrypt_core::vault::DirId;

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
    /// Byte offset that was read (for cache key construction).
    pub offset: u64,
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
            .field("offset", &self.offset)
            .field("result", &self.result.as_ref().map(Bytes::len))
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

// ============================================================================
// Structural Operations (unlink, rmdir, mkdir, create, rename, setattr, etc.)
// ============================================================================

/// Parameters for a setattr operation.
#[derive(Debug, Clone)]
pub struct SetattrParams {
    /// New mode (permissions) if set.
    pub mode: Option<u32>,
    /// New user ID if set.
    pub uid: Option<u32>,
    /// New group ID if set.
    pub gid: Option<u32>,
    /// New size if set (truncate).
    pub size: Option<u64>,
    /// New access time if set.
    pub atime: Option<fuser::TimeOrNow>,
    /// New modification time if set.
    pub mtime: Option<fuser::TimeOrNow>,
    /// New creation time if set (macOS).
    pub ctime: Option<std::time::SystemTime>,
    /// New flags if set (macOS).
    pub flags: Option<u32>,
}

/// A structural operation with its parameters.
///
/// Structural operations modify the filesystem structure (create, delete, rename)
/// and must be serialized per-file to prevent race conditions.
#[derive(Debug, Clone)]
pub enum StructuralOp {
    /// Delete a file.
    Unlink {
        /// Parent directory inode.
        parent: u64,
        /// Parent directory ID for vault operations.
        dir_id: DirId,
        /// Name of the file to delete.
        name: String,
    },
    /// Delete a directory.
    Rmdir {
        /// Parent directory inode.
        parent: u64,
        /// Parent directory ID for vault operations.
        dir_id: DirId,
        /// Name of the directory to delete.
        name: String,
    },
    /// Create a directory.
    Mkdir {
        /// Parent directory inode.
        parent: u64,
        /// Parent directory ID for vault operations.
        dir_id: DirId,
        /// Name of the new directory.
        name: String,
        /// Permissions mode.
        mode: u32,
    },
    /// Create a file.
    Create {
        /// Parent directory inode.
        parent: u64,
        /// Parent directory ID for vault operations.
        dir_id: DirId,
        /// Name of the new file.
        name: String,
        /// Permissions mode.
        mode: u32,
        /// Open flags.
        flags: i32,
    },
    /// Rename a file or directory.
    Rename {
        /// Source parent directory inode.
        parent: u64,
        /// Source parent directory ID.
        src_dir_id: DirId,
        /// Source name.
        name: String,
        /// Destination parent directory inode.
        newparent: u64,
        /// Destination parent directory ID.
        dst_dir_id: DirId,
        /// Destination name.
        newname: String,
        /// Rename flags (e.g., RENAME_NOREPLACE).
        flags: u32,
    },
    /// Set file attributes.
    Setattr {
        /// Target inode.
        ino: u64,
        /// File handle (if from open file).
        fh: Option<u64>,
        /// Attributes to set.
        params: SetattrParams,
    },
    /// Create a symbolic link.
    Symlink {
        /// Parent directory inode.
        parent: u64,
        /// Parent directory ID.
        dir_id: DirId,
        /// Link target path.
        link_target: String,
        /// Name of the symlink.
        name: String,
    },
    /// Create a hard link.
    Link {
        /// Source inode.
        ino: u64,
        /// New parent directory inode.
        newparent: u64,
        /// New parent directory ID.
        dir_id: DirId,
        /// New name.
        newname: String,
    },
}

impl StructuralOp {
    /// Get the primary inode affected by this operation.
    ///
    /// For operations that affect a parent directory (create, delete),
    /// this returns the parent inode. For operations that affect a file
    /// directly (setattr), this returns that inode.
    pub fn primary_inode(&self) -> u64 {
        match self {
            StructuralOp::Unlink { parent, .. }
            | StructuralOp::Rmdir { parent, .. }
            | StructuralOp::Mkdir { parent, .. }
            | StructuralOp::Create { parent, .. }
            | StructuralOp::Symlink { parent, .. } => *parent,
            StructuralOp::Rename { parent, .. } => *parent,
            StructuralOp::Setattr { ino, .. } | StructuralOp::Link { ino, .. } => *ino,
        }
    }

    /// Get all inodes affected by this operation (for rename).
    pub fn affected_inodes(&self) -> Vec<u64> {
        match self {
            StructuralOp::Rename {
                parent, newparent, ..
            } => {
                if parent == newparent {
                    vec![*parent]
                } else {
                    vec![*parent, *newparent]
                }
            }
            StructuralOp::Link { ino, newparent, .. } => vec![*ino, *newparent],
            _ => vec![self.primary_inode()],
        }
    }

    /// Get the operation name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            StructuralOp::Unlink { .. } => "unlink",
            StructuralOp::Rmdir { .. } => "rmdir",
            StructuralOp::Mkdir { .. } => "mkdir",
            StructuralOp::Create { .. } => "create",
            StructuralOp::Rename { .. } => "rename",
            StructuralOp::Setattr { .. } => "setattr",
            StructuralOp::Symlink { .. } => "symlink",
            StructuralOp::Link { .. } => "link",
        }
    }
}

/// Reply handle for structural operations.
///
/// Wraps the different FUSE reply types in a single enum.
pub enum StructuralReply {
    /// Reply for unlink, rmdir, rename.
    Empty(ReplyEmpty),
    /// Reply for mkdir, symlink, link.
    Entry(ReplyEntry),
    /// Reply for create (includes file handle).
    Create(ReplyCreate),
    /// Reply for setattr.
    Attr(ReplyAttr),
}

impl StructuralReply {
    /// Send an error reply.
    pub fn error(self, errno: i32) {
        match self {
            StructuralReply::Empty(r) => r.error(errno),
            StructuralReply::Entry(r) => r.error(errno),
            StructuralReply::Create(r) => r.error(errno),
            StructuralReply::Attr(r) => r.error(errno),
        }
    }
}

impl std::fmt::Debug for StructuralReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StructuralReply::Empty(_) => write!(f, "StructuralReply::Empty"),
            StructuralReply::Entry(_) => write!(f, "StructuralReply::Entry"),
            StructuralReply::Create(_) => write!(f, "StructuralReply::Create"),
            StructuralReply::Attr(_) => write!(f, "StructuralReply::Attr"),
        }
    }
}

/// A structural request waiting for async completion.
pub struct StructuralRequest {
    /// Unique request identifier.
    pub id: RequestId,
    /// The operation to perform.
    pub op: StructuralOp,
    /// Deadline for this request.
    pub deadline: Instant,
    /// Reply handle.
    pub reply: StructuralReply,
}

impl std::fmt::Debug for StructuralRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructuralRequest")
            .field("id", &self.id)
            .field("op", &self.op)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// Result of a completed structural operation.
#[derive(Debug)]
pub enum StructuralResult {
    /// Result for unlink, rmdir, rename (success or error).
    Empty {
        /// Request ID.
        id: RequestId,
        /// Success or error code.
        result: Result<(), i32>,
    },
    /// Result for mkdir, symlink, link.
    Entry {
        /// Request ID.
        id: RequestId,
        /// File attributes and generation, or error.
        result: Result<(FileAttr, u64), i32>,
    },
    /// Result for create.
    Create {
        /// Request ID.
        id: RequestId,
        /// File attributes, generation, and file handle, or error.
        result: Result<(FileAttr, u64, u64, u32), i32>,
    },
    /// Result for setattr.
    Attr {
        /// Request ID.
        id: RequestId,
        /// File attributes or error.
        result: Result<FileAttr, i32>,
    },
}

impl StructuralResult {
    /// Get the request ID.
    pub fn id(&self) -> RequestId {
        match self {
            StructuralResult::Empty { id, .. }
            | StructuralResult::Entry { id, .. }
            | StructuralResult::Create { id, .. }
            | StructuralResult::Attr { id, .. } => *id,
        }
    }

    /// Get the error code if this was an error.
    pub fn error(&self) -> Option<i32> {
        match self {
            StructuralResult::Empty { result, .. } => result.as_ref().err().copied(),
            StructuralResult::Entry { result, .. } => result.as_ref().err().copied(),
            StructuralResult::Create { result, .. } => result.as_ref().err().copied(),
            StructuralResult::Attr { result, .. } => result.as_ref().err().copied(),
        }
    }
}

/// A structural job waiting in a lane queue.
pub struct QueuedStructuralJob {
    /// The operation to perform.
    pub op: StructuralOp,
    /// Vault operations for executing the operation.
    pub ops: std::sync::Arc<oxcrypt_core::vault::VaultOperationsAsync>,
    /// Deadline for this request.
    pub deadline: Instant,
}

impl std::fmt::Debug for QueuedStructuralJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedStructuralJob")
            .field("op", &self.op.name())
            .field("primary_inode", &self.op.primary_inode())
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// A read job waiting in a lane queue.
///
/// This is the payload type for `LaneQueues<QueuedReadJob>`.
/// When dequeued by the fairness dispatcher, it's submitted to the executor.
pub struct QueuedReadJob {
    /// File handle ID.
    pub fh: u64,
    /// The reader to use.
    pub reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
    /// Byte offset to read from.
    pub offset: u64,
    /// Number of bytes to read.
    pub size: usize,
    /// Deadline for this request.
    pub deadline: Instant,
}

impl std::fmt::Debug for QueuedReadJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedReadJob")
            .field("fh", &self.fh)
            .field("offset", &self.offset)
            .field("size", &self.size)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// A copy_file_range job waiting in a lane queue.
///
/// This is the payload type for queued copy operations.
pub struct QueuedCopyRangeJob {
    /// Source file handle.
    pub fh_in: u64,
    /// Source reader.
    pub reader: Box<oxcrypt_core::fs::streaming::VaultFileReader>,
    /// Source offset.
    pub offset_in: u64,
    /// Destination file handle.
    pub fh_out: u64,
    /// Destination inode (for cache invalidation and barrier tracking).
    pub ino_out: u64,
    /// Destination offset.
    pub offset_out: u64,
    /// Number of bytes to copy.
    pub len: usize,
    /// Deadline for this request.
    pub deadline: Instant,
}

impl std::fmt::Debug for QueuedCopyRangeJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedCopyRangeJob")
            .field("fh_in", &self.fh_in)
            .field("offset_in", &self.offset_in)
            .field("fh_out", &self.fh_out)
            .field("offset_out", &self.offset_out)
            .field("len", &self.len)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// A queued job waiting in a lane queue (union type for dispatch).
pub enum QueuedJob {
    /// A read operation.
    Read(QueuedReadJob),
    /// A copy_file_range operation.
    CopyRange(QueuedCopyRangeJob),
    /// A structural operation (unlink, mkdir, rename, etc.).
    Structural(QueuedStructuralJob),
}

impl QueuedJob {
    /// Get the deadline for this job.
    pub fn deadline(&self) -> Instant {
        match self {
            QueuedJob::Read(job) => job.deadline,
            QueuedJob::CopyRange(job) => job.deadline,
            QueuedJob::Structural(job) => job.deadline,
        }
    }
}

impl std::fmt::Debug for QueuedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueuedJob::Read(r) => write!(f, "QueuedJob::Read({r:?})"),
            QueuedJob::CopyRange(r) => write!(f, "QueuedJob::CopyRange({r:?})"),
            QueuedJob::Structural(s) => write!(f, "QueuedJob::Structural({s:?})"),
        }
    }
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
    /// A structural request.
    Structural(StructuralRequest),
}

impl FuseRequest {
    /// Get the request ID.
    pub fn id(&self) -> RequestId {
        match self {
            FuseRequest::Read(r) => r.id,
            FuseRequest::CopyRange(r) => r.id,
            FuseRequest::Structural(r) => r.id,
        }
    }

    /// Get the deadline.
    pub fn deadline(&self) -> Instant {
        match self {
            FuseRequest::Read(r) => r.deadline,
            FuseRequest::CopyRange(r) => r.deadline,
            FuseRequest::Structural(r) => r.deadline,
        }
    }
}

impl std::fmt::Debug for FuseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuseRequest::Read(r) => write!(f, "FuseRequest::Read({r:?})"),
            FuseRequest::CopyRange(r) => write!(f, "FuseRequest::CopyRange({r:?})"),
            FuseRequest::Structural(r) => write!(f, "FuseRequest::Structural({r:?})"),
        }
    }
}

/// Enumeration of all async FUSE results.
pub enum FuseResult {
    /// Result of a read request.
    Read(ReadResult),
    /// Result of a copy_file_range request.
    CopyRange(CopyRangeResult),
    /// Result of a structural request.
    Structural(StructuralResult),
}

impl FuseResult {
    /// Get the request ID.
    pub fn id(&self) -> RequestId {
        match self {
            FuseResult::Read(r) => r.id,
            FuseResult::CopyRange(r) => r.id,
            FuseResult::Structural(r) => r.id(),
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
