//! Inode management for the FUSE filesystem.
//!
//! This module provides the mapping between FUSE inodes and vault paths,
//! enabling efficient lookup and management of filesystem entries.
//!
//! The implementation uses [`PathTable`] from `oxcrypt-mount` for the
//! core path-to-ID mapping, with FUSE-specific `nlookup` tracking added on top.

use dashmap::mapref::one::{Ref, RefMut};
use oxcrypt_core::vault::path::{DirId, VaultPath};
use oxcrypt_mount::path_mapper::{EntryKind, PathTable};
use std::sync::atomic::{AtomicU64, Ordering};

/// The root inode number (FUSE convention).
pub const ROOT_INODE: u64 = 1;

/// Represents the kind of inode entry.
///
/// This is a re-export of [`EntryKind`] from `oxcrypt-mount` for
/// backwards compatibility with existing FUSE code.
pub type InodeKind = EntryKind;

/// An entry in the inode table.
///
/// Contains the path, entry kind, and FUSE-specific `nlookup` counter
/// for reference counting.
#[derive(Debug)]
pub struct InodeEntry {
    /// The virtual path within the vault.
    pub path: VaultPath,
    /// The kind of entry (directory, file, symlink).
    pub kind: InodeKind,
    /// Lookup count for proper `forget()` handling.
    /// FUSE calls forget() when the kernel drops references.
    nlookup: AtomicU64,
}

impl InodeEntry {
    /// Creates a new inode entry with nlookup = 1.
    pub fn new(path: VaultPath, kind: InodeKind) -> Self {
        Self {
            path,
            kind,
            nlookup: AtomicU64::new(1), // Initial lookup count is 1
        }
    }

    /// Creates a new inode entry with nlookup = 0.
    /// Used for entries returned from `readdir()` which per FUSE spec
    /// should NOT increment the lookup count.
    pub fn new_no_lookup(path: VaultPath, kind: InodeKind) -> Self {
        Self {
            path,
            kind,
            nlookup: AtomicU64::new(0), // No lookup count for readdir entries
        }
    }

    /// Increments the lookup count and returns the new value.
    ///
    /// Uses `Relaxed` ordering since this is a simple counter with no
    /// synchronization requirements - we only care that the increment is atomic.
    pub fn inc_nlookup(&self) -> u64 {
        self.nlookup.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrements the lookup count by the given amount and returns the new value.
    /// Returns `None` if the count would go negative (shouldn't happen in normal operation).
    ///
    /// Uses `AcqRel` ordering to synchronize with the eviction check that follows.
    /// The `Release` ensures our decrement is visible before eviction,
    /// and `Acquire` ensures we see all prior increments.
    pub fn dec_nlookup(&self, count: u64) -> Option<u64> {
        let old = self.nlookup.fetch_sub(count, Ordering::AcqRel);
        if old < count {
            // This shouldn't happen - restore and return None
            self.nlookup.fetch_add(count, Ordering::Relaxed);
            None
        } else {
            Some(old - count)
        }
    }

    /// Returns the current lookup count.
    ///
    /// Uses `Relaxed` ordering since this is a read-only operation
    /// that doesn't synchronize with other operations.
    pub fn nlookup(&self) -> u64 {
        self.nlookup.load(Ordering::Relaxed)
    }

    /// Returns the parent directory ID if this is a file or symlink.
    #[inline]
    pub fn parent_dir_id(&self) -> Option<&DirId> {
        self.kind.parent_dir_id()
    }

    /// Returns the filename if this is a file or symlink.
    #[inline]
    pub fn filename(&self) -> Option<&str> {
        self.kind.filename()
    }

    /// Returns the directory ID if this is a directory or root.
    /// For root, returns a cloned root DirId.
    #[inline]
    pub fn dir_id(&self) -> Option<DirId> {
        self.kind.dir_id()
    }
}

/// Thread-safe table mapping between inodes and vault paths.
///
/// This table maintains a bidirectional mapping using [`PathTable`] from
/// `oxcrypt-mount`, with FUSE-specific `nlookup` tracking for
/// proper reference counting.
///
/// The table uses `DashMap` for lock-free concurrent access.
pub struct InodeTable {
    /// The underlying path table.
    inner: PathTable<u64, InodeEntry>,
}

impl InodeTable {
    /// Creates a new inode table with the root directory pre-allocated.
    pub fn new() -> Self {
        Self {
            inner: PathTable::with_root(
                ROOT_INODE,
                2, // First non-root inode
                InodeEntry::new(VaultPath::root(), InodeKind::Root),
            ),
        }
    }

    /// Allocates a new inode for the given path and kind.
    /// If the path already has an inode, increments its lookup count and returns the existing inode.
    pub fn get_or_insert(&self, path: &VaultPath, kind: &InodeKind) -> u64 {
        // Check if already exists
        if let Some(inode) = self.inner.get_id(path) {
            // Increment lookup count
            if let Some(entry) = self.inner.get(inode) {
                entry.inc_nlookup();
            }
            return inode;
        }

        // Allocate new inode
        let path_clone = path.clone();
        let kind_clone = kind.clone();
        self.inner
            .get_or_insert_with(path, || InodeEntry::new(path_clone, kind_clone))
    }

    /// Allocates a new inode for the given path and kind WITHOUT incrementing nlookup.
    ///
    /// Per FUSE specification, returning entries from `readdir()` should NOT affect
    /// the lookup count. Only `lookup()`, `create()`, `mkdir()`, `symlink()`, `link()`,
    /// and `readdirplus()` should increment nlookup.
    ///
    /// If the path already has an inode, returns the existing inode without incrementing.
    /// If the path is new, creates an inode entry with nlookup = 0.
    pub fn get_or_insert_no_lookup_inc(&self, path: &VaultPath, kind: &InodeKind) -> u64 {
        // Check if already exists - return without incrementing
        if let Some(inode) = self.inner.get_id(path) {
            return inode;
        }

        // Allocate new inode with nlookup = 0
        let path_clone = path.clone();
        let kind_clone = kind.clone();
        self.inner
            .get_or_insert_with(path, || InodeEntry::new_no_lookup(path_clone, kind_clone))
    }

    /// Looks up an entry by inode number.
    pub fn get(&self, inode: u64) -> Option<Ref<'_, u64, InodeEntry>> {
        self.inner.get(inode)
    }

    /// Looks up an entry by inode number for mutation.
    pub fn get_mut(&self, inode: u64) -> Option<RefMut<'_, u64, InodeEntry>> {
        self.inner.get_mut(inode)
    }

    /// Updates the kind of an existing inode entry.
    /// Returns true if the inode was found and updated.
    pub fn update_kind(&self, inode: u64, kind: InodeKind) -> bool {
        if let Some(mut entry) = self.inner.get_mut(inode) {
            entry.kind = kind;
            true
        } else {
            false
        }
    }

    /// Looks up an inode by vault path.
    pub fn get_inode(&self, path: &VaultPath) -> Option<u64> {
        self.inner.get_id(path)
    }

    /// Decrements the lookup count for an inode.
    /// If the count reaches zero, the inode is eligible for eviction.
    /// Returns `true` if the inode was evicted.
    pub fn forget(&self, inode: u64, nlookup: u64) -> bool {
        // Don't evict root
        if inode == ROOT_INODE {
            return false;
        }

        if let Some(entry) = self.inner.get(inode)
            && let Some(remaining) = entry.dec_nlookup(nlookup)
                && remaining == 0 {
                    // Safe to evict - drop the ref first
                    drop(entry);
                    return self.evict(inode);
                }
        false
    }

    /// Evicts an inode from the table.
    /// This should only be called when nlookup reaches 0.
    fn evict(&self, inode: u64) -> bool {
        self.inner.remove_by_id(inode).is_some()
    }

    /// Invalidates an inode by path (used after delete operations).
    ///
    /// Removes the path-to-ID mapping but does NOT evict the inode entry.
    /// The kernel will call forget() when it's done with the inode, which is
    /// the only reliable signal for safe eviction per the FUSE protocol.
    ///
    /// # FUSE Protocol Semantics
    ///
    /// Even when nlookup=0, the kernel may still have the inode cached in its
    /// dcache (from readdir entries). The kernel can pass these cached inode
    /// numbers to subsequent FUSE operations. Therefore, we must NOT evict
    /// inodes until the kernel explicitly signals via forget().
    pub fn invalidate_path(&self, path: &VaultPath) {
        self.inner.invalidate_path(path);
    }

    /// Updates the path for an inode (used after rename operations).
    pub fn update_path(&self, inode: u64, old_path: &VaultPath, new_path: VaultPath) {
        self.inner
            .update_path(inode, old_path, new_path, |entry, path| {
                entry.path = path;
            });
    }

    /// Atomically swaps the paths of two inodes (used for RENAME_EXCHANGE).
    ///
    /// After this operation:
    /// - `inode_a` will have `path_b` as its path
    /// - `inode_b` will have `path_a` as its path
    /// - Path-to-inode mappings are updated accordingly
    ///
    /// # Arguments
    ///
    /// * `inode_a` - First inode
    /// * `inode_b` - Second inode
    /// * `path_a` - Original path of inode_a (will become path of inode_b)
    /// * `path_b` - Original path of inode_b (will become path of inode_a)
    pub fn swap_paths(
        &self,
        inode_a: u64,
        inode_b: u64,
        path_a: &VaultPath,
        path_b: &VaultPath,
    ) {
        // Update path-to-id mappings: path_a now points to inode_b, path_b now points to inode_a
        self.inner.set_path_mapping(path_a.clone(), inode_b);
        self.inner.set_path_mapping(path_b.clone(), inode_a);

        // Update the entries' internal paths
        if let Some(mut entry_a) = self.inner.get_mut(inode_a) {
            entry_a.path = path_b.clone();
        }
        if let Some(mut entry_b) = self.inner.get_mut(inode_b) {
            entry_b.path = path_a.clone();
        }
    }

    /// Returns the number of inodes currently in the table.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the table only contains the root inode.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_inode_exists() {
        let table = InodeTable::new();
        assert!(table.get(ROOT_INODE).is_some());
        let entry = table.get(ROOT_INODE).unwrap();
        assert!(matches!(entry.kind, InodeKind::Root));
    }

    #[test]
    fn test_allocate_inode() {
        let table = InodeTable::new();
        let path = VaultPath::new("documents");
        let dir_id = DirId::from_raw("test-uuid");

        let inode = table.get_or_insert(&path.clone(), &InodeKind::Directory { dir_id });
        assert!(inode > ROOT_INODE);

        // Second call should return same inode
        let inode2 = table.get_or_insert(
            &path.clone(),
            &InodeKind::Directory {
                dir_id: DirId::from_raw("different"),
            },
        );
        assert_eq!(inode, inode2);

        // Lookup count should be 2 now
        let entry = table.get(inode).unwrap();
        assert_eq!(entry.nlookup(), 2);
    }

    #[test]
    fn test_forget_evicts() {
        let table = InodeTable::new();
        let path = VaultPath::new("temp");

        let inode = table.get_or_insert(
            &path.clone(),
            &InodeKind::File {
                dir_id: DirId::root(),
                name: "temp".to_string(),
            },
        );

        // Initial nlookup is 1
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Forget should evict
        assert!(table.forget(inode, 1));

        // Inode should be gone
        assert!(table.get(inode).is_none());
        assert!(table.get_inode(&path).is_none());
    }

    #[test]
    fn test_forget_root_never_evicts() {
        let table = InodeTable::new();
        assert!(!table.forget(ROOT_INODE, 1));
        assert!(table.get(ROOT_INODE).is_some());
    }

    #[test]
    fn test_update_path() {
        let table = InodeTable::new();
        let old_path = VaultPath::new("old_name");
        let new_path = VaultPath::new("new_name");

        let inode = table.get_or_insert(&old_path.clone(), &InodeKind::File {
                dir_id: DirId::root(),
                name: "old_name".to_string(),
            },
        );

        // Update the path
        table.update_path(inode, &old_path, new_path.clone());

        // Old path should not be found
        assert!(table.get_inode(&old_path).is_none());

        // New path should point to the same inode
        assert_eq!(table.get_inode(&new_path), Some(inode));

        // Entry should have new path
        let entry = table.get(inode).unwrap();
        assert_eq!(entry.path, new_path);
    }

    #[test]
    fn test_invalidate_path_with_nlookup() {
        let table = InodeTable::new();
        let path = VaultPath::new("to_delete");

        // get_or_insert sets nlookup=1
        let inode = table.get_or_insert(&path.clone(), &InodeKind::File {
                dir_id: DirId::root(),
                name: "to_delete".to_string(),
            },
        );

        // Path should be mapped
        assert_eq!(table.get_inode(&path), Some(inode));
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Invalidate - inode stays because nlookup > 0
        table.invalidate_path(&path);

        // Path should not be mapped, but inode entry still exists (kernel holds reference)
        assert!(table.get_inode(&path).is_none());
        assert!(table.get(inode).is_some());
    }

    #[test]
    fn test_invalidate_path_keeps_inode_nlookup_zero() {
        let table = InodeTable::new();
        let path = VaultPath::new("readdir_entry");

        // get_or_insert_no_lookup_inc sets nlookup=0 (like readdir does)
        let inode = table.get_or_insert_no_lookup_inc(
            &path.clone(),
            &InodeKind::File {
                dir_id: DirId::root(),
                name: "readdir_entry".to_string(),
            },
        );

        // Path should be mapped
        assert_eq!(table.get_inode(&path), Some(inode));
        assert_eq!(table.get(inode).unwrap().nlookup(), 0);

        // Invalidate - path mapping removed but inode stays
        table.invalidate_path(&path);

        // Path mapping should be gone
        assert!(table.get_inode(&path).is_none());

        // BUT inode entry should STILL EXIST
        // Only forget() should evict it
        assert!(table.get(inode).is_some());
        assert_eq!(table.get(inode).unwrap().nlookup(), 0);
    }

    #[test]
    fn test_concurrent_allocation() {
        use std::sync::Arc;
        use std::thread;

        let table = Arc::new(InodeTable::new());
        let mut handles = vec![];

        // Spawn multiple threads allocating inodes
        for i in 0..10 {
            let table = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                let path = VaultPath::new(format!("file_{i}"));
                table.get_or_insert(&path, &InodeKind::File {
                        dir_id: DirId::root(),
                        name: format!("file_{i}"),
                    },
                )
            }));
        }

        let inodes: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All inodes should be unique (not counting root)
        let mut sorted = inodes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), inodes.len());

        // Table should have 11 entries (root + 10 files)
        assert_eq!(table.len(), 11);
    }

    #[test]
    fn test_nlookup_increment_decrement() {
        let table = InodeTable::new();
        let path = VaultPath::new("nlookup_test");

        // First insert: nlookup = 1
        let inode = table.get_or_insert(&path.clone(), &InodeKind::File {
                dir_id: DirId::root(),
                name: "nlookup_test".to_string(),
            },
        );
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Second lookup: nlookup = 2
        table.get_or_insert(&path.clone(), &InodeKind::File {
                dir_id: DirId::root(),
                name: "ignored".to_string(),
            },
        );
        assert_eq!(table.get(inode).unwrap().nlookup(), 2);

        // Forget 1: nlookup = 1
        assert!(!table.forget(inode, 1)); // Not evicted yet
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Forget 1: nlookup = 0, evicted
        assert!(table.forget(inode, 1)); // Evicted
        assert!(table.get(inode).is_none());
    }

    #[test]
    fn test_get_or_insert_no_lookup_inc() {
        let table = InodeTable::new();
        let path = VaultPath::new("readdir_entry");

        // First insert with no_lookup_inc: nlookup = 0
        let inode = table.get_or_insert_no_lookup_inc(
            &path.clone(),
            &InodeKind::File {
                dir_id: DirId::root(),
                name: "readdir_entry".to_string(),
            },
        );
        assert_eq!(table.get(inode).unwrap().nlookup(), 0);

        // Second call: still nlookup = 0 (no increment)
        let inode2 = table.get_or_insert_no_lookup_inc(
            &path.clone(),
            &InodeKind::File {
                dir_id: DirId::root(),
                name: "ignored".to_string(),
            },
        );
        assert_eq!(inode, inode2);
        assert_eq!(table.get(inode).unwrap().nlookup(), 0);

        // Now use regular get_or_insert: nlookup = 1
        table.get_or_insert(
            &path.clone(),
            &InodeKind::File {
                dir_id: DirId::root(),
                name: "ignored".to_string(),
            },
        );
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Forget with nlookup=1 should evict
        assert!(table.forget(inode, 1));
        assert!(table.get(inode).is_none());
    }

    #[test]
    fn test_inode_entry_methods() {
        let entry = InodeEntry::new(
            VaultPath::new("test/file.txt"),
            InodeKind::File {
                dir_id: DirId::from_raw("parent-id"),
                name: "file.txt".to_string(),
            },
        );

        assert_eq!(entry.filename(), Some("file.txt"));
        assert_eq!(entry.parent_dir_id().map(DirId::as_str), Some("parent-id"));
        assert!(entry.dir_id().is_none());

        let dir_entry = InodeEntry::new(
            VaultPath::new("test/subdir"),
            InodeKind::Directory {
                dir_id: DirId::from_raw("subdir-id"),
            },
        );

        assert!(dir_entry.filename().is_none());
        assert!(dir_entry.parent_dir_id().is_none());
        assert_eq!(
            dir_entry.dir_id().map(|d| d.as_str().to_string()),
            Some("subdir-id".to_string())
        );
    }

    #[test]
    fn test_symlink_handling() {
        let table = InodeTable::new();

        let path = VaultPath::new("link_to_file");
        let kind = InodeKind::Symlink {
            dir_id: DirId::root(),
            name: "link_to_file".to_string(),
        };
        let inode = table.get_or_insert(&path, &kind);

        let entry = table.get(inode).unwrap();
        assert!(matches!(entry.kind, InodeKind::Symlink { .. }));
        assert_eq!(entry.filename(), Some("link_to_file"));
    }

    #[test]
    fn test_very_long_path() {
        let table = InodeTable::new();

        // Create a very deep path (100 levels)
        let path_parts: Vec<String> = (0..100).map(|i| format!("dir_{i}")).collect();
        let long_path = VaultPath::new(path_parts.join("/"));

        let kind = InodeKind::File {
            dir_id: DirId::from_raw("deep-dir"),
            name: "file.txt".to_string(),
        };
        let inode = table.get_or_insert(&long_path.clone(), &kind);

        assert!(table.get(inode).is_some());
        assert_eq!(table.get_inode(&long_path), Some(inode));
    }

    #[test]
    fn test_special_characters_in_path() {
        let table = InodeTable::new();

        let special_names = [
            "file with spaces.txt",
            "file\twith\ttabs.txt",
            "émojis_🎉.txt",
            "中文文件.txt",
            "file-with-dashes.txt",
            "file.multiple.dots.txt",
        ];

        for name in special_names {
            let path = VaultPath::new(name);
            let kind = InodeKind::File {
                dir_id: DirId::root(),
                name: name.to_string(),
            };
            let inode = table.get_or_insert(&path.clone(), &kind);

            let entry = table.get(inode).unwrap();
            assert_eq!(entry.filename(), Some(name));
        }
    }

    #[test]
    fn test_concurrent_lookup_and_forget() {
        use std::sync::Arc;
        use std::thread;

        let table = Arc::new(InodeTable::new());

        // Pre-populate with high nlookup count to survive concurrent forgets
        let inodes: Vec<u64> = (0..100)
            .map(|i| {
                let path = VaultPath::new(format!("file_{i}"));
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: format!("file_{i}"),
                };
                let inode = table.get_or_insert(&path.clone(), &kind.clone());
                // Increase nlookup to 10 so forgets don't evict
                for _ in 0..9 {
                    table.get_or_insert(&path.clone(), &kind.clone());
                }
                inode
            })
            .collect();

        let mut handles = vec![];

        // Lookups
        for _ in 0..5 {
            let table = Arc::clone(&table);
            let inodes = inodes.clone();
            handles.push(thread::spawn(move || {
                for inode in inodes {
                    let _ = table.get(inode);
                }
            }));
        }

        // Partial forgets (shouldn't evict because nlookup starts at 10)
        // Each thread decrements by 1, with 3 threads that's at most 3 decrements
        for _ in 0..3 {
            let table = Arc::clone(&table);
            let inodes = inodes.clone();
            handles.push(thread::spawn(move || {
                for inode in inodes {
                    let _ = table.forget(inode, 1);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All inodes should still exist (initial nlookup=10, 3x forget(1) leaves nlookup=7)
        assert_eq!(table.len(), 101); // 100 files + root
    }
}
