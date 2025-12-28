//! Inode management for the FUSE filesystem.
//!
//! This module provides the mapping between FUSE inodes and vault paths,
//! enabling efficient lookup and management of filesystem entries.

use dashmap::DashMap;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use std::sync::atomic::{AtomicU64, Ordering};

/// The root inode number (FUSE convention).
pub const ROOT_INODE: u64 = 1;

/// Represents the kind of inode entry.
#[derive(Debug, Clone)]
pub enum InodeKind {
    /// Root directory of the vault.
    Root,
    /// A directory within the vault.
    Directory {
        /// The directory ID used by Cryptomator.
        dir_id: DirId,
    },
    /// A regular file.
    File {
        /// Parent directory ID.
        dir_id: DirId,
        /// Decrypted filename.
        name: String,
    },
    /// A symbolic link.
    Symlink {
        /// Parent directory ID.
        dir_id: DirId,
        /// Decrypted filename.
        name: String,
    },
}

/// An entry in the inode table.
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
    /// Creates a new inode entry.
    pub fn new(path: VaultPath, kind: InodeKind) -> Self {
        Self {
            path,
            kind,
            nlookup: AtomicU64::new(1), // Initial lookup count is 1
        }
    }

    /// Increments the lookup count and returns the new value.
    pub fn inc_nlookup(&self) -> u64 {
        self.nlookup.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Decrements the lookup count by the given amount and returns the new value.
    /// Returns `None` if the count would go negative (shouldn't happen in normal operation).
    pub fn dec_nlookup(&self, count: u64) -> Option<u64> {
        let old = self.nlookup.fetch_sub(count, Ordering::SeqCst);
        if old < count {
            // This shouldn't happen - restore and return None
            self.nlookup.fetch_add(count, Ordering::SeqCst);
            None
        } else {
            Some(old - count)
        }
    }

    /// Returns the current lookup count.
    pub fn nlookup(&self) -> u64 {
        self.nlookup.load(Ordering::SeqCst)
    }

    /// Returns the parent directory ID if this is a file or symlink.
    pub fn parent_dir_id(&self) -> Option<&DirId> {
        match &self.kind {
            InodeKind::Root => None,
            InodeKind::Directory { .. } => None, // Directories don't store parent
            InodeKind::File { dir_id, .. } => Some(dir_id),
            InodeKind::Symlink { dir_id, .. } => Some(dir_id),
        }
    }

    /// Returns the filename if this is a file or symlink.
    pub fn filename(&self) -> Option<&str> {
        match &self.kind {
            InodeKind::Root => None,
            InodeKind::Directory { .. } => None,
            InodeKind::File { name, .. } => Some(name),
            InodeKind::Symlink { name, .. } => Some(name),
        }
    }

    /// Returns the directory ID if this is a directory or root.
    /// For root, returns a cloned root DirId.
    pub fn dir_id(&self) -> Option<DirId> {
        match &self.kind {
            InodeKind::Root => Some(DirId::root()),
            InodeKind::Directory { dir_id } => Some(dir_id.clone()),
            InodeKind::File { .. } => None,
            InodeKind::Symlink { .. } => None,
        }
    }
}

/// Thread-safe table mapping between inodes and vault paths.
///
/// This table maintains a bidirectional mapping:
/// - `path_to_inode`: VaultPath -> inode number
/// - `inode_to_entry`: inode number -> InodeEntry
///
/// The table uses `DashMap` for lock-free concurrent access.
pub struct InodeTable {
    /// Maps vault paths to inode numbers.
    path_to_inode: DashMap<VaultPath, u64>,
    /// Maps inode numbers to entry details.
    inode_to_entry: DashMap<u64, InodeEntry>,
    /// Next available inode number (atomic counter).
    next_inode: AtomicU64,
}

impl InodeTable {
    /// Creates a new inode table with the root directory pre-allocated.
    pub fn new() -> Self {
        let table = Self {
            path_to_inode: DashMap::new(),
            inode_to_entry: DashMap::new(),
            // Start at 2 since inode 1 is reserved for root
            next_inode: AtomicU64::new(2),
        };

        // Pre-allocate root inode
        let root_path = VaultPath::root();
        table
            .path_to_inode
            .insert(root_path.clone(), ROOT_INODE);
        table.inode_to_entry.insert(
            ROOT_INODE,
            InodeEntry::new(root_path, InodeKind::Root),
        );

        table
    }

    /// Allocates a new inode for the given path and kind.
    /// If the path already has an inode, increments its lookup count and returns the existing inode.
    pub fn get_or_insert(&self, path: VaultPath, kind: InodeKind) -> u64 {
        // Fast path: check if already exists
        if let Some(inode) = self.path_to_inode.get(&path) {
            let ino = *inode;
            // Increment lookup count
            if let Some(entry) = self.inode_to_entry.get(&ino) {
                entry.inc_nlookup();
            }
            return ino;
        }

        // Slow path: allocate new inode
        // Use entry API to avoid TOCTOU race
        let inode = self
            .path_to_inode
            .entry(path.clone())
            .or_insert_with(|| {
                let ino = self.next_inode.fetch_add(1, Ordering::SeqCst);
                self.inode_to_entry
                    .insert(ino, InodeEntry::new(path.clone(), kind));
                ino
            });

        *inode
    }

    /// Looks up an entry by inode number.
    pub fn get(&self, inode: u64) -> Option<dashmap::mapref::one::Ref<'_, u64, InodeEntry>> {
        self.inode_to_entry.get(&inode)
    }

    /// Looks up an entry by inode number for mutation.
    pub fn get_mut(
        &self,
        inode: u64,
    ) -> Option<dashmap::mapref::one::RefMut<'_, u64, InodeEntry>> {
        self.inode_to_entry.get_mut(&inode)
    }

    /// Looks up an inode by vault path.
    pub fn get_inode(&self, path: &VaultPath) -> Option<u64> {
        self.path_to_inode.get(path).map(|r| *r)
    }

    /// Decrements the lookup count for an inode.
    /// If the count reaches zero, the inode is eligible for eviction.
    /// Returns `true` if the inode was evicted.
    pub fn forget(&self, inode: u64, nlookup: u64) -> bool {
        // Don't evict root
        if inode == ROOT_INODE {
            return false;
        }

        if let Some(entry) = self.inode_to_entry.get(&inode)
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
        if let Some((_, entry)) = self.inode_to_entry.remove(&inode) {
            self.path_to_inode.remove(&entry.path);
            true
        } else {
            false
        }
    }

    /// Invalidates an inode by path (used after delete operations).
    /// This removes the path mapping but keeps the inode entry until forget() is called.
    pub fn invalidate_path(&self, path: &VaultPath) {
        self.path_to_inode.remove(path);
    }

    /// Updates the path for an inode (used after rename operations).
    pub fn update_path(&self, inode: u64, old_path: &VaultPath, new_path: VaultPath) {
        self.path_to_inode.remove(old_path);
        self.path_to_inode.insert(new_path.clone(), inode);

        if let Some(mut entry) = self.inode_to_entry.get_mut(&inode) {
            entry.path = new_path;
        }
    }

    /// Returns the number of inodes currently in the table.
    pub fn len(&self) -> usize {
        self.inode_to_entry.len()
    }

    /// Returns true if the table only contains the root inode.
    pub fn is_empty(&self) -> bool {
        self.inode_to_entry.len() <= 1
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

        let inode = table.get_or_insert(path.clone(), InodeKind::Directory { dir_id });
        assert!(inode > ROOT_INODE);

        // Second call should return same inode
        let inode2 = table.get_or_insert(
            path.clone(),
            InodeKind::Directory {
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
            path.clone(),
            InodeKind::File {
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

        let inode = table.get_or_insert(
            old_path.clone(),
            InodeKind::File {
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
    fn test_invalidate_path() {
        let table = InodeTable::new();
        let path = VaultPath::new("to_delete");

        let inode = table.get_or_insert(
            path.clone(),
            InodeKind::File {
                dir_id: DirId::root(),
                name: "to_delete".to_string(),
            },
        );

        // Path should be mapped
        assert_eq!(table.get_inode(&path), Some(inode));

        // Invalidate
        table.invalidate_path(&path);

        // Path should not be mapped, but inode entry still exists
        assert!(table.get_inode(&path).is_none());
        assert!(table.get(inode).is_some());
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
                let path = VaultPath::new(format!("file_{}", i));
                table.get_or_insert(
                    path,
                    InodeKind::File {
                        dir_id: DirId::root(),
                        name: format!("file_{}", i),
                    },
                )
            }));
        }

        let inodes: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All inodes should be unique (not counting root)
        let mut sorted = inodes.clone();
        sorted.sort();
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
        let inode = table.get_or_insert(
            path.clone(),
            InodeKind::File {
                dir_id: DirId::root(),
                name: "nlookup_test".to_string(),
            },
        );
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Second lookup: nlookup = 2
        table.get_or_insert(
            path.clone(),
            InodeKind::File {
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
    fn test_inode_entry_methods() {
        let entry = InodeEntry::new(
            VaultPath::new("test/file.txt"),
            InodeKind::File {
                dir_id: DirId::from_raw("parent-id"),
                name: "file.txt".to_string(),
            },
        );

        assert_eq!(entry.filename(), Some("file.txt"));
        assert_eq!(entry.parent_dir_id().map(|d| d.as_str()), Some("parent-id"));
        assert!(entry.dir_id().is_none());

        let dir_entry = InodeEntry::new(
            VaultPath::new("test/subdir"),
            InodeKind::Directory {
                dir_id: DirId::from_raw("subdir-id"),
            },
        );

        assert!(dir_entry.filename().is_none());
        assert!(dir_entry.parent_dir_id().is_none());
        assert_eq!(dir_entry.dir_id().map(|d| d.as_str().to_string()), Some("subdir-id".to_string()));
    }
}
