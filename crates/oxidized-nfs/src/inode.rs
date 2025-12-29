//! Inode management for the NFS filesystem.
//!
//! This module provides the mapping between NFS file IDs (fileid3) and vault paths.
//! Unlike FUSE, NFS is stateless so we don't need nlookup tracking.
//!
//! The implementation uses the shared `PathTable` from `oxidized-mount-common`,
//! providing consistent behavior across mount backends.

use dashmap::mapref::one::{Ref, RefMut};
use oxidized_cryptolib::vault::path::VaultPath;
use oxidized_mount_common::path_mapper::{EntryKind, PathEntry, PathTable};

/// The root file ID (NFS convention, matching FUSE).
pub const ROOT_FILEID: u64 = 1;

/// Represents the kind of inode entry.
/// This is an alias for the shared `EntryKind` from mount-common.
pub type InodeKind = EntryKind;

/// An entry in the inode table.
/// This is an alias for the shared `PathEntry` from mount-common.
pub type InodeEntry = PathEntry;

/// Thread-safe table mapping between file IDs and vault paths.
///
/// Unlike FUSE's InodeTable, this doesn't track nlookup because NFS is stateless.
/// Entries are kept until explicitly removed (on delete/rename).
pub struct NfsInodeTable {
    /// The shared path table implementation.
    inner: PathTable<u64, InodeEntry>,
}

impl NfsInodeTable {
    /// Creates a new inode table with the root directory pre-allocated.
    pub fn new() -> Self {
        Self {
            inner: PathTable::with_root(
                ROOT_FILEID,
                // Start at 2 since ID 1 is reserved for root
                2,
                PathEntry::new(VaultPath::root(), InodeKind::Root),
            ),
        }
    }

    /// Gets or creates a file ID for the given path.
    ///
    /// If the path already has an ID, returns the existing ID.
    /// Otherwise, allocates a new ID and stores the entry.
    pub fn get_or_insert(&self, path: VaultPath, kind: InodeKind) -> u64 {
        self.inner
            .get_or_insert_with(path.clone(), || PathEntry::new(path, kind))
    }

    /// Looks up an entry by file ID.
    pub fn get(&self, id: u64) -> Option<Ref<'_, u64, InodeEntry>> {
        self.inner.get(id)
    }

    /// Looks up an entry by file ID for mutation.
    pub fn get_mut(&self, id: u64) -> Option<RefMut<'_, u64, InodeEntry>> {
        self.inner.get_mut(id)
    }

    /// Looks up a file ID by vault path.
    pub fn get_id(&self, path: &VaultPath) -> Option<u64> {
        self.inner.get_id(path)
    }

    /// Removes an entry by path.
    ///
    /// Returns the file ID if it was removed.
    pub fn remove(&self, path: &VaultPath) -> Option<u64> {
        self.inner.remove_by_path(path).map(|(id, _)| id)
    }

    /// Removes an entry by file ID.
    ///
    /// Returns the entry if it was removed.
    pub fn remove_by_id(&self, id: u64) -> Option<InodeEntry> {
        // Don't allow removing root
        if id == ROOT_FILEID {
            return None;
        }

        self.inner.remove_by_id(id)
    }

    /// Updates the path for an entry (used after rename operations).
    pub fn update_path(&self, id: u64, old_path: &VaultPath, new_path: VaultPath) {
        self.inner
            .update_path(id, old_path, new_path.clone(), |entry, path| {
                entry.path = path;
            });
    }

    /// Updates the kind of an existing entry.
    pub fn update_kind(&self, id: u64, kind: InodeKind) -> bool {
        if let Some(mut entry) = self.inner.get_mut(id) {
            entry.kind = kind;
            true
        } else {
            false
        }
    }

    /// Returns the number of entries in the table.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the table only contains the root entry.
    pub fn is_empty(&self) -> bool {
        self.inner.len() <= 1
    }

    /// Checks if an entry exists for the given ID.
    pub fn contains(&self, id: u64) -> bool {
        self.inner.contains(id)
    }

    /// Invalidates all cached entries except root.
    ///
    /// This can be called when the vault state may have changed externally.
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }
}

impl Default for NfsInodeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidized_cryptolib::vault::path::DirId;

    #[test]
    fn test_root_exists() {
        let table = NfsInodeTable::new();
        assert!(table.get(ROOT_FILEID).is_some());
        let entry = table.get(ROOT_FILEID).unwrap();
        assert!(matches!(entry.kind, InodeKind::Root));
        assert!(entry.is_directory());
    }

    #[test]
    fn test_get_or_insert() {
        let table = NfsInodeTable::new();
        let path = VaultPath::new("documents");
        let dir_id = DirId::from_raw("test-uuid");

        let id = table.get_or_insert(path.clone(), InodeKind::Directory { dir_id });
        assert!(id > ROOT_FILEID);

        // Second call should return same ID
        let id2 = table.get_or_insert(
            path.clone(),
            InodeKind::Directory {
                dir_id: DirId::from_raw("different"),
            },
        );
        assert_eq!(id, id2);
    }

    #[test]
    fn test_remove() {
        let table = NfsInodeTable::new();
        let path = VaultPath::new("temp");

        let id = table.get_or_insert(
            path.clone(),
            InodeKind::File {
                dir_id: DirId::root(),
                name: "temp".to_string(),
            },
        );

        assert!(table.get(id).is_some());

        let removed_id = table.remove(&path);
        assert_eq!(removed_id, Some(id));
        assert!(table.get(id).is_none());
        assert!(table.get_id(&path).is_none());
    }

    #[test]
    fn test_remove_root_fails() {
        let table = NfsInodeTable::new();
        assert!(table.remove_by_id(ROOT_FILEID).is_none());
        assert!(table.get(ROOT_FILEID).is_some());
    }

    #[test]
    fn test_update_path() {
        let table = NfsInodeTable::new();
        let old_path = VaultPath::new("old_name");
        let new_path = VaultPath::new("new_name");

        let id = table.get_or_insert(
            old_path.clone(),
            InodeKind::File {
                dir_id: DirId::root(),
                name: "old_name".to_string(),
            },
        );

        table.update_path(id, &old_path, new_path.clone());

        assert!(table.get_id(&old_path).is_none());
        assert_eq!(table.get_id(&new_path), Some(id));

        let entry = table.get(id).unwrap();
        assert_eq!(entry.path, new_path);
    }

    #[test]
    fn test_entry_methods() {
        let file_entry = PathEntry::new(
            VaultPath::new("test/file.txt"),
            InodeKind::File {
                dir_id: DirId::from_raw("parent-id"),
                name: "file.txt".to_string(),
            },
        );

        assert!(file_entry.is_file());
        assert!(!file_entry.is_directory());
        assert!(!file_entry.is_symlink());
        assert_eq!(file_entry.filename(), Some("file.txt"));
        assert_eq!(
            file_entry.parent_dir_id().map(|d| d.as_str()),
            Some("parent-id")
        );
        assert!(file_entry.dir_id().is_none());
        assert_eq!(
            file_entry.file_info().map(|(d, n)| (d.as_str(), n)),
            Some(("parent-id", "file.txt"))
        );

        let dir_entry = PathEntry::new(
            VaultPath::new("test/subdir"),
            InodeKind::Directory {
                dir_id: DirId::from_raw("subdir-id"),
            },
        );

        assert!(!dir_entry.is_file());
        assert!(dir_entry.is_directory());
        assert!(dir_entry.filename().is_none());
        assert!(dir_entry.file_info().is_none());
        assert_eq!(
            dir_entry.dir_id().map(|d| d.as_str().to_string()),
            Some("subdir-id".to_string())
        );
    }

    #[test]
    fn test_concurrent_allocation() {
        use std::sync::Arc;
        use std::thread;

        let table = Arc::new(NfsInodeTable::new());
        let mut handles = vec![];

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

        let ids: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All IDs should be unique
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());

        // Table should have 11 entries (root + 10 files)
        assert_eq!(table.len(), 11);
    }

    #[test]
    fn test_invalidate_all() {
        let table = NfsInodeTable::new();

        // Add some entries
        for i in 0..5 {
            table.get_or_insert(
                VaultPath::new(format!("file_{}", i)),
                InodeKind::File {
                    dir_id: DirId::root(),
                    name: format!("file_{}", i),
                },
            );
        }

        assert_eq!(table.len(), 6); // root + 5 files

        table.invalidate_all();

        assert_eq!(table.len(), 1); // Only root remains
        assert!(table.get(ROOT_FILEID).is_some());
    }
}
