//! Inode management for the NFS filesystem.
//!
//! This module provides the mapping between NFS file IDs (fileid3) and vault paths.
//! Unlike FUSE, NFS is stateless so we don't need nlookup tracking.

use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use std::sync::atomic::{AtomicU64, Ordering};

/// The root file ID (NFS convention, matching FUSE).
pub const ROOT_FILEID: u64 = 1;

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
}

impl InodeEntry {
    /// Creates a new inode entry.
    pub fn new(path: VaultPath, kind: InodeKind) -> Self {
        Self { path, kind }
    }

    /// Returns the parent directory ID if this is a file or symlink.
    pub fn parent_dir_id(&self) -> Option<&DirId> {
        match &self.kind {
            InodeKind::Root => None,
            InodeKind::Directory { .. } => None,
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
    pub fn dir_id(&self) -> Option<DirId> {
        match &self.kind {
            InodeKind::Root => Some(DirId::root()),
            InodeKind::Directory { dir_id } => Some(dir_id.clone()),
            InodeKind::File { .. } => None,
            InodeKind::Symlink { .. } => None,
        }
    }

    /// Returns file info (dir_id, filename) if this is a file or symlink.
    pub fn file_info(&self) -> Option<(&DirId, &str)> {
        match &self.kind {
            InodeKind::File { dir_id, name } => Some((dir_id, name)),
            InodeKind::Symlink { dir_id, name } => Some((dir_id, name)),
            _ => None,
        }
    }

    /// Returns true if this is a directory (including root).
    pub fn is_directory(&self) -> bool {
        matches!(self.kind, InodeKind::Root | InodeKind::Directory { .. })
    }

    /// Returns true if this is a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self.kind, InodeKind::File { .. })
    }

    /// Returns true if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, InodeKind::Symlink { .. })
    }
}

/// Thread-safe table mapping between file IDs and vault paths.
///
/// Unlike FUSE's InodeTable, this doesn't track nlookup because NFS is stateless.
/// Entries are kept until explicitly removed (on delete/rename).
#[derive(Debug)]
pub struct NfsInodeTable {
    /// Maps vault paths to file IDs.
    path_to_id: DashMap<VaultPath, u64>,
    /// Maps file IDs to entry details.
    id_to_entry: DashMap<u64, InodeEntry>,
    /// Next available file ID (atomic counter).
    next_id: AtomicU64,
}

impl NfsInodeTable {
    /// Creates a new inode table with the root directory pre-allocated.
    pub fn new() -> Self {
        let table = Self {
            path_to_id: DashMap::new(),
            id_to_entry: DashMap::new(),
            // Start at 2 since ID 1 is reserved for root
            next_id: AtomicU64::new(2),
        };

        // Pre-allocate root
        let root_path = VaultPath::root();
        table.path_to_id.insert(root_path.clone(), ROOT_FILEID);
        table
            .id_to_entry
            .insert(ROOT_FILEID, InodeEntry::new(root_path, InodeKind::Root));

        table
    }

    /// Gets or creates a file ID for the given path.
    ///
    /// If the path already has an ID, returns the existing ID.
    /// Otherwise, allocates a new ID and stores the entry.
    pub fn get_or_insert(&self, path: VaultPath, kind: InodeKind) -> u64 {
        // Fast path: check if already exists
        if let Some(id) = self.path_to_id.get(&path) {
            return *id;
        }

        // Slow path: allocate new ID
        let id = self
            .path_to_id
            .entry(path.clone())
            .or_insert_with(|| {
                let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
                self.id_to_entry
                    .insert(new_id, InodeEntry::new(path.clone(), kind));
                new_id
            });

        *id
    }

    /// Looks up an entry by file ID.
    pub fn get(&self, id: u64) -> Option<Ref<'_, u64, InodeEntry>> {
        self.id_to_entry.get(&id)
    }

    /// Looks up an entry by file ID for mutation.
    pub fn get_mut(&self, id: u64) -> Option<RefMut<'_, u64, InodeEntry>> {
        self.id_to_entry.get_mut(&id)
    }

    /// Looks up a file ID by vault path.
    pub fn get_id(&self, path: &VaultPath) -> Option<u64> {
        self.path_to_id.get(path).map(|r| *r)
    }

    /// Removes an entry by path.
    ///
    /// Returns the file ID if it was removed.
    pub fn remove(&self, path: &VaultPath) -> Option<u64> {
        if let Some((_, id)) = self.path_to_id.remove(path) {
            self.id_to_entry.remove(&id);
            Some(id)
        } else {
            None
        }
    }

    /// Removes an entry by file ID.
    ///
    /// Returns the entry if it was removed.
    pub fn remove_by_id(&self, id: u64) -> Option<InodeEntry> {
        // Don't allow removing root
        if id == ROOT_FILEID {
            return None;
        }

        if let Some((_, entry)) = self.id_to_entry.remove(&id) {
            self.path_to_id.remove(&entry.path);
            Some(entry)
        } else {
            None
        }
    }

    /// Updates the path for an entry (used after rename operations).
    pub fn update_path(&self, id: u64, old_path: &VaultPath, new_path: VaultPath) {
        self.path_to_id.remove(old_path);
        self.path_to_id.insert(new_path.clone(), id);

        if let Some(mut entry) = self.id_to_entry.get_mut(&id) {
            entry.path = new_path;
        }
    }

    /// Updates the kind of an existing entry.
    pub fn update_kind(&self, id: u64, kind: InodeKind) -> bool {
        if let Some(mut entry) = self.id_to_entry.get_mut(&id) {
            entry.kind = kind;
            true
        } else {
            false
        }
    }

    /// Returns the number of entries in the table.
    pub fn len(&self) -> usize {
        self.id_to_entry.len()
    }

    /// Returns true if the table only contains the root entry.
    pub fn is_empty(&self) -> bool {
        self.id_to_entry.len() <= 1
    }

    /// Checks if an entry exists for the given ID.
    pub fn contains(&self, id: u64) -> bool {
        self.id_to_entry.contains_key(&id)
    }

    /// Invalidates all cached entries except root.
    ///
    /// This can be called when the vault state may have changed externally.
    pub fn invalidate_all(&self) {
        // Collect non-root entries to remove
        let to_remove: Vec<u64> = self
            .id_to_entry
            .iter()
            .filter(|e| *e.key() != ROOT_FILEID)
            .map(|e| *e.key())
            .collect();

        for id in to_remove {
            self.remove_by_id(id);
        }
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
        let file_entry = InodeEntry::new(
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

        let dir_entry = InodeEntry::new(
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
