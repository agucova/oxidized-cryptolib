//! Generic path-to-ID mapping for mount backends.
//!
//! This module provides a unified abstraction for mapping virtual paths to
//! numeric IDs, used by FUSE (inodes), FSKit (item IDs), and NFS (file IDs).
//!
//! # Design
//!
//! All mount backends need to map `VaultPath` to numeric identifiers:
//! - FUSE: inodes (u64) with nlookup reference counting
//! - FSKit: item IDs (u64) with kernel-managed reclaim
//! - NFS: file IDs (u64), stateless
//!
//! This module provides [`PathTable`], a generic bidirectional mapping with:
//! - Lock-free concurrent access via `DashMap`
//! - Atomic ID generation
//! - Path updates for rename operations
//! - Entry invalidation for delete operations
//!
//! # Reference Counting
//!
//! FUSE requires nlookup tracking (increment on lookup, decrement on forget).
//! Rather than baking this into the generic table, FUSE can wrap entries with
//! its own atomic counter. The [`PathTable`] provides the mapping; lifecycle
//! management is backend-specific.

use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use oxcrypt_core::vault::path::{DirId, VaultPath};
use std::sync::atomic::{AtomicU64, Ordering};

/// The kind of entry in a path table.
///
/// This enum represents the four types of filesystem entries:
/// root directory, regular directories, files, and symbolic links.
#[derive(Debug, Clone)]
pub enum EntryKind {
    /// Root directory of the vault.
    Root,
    /// A directory within the vault.
    Directory {
        /// The Cryptomator directory ID.
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

impl EntryKind {
    /// Returns the parent directory ID if this is a file or symlink.
    pub fn parent_dir_id(&self) -> Option<&DirId> {
        match self {
            EntryKind::Root | EntryKind::Directory { .. } => None,
            EntryKind::File { dir_id, .. } | EntryKind::Symlink { dir_id, .. } => Some(dir_id),
        }
    }

    /// Returns the filename if this is a file or symlink.
    pub fn filename(&self) -> Option<&str> {
        match self {
            EntryKind::Root | EntryKind::Directory { .. } => None,
            EntryKind::File { name, .. } | EntryKind::Symlink { name, .. } => Some(name),
        }
    }

    /// Returns the directory ID if this is a directory or root.
    pub fn dir_id(&self) -> Option<DirId> {
        match self {
            EntryKind::Root => Some(DirId::root()),
            EntryKind::Directory { dir_id } => Some(dir_id.clone()),
            EntryKind::File { .. } | EntryKind::Symlink { .. } => None,
        }
    }

    /// Returns file info (dir_id, filename) if this is a file or symlink.
    pub fn file_info(&self) -> Option<(&DirId, &str)> {
        match self {
            EntryKind::File { dir_id, name } | EntryKind::Symlink { dir_id, name } => {
                Some((dir_id, name))
            }
            _ => None,
        }
    }

    /// Returns true if this is a directory (including root).
    pub fn is_directory(&self) -> bool {
        matches!(self, EntryKind::Root | EntryKind::Directory { .. })
    }

    /// Returns true if this is a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self, EntryKind::File { .. })
    }

    /// Returns true if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self, EntryKind::Symlink { .. })
    }
}

/// An entry in the path table.
///
/// Contains the virtual path and its kind. Backends that need additional
/// per-entry state (like FUSE's nlookup) should wrap this in their own type.
#[derive(Debug)]
pub struct PathEntry {
    /// The virtual path within the vault.
    pub path: VaultPath,
    /// The kind of entry (directory, file, symlink).
    pub kind: EntryKind,
}

impl PathEntry {
    /// Creates a new path entry.
    pub fn new(path: VaultPath, kind: EntryKind) -> Self {
        Self { path, kind }
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
    #[inline]
    pub fn dir_id(&self) -> Option<DirId> {
        self.kind.dir_id()
    }

    /// Returns file info (dir_id, filename) if this is a file or symlink.
    #[inline]
    pub fn file_info(&self) -> Option<(&DirId, &str)> {
        self.kind.file_info()
    }

    /// Returns true if this is a directory (including root).
    #[inline]
    pub fn is_directory(&self) -> bool {
        self.kind.is_directory()
    }

    /// Returns true if this is a regular file.
    #[inline]
    pub fn is_file(&self) -> bool {
        self.kind.is_file()
    }

    /// Returns true if this is a symlink.
    #[inline]
    pub fn is_symlink(&self) -> bool {
        self.kind.is_symlink()
    }
}

/// Thread-safe bidirectional mapping between paths and numeric IDs.
///
/// This table maintains two `DashMap`s for efficient lookup in both directions:
/// - `path_to_id`: VaultPath → ID
/// - `id_to_entry`: ID → Entry
///
/// # Type Parameters
///
/// - `Id`: The numeric ID type (typically `u64`)
/// - `Entry`: The entry type (typically [`PathEntry`] or a wrapper)
///
/// # Thread Safety
///
/// All operations are lock-free and safe for concurrent access.
/// The atomic ID counter uses `Ordering::Relaxed` since we only need uniqueness.
///
/// # Example
///
/// ```
/// use oxcrypt_mount::path_mapper::{PathTable, PathEntry, EntryKind};
/// use oxcrypt_core::vault::path::VaultPath;
///
/// let table: PathTable<u64, PathEntry> = PathTable::new(1, 2);
/// let path = VaultPath::new("documents");
/// let kind = EntryKind::Directory { dir_id: oxcrypt_core::vault::path::DirId::from_raw("abc") };
///
/// let id = table.get_or_insert_with(path, || PathEntry::new(VaultPath::new("documents"), kind));
/// assert!(id > 1); // Greater than root ID
/// ```
pub struct PathTable<Id, Entry> {
    /// Maps vault paths to IDs.
    path_to_id: DashMap<VaultPath, Id>,
    /// Maps IDs to entries.
    id_to_entry: DashMap<Id, Entry>,
    /// Next available ID.
    next_id: AtomicU64,
    /// The root ID (reserved).
    root_id: Id,
}

impl<Entry> PathTable<u64, Entry>
where
    Entry: Send + Sync,
{
    /// Creates a new path table with the specified root ID.
    ///
    /// # Arguments
    ///
    /// * `root_id` - The ID to use for the root entry (typically 1 or 2)
    /// * `first_id` - The first ID to allocate for non-root entries
    ///
    /// # Example
    ///
    /// ```
    /// use oxcrypt_mount::path_mapper::{PathTable, PathEntry};
    ///
    /// // FUSE: root=1, first=2
    /// let fuse_table: PathTable<u64, PathEntry> = PathTable::new(1, 2);
    ///
    /// // FSKit: root=2, first=3 (ID 1 is reserved by FSKit)
    /// let fskit_table: PathTable<u64, PathEntry> = PathTable::new(2, 3);
    /// ```
    pub fn new(root_id: u64, first_id: u64) -> Self {
        Self {
            path_to_id: DashMap::new(),
            id_to_entry: DashMap::new(),
            next_id: AtomicU64::new(first_id),
            root_id,
        }
    }

    /// Creates a new path table with the root entry pre-allocated.
    ///
    /// This is a convenience method that calls `new()` and then inserts
    /// the root entry.
    pub fn with_root(root_id: u64, first_id: u64, root_entry: Entry) -> Self {
        let table = Self::new(root_id, first_id);
        let root_path = VaultPath::root();
        table.path_to_id.insert(root_path.clone(), root_id);
        table.id_to_entry.insert(root_id, root_entry);
        table
    }

    /// Returns the root ID.
    #[inline]
    pub fn root_id(&self) -> u64 {
        self.root_id
    }

    /// Allocates a new ID.
    ///
    /// Uses `Ordering::Relaxed` since we only need uniqueness, not synchronization.
    #[inline]
    fn allocate_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Gets or inserts an entry for the given path.
    ///
    /// If the path already has an ID, returns the existing ID.
    /// Otherwise, calls `make_entry` to create a new entry and assigns a new ID.
    ///
    /// # Arguments
    ///
    /// * `path` - The vault path to look up or insert
    /// * `make_entry` - Factory function to create the entry if not present
    ///
    /// # Returns
    ///
    /// The ID associated with the path (existing or newly allocated).
    pub fn get_or_insert_with<F>(&self, path: VaultPath, make_entry: F) -> u64
    where
        F: FnOnce() -> Entry,
    {
        // Fast path: check if already exists
        if let Some(id) = self.path_to_id.get(&path) {
            return *id;
        }

        // Slow path: allocate new ID
        // Use entry API to avoid TOCTOU race
        let id = self
            .path_to_id
            .entry(path.clone())
            .or_insert_with(|| {
                let new_id = self.allocate_id();
                self.id_to_entry.insert(new_id, make_entry());
                new_id
            });

        *id
    }

    /// Gets the ID for a path without inserting.
    pub fn get_id(&self, path: &VaultPath) -> Option<u64> {
        self.path_to_id.get(path).map(|r| *r)
    }

    /// Gets an entry by ID.
    pub fn get(&self, id: u64) -> Option<Ref<'_, u64, Entry>> {
        self.id_to_entry.get(&id)
    }

    /// Gets a mutable entry by ID.
    pub fn get_mut(&self, id: u64) -> Option<RefMut<'_, u64, Entry>> {
        self.id_to_entry.get_mut(&id)
    }

    /// Checks if an entry exists for the given ID.
    pub fn contains(&self, id: u64) -> bool {
        self.id_to_entry.contains_key(&id)
    }

    /// Removes an entry by path.
    ///
    /// Returns the ID and entry if removed, or `None` if not found.
    /// Does not allow removing the root entry.
    pub fn remove_by_path(&self, path: &VaultPath) -> Option<(u64, Entry)> {
        if let Some((_, id)) = self.path_to_id.remove(path) {
            if id == self.root_id {
                // Don't remove root - restore the path mapping
                self.path_to_id.insert(path.clone(), id);
                return None;
            }
            if let Some((_, entry)) = self.id_to_entry.remove(&id) {
                return Some((id, entry));
            }
        }
        None
    }

    /// Removes an entry by ID.
    ///
    /// Returns the entry if removed, or `None` if not found.
    /// Does not allow removing the root entry.
    pub fn remove_by_id(&self, id: u64) -> Option<Entry> {
        if id == self.root_id {
            return None;
        }

        if let Some((_, entry)) = self.id_to_entry.remove(&id) {
            // We need to find and remove the path mapping
            // This is O(n) but remove operations are relatively rare
            self.path_to_id.retain(|_, v| *v != id);
            Some(entry)
        } else {
            None
        }
    }

    /// Invalidates a path mapping without removing the entry.
    ///
    /// This is used after delete operations where the entry should remain
    /// until explicitly reclaimed (e.g., FUSE forget).
    pub fn invalidate_path(&self, path: &VaultPath) {
        self.path_to_id.remove(path);
    }

    /// Updates the path for an entry (used after rename operations).
    ///
    /// This atomically updates both the path-to-ID mapping and the entry's path.
    /// Requires a mutable update function since [`PathEntry`] stores the path.
    pub fn update_path<F>(&self, id: u64, old_path: &VaultPath, new_path: VaultPath, update_entry: F)
    where
        F: FnOnce(&mut Entry, VaultPath),
    {
        self.path_to_id.remove(old_path);
        self.path_to_id.insert(new_path.clone(), id);

        if let Some(mut entry) = self.id_to_entry.get_mut(&id) {
            update_entry(&mut entry, new_path);
        }
    }

    /// Directly sets the path-to-ID mapping.
    ///
    /// This is a low-level method for operations like atomic path swaps
    /// where two paths need to exchange IDs. The caller is responsible
    /// for updating the entry's internal path field separately.
    ///
    /// Note: This only updates the path_to_id map, not the entry itself.
    /// Use `update_path` if you need to update both the mapping and entry.
    pub fn set_path_mapping(&self, path: VaultPath, id: u64) {
        self.path_to_id.insert(path, id);
    }

    /// Invalidates all entries except root.
    ///
    /// This is useful when the vault state may have changed externally.
    pub fn invalidate_all(&self) {
        let to_remove: Vec<u64> = self
            .id_to_entry
            .iter()
            .filter(|e| *e.key() != self.root_id)
            .map(|e| *e.key())
            .collect();

        for id in to_remove {
            self.remove_by_id(id);
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
}

// Implement Default for common case (FUSE-style: root=1, first=2)
impl Default for PathTable<u64, PathEntry> {
    fn default() -> Self {
        Self::with_root(1, 2, PathEntry::new(VaultPath::root(), EntryKind::Root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_table() -> PathTable<u64, PathEntry> {
        PathTable::with_root(1, 2, PathEntry::new(VaultPath::root(), EntryKind::Root))
    }

    #[test]
    fn test_root_exists() {
        let table = make_test_table();
        assert!(table.get(1).is_some());
        let entry = table.get(1).unwrap();
        assert!(matches!(entry.kind, EntryKind::Root));
        assert!(entry.is_directory());
    }

    #[test]
    fn test_get_or_insert() {
        let table = make_test_table();
        let path = VaultPath::new("documents");

        let id = table.get_or_insert_with(path.clone(), || {
            PathEntry::new(
                path.clone(),
                EntryKind::Directory {
                    dir_id: DirId::from_raw("test-uuid"),
                },
            )
        });
        assert!(id > 1);

        // Second call should return same ID
        let id2 = table.get_or_insert_with(path.clone(), || {
            PathEntry::new(
                path.clone(),
                EntryKind::Directory {
                    dir_id: DirId::from_raw("different"),
                },
            )
        });
        assert_eq!(id, id2);
    }

    #[test]
    fn test_remove_by_path() {
        let table = make_test_table();
        let path = VaultPath::new("temp");

        let id = table.get_or_insert_with(path.clone(), || {
            PathEntry::new(
                path.clone(),
                EntryKind::File {
                    dir_id: DirId::root(),
                    name: "temp".to_string(),
                },
            )
        });

        assert!(table.get(id).is_some());

        let removed = table.remove_by_path(&path);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().0, id);
        assert!(table.get(id).is_none());
        assert!(table.get_id(&path).is_none());
    }

    #[test]
    fn test_remove_root_fails() {
        let table = make_test_table();
        let root_path = VaultPath::root();

        assert!(table.remove_by_path(&root_path).is_none());
        assert!(table.remove_by_id(1).is_none());
        assert!(table.get(1).is_some());
    }

    #[test]
    fn test_update_path() {
        let table = make_test_table();
        let old_path = VaultPath::new("old_name");
        let new_path = VaultPath::new("new_name");

        let id = table.get_or_insert_with(old_path.clone(), || {
            PathEntry::new(
                old_path.clone(),
                EntryKind::File {
                    dir_id: DirId::root(),
                    name: "old_name".to_string(),
                },
            )
        });

        table.update_path(id, &old_path, new_path.clone(), |entry, path| {
            entry.path = path;
        });

        assert!(table.get_id(&old_path).is_none());
        assert_eq!(table.get_id(&new_path), Some(id));

        let entry = table.get(id).unwrap();
        assert_eq!(entry.path, new_path);
    }

    #[test]
    fn test_invalidate_path() {
        let table = make_test_table();
        let path = VaultPath::new("to_delete");

        let id = table.get_or_insert_with(path.clone(), || {
            PathEntry::new(
                path.clone(),
                EntryKind::File {
                    dir_id: DirId::root(),
                    name: "to_delete".to_string(),
                },
            )
        });

        assert_eq!(table.get_id(&path), Some(id));

        table.invalidate_path(&path);

        // Path mapping gone, but entry still exists
        assert!(table.get_id(&path).is_none());
        assert!(table.get(id).is_some());
    }

    #[test]
    fn test_invalidate_all() {
        let table = make_test_table();

        // Add some entries
        for i in 0..5 {
            let path = VaultPath::new(format!("file_{}", i));
            table.get_or_insert_with(path.clone(), || {
                PathEntry::new(
                    path,
                    EntryKind::File {
                        dir_id: DirId::root(),
                        name: format!("file_{}", i),
                    },
                )
            });
        }

        assert_eq!(table.len(), 6); // root + 5 files

        table.invalidate_all();

        assert_eq!(table.len(), 1); // Only root remains
        assert!(table.get(1).is_some());
    }

    #[test]
    fn test_entry_kind_methods() {
        let file = EntryKind::File {
            dir_id: DirId::from_raw("parent"),
            name: "test.txt".to_string(),
        };
        assert!(file.is_file());
        assert!(!file.is_directory());
        assert!(!file.is_symlink());
        assert_eq!(file.filename(), Some("test.txt"));
        assert_eq!(file.parent_dir_id().map(|d| d.as_str()), Some("parent"));
        assert!(file.dir_id().is_none());

        let dir = EntryKind::Directory {
            dir_id: DirId::from_raw("dir-id"),
        };
        assert!(!dir.is_file());
        assert!(dir.is_directory());
        assert!(dir.filename().is_none());
        assert_eq!(
            dir.dir_id().map(|d| d.as_str().to_string()),
            Some("dir-id".to_string())
        );

        let symlink = EntryKind::Symlink {
            dir_id: DirId::from_raw("parent"),
            name: "link".to_string(),
        };
        assert!(symlink.is_symlink());
        assert!(!symlink.is_file());
        assert_eq!(symlink.filename(), Some("link"));
    }

    #[test]
    fn test_concurrent_allocation() {
        use std::sync::Arc;
        use std::thread;

        let table = Arc::new(make_test_table());
        let mut handles = vec![];

        for i in 0..10 {
            let table = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                let path = VaultPath::new(format!("file_{}", i));
                table.get_or_insert_with(path.clone(), || {
                    PathEntry::new(
                        path,
                        EntryKind::File {
                            dir_id: DirId::root(),
                            name: format!("file_{}", i),
                        },
                    )
                })
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
    fn test_fskit_style_ids() {
        // FSKit uses root_id=2, first_id=3 (ID 1 is reserved by FSKit)
        let table: PathTable<u64, PathEntry> =
            PathTable::with_root(2, 3, PathEntry::new(VaultPath::root(), EntryKind::Root));

        assert_eq!(table.root_id(), 2);
        assert!(table.get(2).is_some());

        let path = VaultPath::new("test");
        let id = table.get_or_insert_with(path.clone(), || {
            PathEntry::new(
                path,
                EntryKind::File {
                    dir_id: DirId::root(),
                    name: "test".to_string(),
                },
            )
        });

        // First allocated ID should be 3
        assert_eq!(id, 3);
    }
}
