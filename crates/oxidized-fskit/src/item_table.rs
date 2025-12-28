//! Item ID management for the FSKit filesystem.
//!
//! This module provides the mapping between FSKit item IDs and vault paths,
//! enabling efficient lookup and management of filesystem entries.
//! Similar to FUSE inodes but adapted for FSKit's semantics.

use dashmap::DashMap;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use std::sync::atomic::{AtomicU64, Ordering};

/// The root item ID for FSKit.
/// FSKit reserves ID 1, so we start the root at 2.
pub const ROOT_ITEM_ID: u64 = 2;

/// Represents the kind of item entry.
#[derive(Debug, Clone)]
pub enum ItemKind {
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

/// An entry in the item table.
#[derive(Debug)]
pub struct ItemEntry {
    /// The virtual path within the vault.
    pub path: VaultPath,
    /// The kind of entry (directory, file, symlink).
    pub kind: ItemKind,
}

impl ItemEntry {
    /// Creates a new item entry.
    pub fn new(path: VaultPath, kind: ItemKind) -> Self {
        Self { path, kind }
    }

    /// Returns the parent directory ID if this is a file or symlink.
    pub fn parent_dir_id(&self) -> Option<&DirId> {
        match &self.kind {
            ItemKind::Root => None,
            ItemKind::Directory { .. } => None,
            ItemKind::File { dir_id, .. } => Some(dir_id),
            ItemKind::Symlink { dir_id, .. } => Some(dir_id),
        }
    }

    /// Returns the filename if this is a file or symlink.
    pub fn filename(&self) -> Option<&str> {
        match &self.kind {
            ItemKind::Root => None,
            ItemKind::Directory { .. } => None,
            ItemKind::File { name, .. } => Some(name),
            ItemKind::Symlink { name, .. } => Some(name),
        }
    }

    /// Returns the directory ID if this is a directory or root.
    pub fn dir_id(&self) -> Option<DirId> {
        match &self.kind {
            ItemKind::Root => Some(DirId::root()),
            ItemKind::Directory { dir_id } => Some(dir_id.clone()),
            ItemKind::File { .. } => None,
            ItemKind::Symlink { .. } => None,
        }
    }

    /// Returns true if this is a directory (including root).
    pub fn is_directory(&self) -> bool {
        matches!(self.kind, ItemKind::Root | ItemKind::Directory { .. })
    }

    /// Returns true if this is a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self.kind, ItemKind::File { .. })
    }

    /// Returns true if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, ItemKind::Symlink { .. })
    }
}

/// Thread-safe table mapping between FSKit item IDs and vault paths.
///
/// This table maintains a bidirectional mapping:
/// - `path_to_id`: VaultPath -> item ID
/// - `id_to_entry`: item ID -> ItemEntry
///
/// The table uses `DashMap` for lock-free concurrent access.
///
/// Unlike FUSE's inode table, FSKit handles reference counting differently
/// via `reclaim_item` calls, so we don't need nlookup tracking.
pub struct ItemTable {
    /// Maps vault paths to item IDs.
    path_to_id: DashMap<VaultPath, u64>,
    /// Maps item IDs to entry details.
    id_to_entry: DashMap<u64, ItemEntry>,
    /// Next available item ID (atomic counter).
    next_id: AtomicU64,
}

impl ItemTable {
    /// Creates a new item table with the root directory pre-allocated.
    pub fn new() -> Self {
        let table = Self {
            path_to_id: DashMap::new(),
            id_to_entry: DashMap::new(),
            // Start at 3 since ID 2 is reserved for root
            next_id: AtomicU64::new(3),
        };

        // Pre-allocate root item
        let root_path = VaultPath::root();
        table.path_to_id.insert(root_path.clone(), ROOT_ITEM_ID);
        table
            .id_to_entry
            .insert(ROOT_ITEM_ID, ItemEntry::new(root_path, ItemKind::Root));

        table
    }

    /// Allocates a new item ID for the given path and kind.
    /// If the path already has an item ID, returns the existing one.
    pub fn get_or_insert(&self, path: VaultPath, kind: ItemKind) -> u64 {
        // Fast path: check if already exists
        if let Some(id) = self.path_to_id.get(&path) {
            return *id;
        }

        // Slow path: allocate new item ID
        // Use entry API to avoid TOCTOU race
        let id = self
            .path_to_id
            .entry(path.clone())
            .or_insert_with(|| {
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                self.id_to_entry.insert(id, ItemEntry::new(path.clone(), kind));
                id
            });

        *id
    }

    /// Looks up an entry by item ID.
    pub fn get(&self, id: u64) -> Option<dashmap::mapref::one::Ref<'_, u64, ItemEntry>> {
        self.id_to_entry.get(&id)
    }

    /// Looks up an entry by item ID for mutation.
    pub fn get_mut(&self, id: u64) -> Option<dashmap::mapref::one::RefMut<'_, u64, ItemEntry>> {
        self.id_to_entry.get_mut(&id)
    }

    /// Updates the kind of an existing item entry.
    /// Returns true if the item was found and updated.
    pub fn update_kind(&self, id: u64, kind: ItemKind) -> bool {
        if let Some(mut entry) = self.id_to_entry.get_mut(&id) {
            entry.kind = kind;
            true
        } else {
            false
        }
    }

    /// Looks up an item ID by vault path.
    pub fn get_id(&self, path: &VaultPath) -> Option<u64> {
        self.path_to_id.get(path).map(|r| *r)
    }

    /// Reclaims an item, removing it from the table.
    /// This is called by FSKit when the system no longer needs the item.
    /// Returns true if the item was removed.
    pub fn reclaim(&self, id: u64) -> bool {
        // Don't reclaim root
        if id == ROOT_ITEM_ID {
            return false;
        }

        if let Some((_, entry)) = self.id_to_entry.remove(&id) {
            self.path_to_id.remove(&entry.path);
            true
        } else {
            false
        }
    }

    /// Invalidates an item by path (used after delete operations).
    /// This removes the path mapping and the entry.
    pub fn invalidate_path(&self, path: &VaultPath) {
        if let Some((_, id)) = self.path_to_id.remove(path) {
            self.id_to_entry.remove(&id);
        }
    }

    /// Updates the path for an item (used after rename operations).
    pub fn update_path(&self, id: u64, old_path: &VaultPath, new_path: VaultPath) {
        self.path_to_id.remove(old_path);
        self.path_to_id.insert(new_path.clone(), id);

        if let Some(mut entry) = self.id_to_entry.get_mut(&id) {
            entry.path = new_path;
        }
    }

    /// Returns the number of items currently in the table.
    pub fn len(&self) -> usize {
        self.id_to_entry.len()
    }

    /// Returns true if the table only contains the root item.
    pub fn is_empty(&self) -> bool {
        self.id_to_entry.len() <= 1
    }
}

impl Default for ItemTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_item_exists() {
        let table = ItemTable::new();
        assert!(table.get(ROOT_ITEM_ID).is_some());
        let entry = table.get(ROOT_ITEM_ID).unwrap();
        assert!(matches!(entry.kind, ItemKind::Root));
    }

    #[test]
    fn test_allocate_item() {
        let table = ItemTable::new();
        let path = VaultPath::new("documents");
        let dir_id = DirId::from_raw("test-uuid");

        let id = table.get_or_insert(path.clone(), ItemKind::Directory { dir_id });
        assert!(id > ROOT_ITEM_ID);

        // Second call should return same ID
        let id2 = table.get_or_insert(
            path.clone(),
            ItemKind::Directory {
                dir_id: DirId::from_raw("different"),
            },
        );
        assert_eq!(id, id2);
    }

    #[test]
    fn test_reclaim_removes_item() {
        let table = ItemTable::new();
        let path = VaultPath::new("temp");

        let id = table.get_or_insert(
            path.clone(),
            ItemKind::File {
                dir_id: DirId::root(),
                name: "temp".to_string(),
            },
        );

        assert!(table.get(id).is_some());

        // Reclaim should remove
        assert!(table.reclaim(id));

        // Item should be gone
        assert!(table.get(id).is_none());
        assert!(table.get_id(&path).is_none());
    }

    #[test]
    fn test_reclaim_root_never_removes() {
        let table = ItemTable::new();
        assert!(!table.reclaim(ROOT_ITEM_ID));
        assert!(table.get(ROOT_ITEM_ID).is_some());
    }

    #[test]
    fn test_update_path() {
        let table = ItemTable::new();
        let old_path = VaultPath::new("old_name");
        let new_path = VaultPath::new("new_name");

        let id = table.get_or_insert(
            old_path.clone(),
            ItemKind::File {
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
    fn test_invalidate_path() {
        let table = ItemTable::new();
        let path = VaultPath::new("to_delete");

        let id = table.get_or_insert(
            path.clone(),
            ItemKind::File {
                dir_id: DirId::root(),
                name: "to_delete".to_string(),
            },
        );

        assert_eq!(table.get_id(&path), Some(id));

        table.invalidate_path(&path);

        // Both path and ID should be gone
        assert!(table.get_id(&path).is_none());
        assert!(table.get(id).is_none());
    }

    #[test]
    fn test_item_entry_methods() {
        let entry = ItemEntry::new(
            VaultPath::new("test/file.txt"),
            ItemKind::File {
                dir_id: DirId::from_raw("parent-id"),
                name: "file.txt".to_string(),
            },
        );

        assert!(entry.is_file());
        assert!(!entry.is_directory());
        assert!(!entry.is_symlink());
        assert_eq!(entry.filename(), Some("file.txt"));
        assert_eq!(entry.parent_dir_id().map(|d| d.as_str()), Some("parent-id"));
        assert!(entry.dir_id().is_none());

        let dir_entry = ItemEntry::new(
            VaultPath::new("test/subdir"),
            ItemKind::Directory {
                dir_id: DirId::from_raw("subdir-id"),
            },
        );

        assert!(!dir_entry.is_file());
        assert!(dir_entry.is_directory());
        assert!(dir_entry.filename().is_none());
        assert_eq!(
            dir_entry.dir_id().map(|d| d.as_str().to_string()),
            Some("subdir-id".to_string())
        );
    }
}
