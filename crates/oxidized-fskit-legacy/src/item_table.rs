//! Item ID management for the FSKit filesystem.
//!
//! This module provides the mapping between FSKit item IDs and vault paths,
//! enabling efficient lookup and management of filesystem entries.
//! Similar to FUSE inodes but adapted for FSKit's semantics.
//!
//! The implementation uses the shared `PathTable` from `oxidized-mount-common`,
//! providing consistent behavior across mount backends.

use dashmap::mapref::one::{Ref, RefMut};
use oxidized_cryptolib::vault::path::VaultPath;
use oxidized_mount_common::path_mapper::{EntryKind, PathEntry, PathTable};

/// The root item ID for FSKit.
/// FSKit reserves ID 1, so we start the root at 2.
pub const ROOT_ITEM_ID: u64 = 2;

/// Represents the kind of item entry.
/// This is an alias for the shared `EntryKind` from mount-common.
pub type ItemKind = EntryKind;

/// An entry in the item table.
///
/// FSKit doesn't need reference counting (nlookup) like FUSE because
/// reclaim is handled through `reclaim_item` calls from the kernel.
pub type ItemEntry = PathEntry;

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
    /// The shared path table implementation.
    inner: PathTable<u64, ItemEntry>,
}

impl ItemTable {
    /// Creates a new item table with the root directory pre-allocated.
    pub fn new() -> Self {
        Self {
            inner: PathTable::with_root(
                ROOT_ITEM_ID,
                // Start at 3 since ID 2 is reserved for root
                3,
                PathEntry::new(VaultPath::root(), ItemKind::Root),
            ),
        }
    }

    /// Allocates a new item ID for the given path and kind.
    /// If the path already has an item ID, returns the existing one.
    pub fn get_or_insert(&self, path: VaultPath, kind: ItemKind) -> u64 {
        self.inner
            .get_or_insert_with(path.clone(), || PathEntry::new(path, kind))
    }

    /// Looks up an entry by item ID.
    pub fn get(&self, id: u64) -> Option<Ref<'_, u64, ItemEntry>> {
        self.inner.get(id)
    }

    /// Looks up an entry by item ID for mutation.
    pub fn get_mut(&self, id: u64) -> Option<RefMut<'_, u64, ItemEntry>> {
        self.inner.get_mut(id)
    }

    /// Updates the kind of an existing item entry.
    /// Returns true if the item was found and updated.
    pub fn update_kind(&self, id: u64, kind: ItemKind) -> bool {
        if let Some(mut entry) = self.inner.get_mut(id) {
            entry.kind = kind;
            true
        } else {
            false
        }
    }

    /// Looks up an item ID by vault path.
    pub fn get_id(&self, path: &VaultPath) -> Option<u64> {
        self.inner.get_id(path)
    }

    /// Reclaims an item, removing it from the table.
    /// This is called by FSKit when the system no longer needs the item.
    /// Returns true if the item was removed.
    pub fn reclaim(&self, id: u64) -> bool {
        // Don't reclaim root
        if id == ROOT_ITEM_ID {
            return false;
        }

        self.inner.remove_by_id(id).is_some()
    }

    /// Invalidates an item by path (used after delete operations).
    /// This removes the path mapping and the entry.
    pub fn invalidate_path(&self, path: &VaultPath) {
        // Use remove_by_path to remove both path mapping and entry
        self.inner.remove_by_path(path);
    }

    /// Updates the path for an item (used after rename operations).
    pub fn update_path(&self, id: u64, old_path: &VaultPath, new_path: VaultPath) {
        self.inner.update_path(id, old_path, new_path.clone(), |entry, path| {
            entry.path = path;
        });
    }

    /// Returns the number of items currently in the table.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the table only contains the root item.
    pub fn is_empty(&self) -> bool {
        self.inner.len() <= 1
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
    use oxidized_cryptolib::vault::path::DirId;

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
        let entry = PathEntry::new(
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

        let dir_entry = PathEntry::new(
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
