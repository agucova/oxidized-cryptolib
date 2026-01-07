//! Thread-safe handle table for managing file handles.
//!
//! This module provides a generic handle table backed by `DashMap` for
//! concurrent access. It supports both auto-incrementing IDs (for FUSE)
//! and caller-provided keys (for FSKit/WebDAV).
//!
//! # Handle Lifecycle
//!
//! 1. **Insert**: Add a handle with either auto-generated or caller-provided ID
//! 2. **Get/GetMut**: Access the handle for read/write operations
//! 3. **Remove**: Remove and return the handle when done

use dashmap::mapref::entry::Entry;
use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe handle table with optional auto-ID generation.
///
/// This provides a concurrent map from handle IDs to handle values.
/// For `u64` keys, it can optionally auto-generate incrementing IDs.
///
/// # Example with auto-incrementing IDs (FUSE pattern)
///
/// ```
/// use oxcrypt_mount::HandleTable;
///
/// let table: HandleTable<u64, String> = HandleTable::new_auto_id();
///
/// let id1 = table.insert_auto("file1".to_string());
/// let id2 = table.insert_auto("file2".to_string());
///
/// assert_ne!(id1, id2);
/// assert_eq!(table.len(), 2);
///
/// let value = table.remove(&id1);
/// assert_eq!(value, Some("file1".to_string()));
/// ```
///
/// # Example with caller-provided keys (WebDAV pattern)
///
/// ```
/// use oxcrypt_mount::HandleTable;
///
/// let table: HandleTable<String, i32> = HandleTable::new();
///
/// table.insert("/path/to/file".to_string(), 42);
///
/// if let Some(handle) = table.get(&"/path/to/file".to_string()) {
///     assert_eq!(*handle, 42);
/// }
/// ```
#[derive(Debug)]
pub struct HandleTable<K, V>
where
    K: Eq + Hash,
{
    /// The handle map.
    handles: DashMap<K, V>,
    /// For auto-incrementing u64 keys (starts at 1, 0 reserved for invalid).
    /// Only used when K = u64.
    next_id: Option<AtomicU64>,
}

impl<V> HandleTable<u64, V> {
    /// Create a handle table with auto-incrementing u64 keys.
    ///
    /// IDs start at 1 (0 is reserved for invalid/null handle).
    pub fn new_auto_id() -> Self {
        Self {
            handles: DashMap::new(),
            next_id: Some(AtomicU64::new(1)),
        }
    }

    /// Insert a value with an auto-generated ID.
    ///
    /// # Returns
    ///
    /// The auto-generated handle ID.
    pub fn insert_auto(&self, value: V) -> u64 {
        let next_id = self
            .next_id
            .as_ref()
            .expect("insert_auto requires new_auto_id");
        let mut value = Some(value);
        loop {
            let id = next_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    let next = current.checked_add(1).unwrap_or(1);
                    Some(next)
                })
                .expect("fetch_update always succeeds");
            if id == 0 {
                continue;
            }
            if let Entry::Vacant(entry) = self.handles.entry(id) {
                entry.insert(value.take().expect("value already inserted"));
                return id;
            }
        }
    }
}

impl<K, V> HandleTable<K, V>
where
    K: Eq + Hash,
{
    /// Create a handle table with caller-provided keys.
    pub fn new() -> Self {
        Self {
            handles: DashMap::new(),
            next_id: None,
        }
    }

    /// Create a handle table with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            handles: DashMap::with_capacity(capacity),
            next_id: None,
        }
    }

    /// Insert a handle with a specific key.
    ///
    /// If the key already exists, the old value is replaced.
    pub fn insert(&self, key: K, value: V) {
        self.handles.insert(key, value);
    }

    /// Get a reference to a handle by key.
    pub fn get(&self, key: &K) -> Option<Ref<'_, K, V>> {
        self.handles.get(key)
    }

    /// Get a mutable reference to a handle by key.
    pub fn get_mut(&self, key: &K) -> Option<RefMut<'_, K, V>> {
        self.handles.get_mut(key)
    }

    /// Remove a handle by key and return it.
    pub fn remove(&self, key: &K) -> Option<V> {
        self.handles.remove(key).map(|(_, v)| v)
    }

    /// Check if a handle exists.
    pub fn contains(&self, key: &K) -> bool {
        self.handles.contains_key(key)
    }

    /// Get the number of handles.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Clear all handles.
    pub fn clear(&self) {
        self.handles.clear();
    }

    /// Retain only handles matching a predicate.
    pub fn retain<F>(&self, f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.handles.retain(f);
    }
}

impl<K, V> Default for HandleTable<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_auto_id_insert() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();

        let id1 = table.insert_auto("file1".to_string());
        let id2 = table.insert_auto("file2".to_string());
        let id3 = table.insert_auto("file3".to_string());

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn test_manual_insert() {
        let table: HandleTable<String, i32> = HandleTable::new();

        table.insert("/file1".to_string(), 100);
        table.insert("/file2".to_string(), 200);

        assert_eq!(table.len(), 2);
        assert!(table.contains(&"/file1".to_string()));
        assert!(!table.contains(&"/file3".to_string()));
    }

    #[test]
    fn test_get() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();
        let id = table.insert_auto("hello".to_string());

        let handle = table.get(&id).expect("Should exist");
        assert_eq!(*handle, "hello");
    }

    #[test]
    fn test_get_mut() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();
        let id = table.insert_auto("hello".to_string());

        {
            let mut handle = table.get_mut(&id).expect("Should exist");
            handle.push_str(" world");
        }

        let handle = table.get(&id).expect("Should still exist");
        assert_eq!(*handle, "hello world");
    }

    #[test]
    fn test_remove() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();
        let id = table.insert_auto("hello".to_string());

        assert!(table.contains(&id));
        assert_eq!(table.len(), 1);

        let removed = table.remove(&id);
        assert_eq!(removed, Some("hello".to_string()));
        assert!(!table.contains(&id));
        assert!(table.is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();
        assert!(table.remove(&999).is_none());
    }

    #[test]
    fn test_clear() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();
        table.insert_auto("a".to_string());
        table.insert_auto("b".to_string());
        table.insert_auto("c".to_string());

        assert_eq!(table.len(), 3);

        table.clear();

        assert!(table.is_empty());
    }

    #[test]
    fn test_retain() {
        let table: HandleTable<u64, i32> = HandleTable::new_auto_id();
        table.insert_auto(1);
        table.insert_auto(2);
        table.insert_auto(3);
        table.insert_auto(4);

        // Keep only even values
        table.retain(|_, v| *v % 2 == 0);

        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_unique_ids() {
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();
        let mut ids = Vec::new();

        for i in 0..100 {
            ids.push(table.insert_auto(format!("file{i}")));
        }

        // All IDs should be unique
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }

    #[test]
    fn test_concurrent_insert() {
        let table = Arc::new(HandleTable::<u64, i32>::new_auto_id());
        let mut handles = vec![];

        for i in 0..10 {
            let table = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                for j in 0..10 {
                    table.insert_auto(i * 10 + j);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(table.len(), 100);
    }

    #[test]
    fn test_concurrent_get_and_remove() {
        let table = Arc::new(HandleTable::<u64, i32>::new_auto_id());

        // Insert some values
        let ids: Vec<u64> = (0..100).map(|i| table.insert_auto(i)).collect();

        let mut handles = vec![];

        // Spawn readers
        for id in ids.iter().take(50) {
            let table = Arc::clone(&table);
            let id = *id;
            handles.push(thread::spawn(move || table.get(&id).map(|r| *r)));
        }

        // Spawn removers
        for id in ids.iter().skip(50) {
            let table = Arc::clone(&table);
            let id = *id;
            handles.push(thread::spawn(move || table.remove(&id)));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_with_capacity() {
        let table: HandleTable<u64, String> = HandleTable::with_capacity(100);
        assert!(table.is_empty());
    }

    #[test]
    fn test_default() {
        let table: HandleTable<String, i32> = HandleTable::default();
        assert!(table.is_empty());
    }

    #[test]
    fn test_insert_overwrites() {
        let table: HandleTable<String, i32> = HandleTable::new();

        table.insert("key".to_string(), 1);
        assert_eq!(*table.get(&"key".to_string()).unwrap(), 1);

        table.insert("key".to_string(), 2);
        assert_eq!(*table.get(&"key".to_string()).unwrap(), 2);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_string_keys() {
        // Verify the WebDAV pattern works well
        let table: HandleTable<String, Vec<u8>> = HandleTable::new();

        table.insert("/path/to/file.txt".to_string(), vec![1, 2, 3]);
        table.insert("/other/file.bin".to_string(), vec![4, 5, 6]);

        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get(&"/path/to/file.txt".to_string()).unwrap().len(),
            3
        );
    }

    #[test]
    fn test_u64_manual_insert() {
        // Can still use manual insert with u64 keys if using new_auto_id
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();

        let id = table.insert_auto("auto".to_string());
        table.insert(999, "manual".to_string());

        assert_eq!(*table.get(&id).unwrap(), "auto");
        assert_eq!(*table.get(&999).unwrap(), "manual");
        assert_eq!(table.len(), 2);
    }

    // ========================================================================
    // Edge case tests targeting specific bug classes
    // ========================================================================

    #[test]
    fn test_id_zero_never_returned() {
        // Bug class: ID 0 is reserved but could be returned after overflow
        // Documents that ID 0 should never be returned in normal usage
        let table: HandleTable<u64, &str> = HandleTable::new_auto_id();

        // Test that normal usage never returns 0
        for _ in 0..1000 {
            let id = table.insert_auto("value");
            assert_ne!(id, 0, "ID 0 should be reserved for invalid handle");
        }
    }

    #[test]
    fn test_id_overflow_guarded() {
        // Force the counter to wrap and ensure we never return 0 or overwrite.
        let mut table: HandleTable<u64, &str> = HandleTable::new_auto_id();

        table.insert(1, "first");
        table.next_id = Some(AtomicU64::new(u64::MAX));

        let max_id = table.insert_auto("max");
        assert_eq!(max_id, u64::MAX);

        let next_id = table.insert_auto("after");
        assert_ne!(next_id, 0);
        assert_eq!(next_id, 2);
        assert_eq!(*table.get(&1).unwrap(), "first");
    }

    #[test]
    fn test_concurrent_get_mut_same_key() {
        // Bug class: Race condition when multiple threads modify same key
        let table = Arc::new(HandleTable::<u64, u64>::new_auto_id());
        let id = table.insert_auto(0);

        let mut handles = vec![];

        // Spawn threads that all increment the same value
        for _ in 0..10 {
            let t = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    if let Some(mut val) = t.get_mut(&id) {
                        *val += 1;
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // All increments should have been applied
        // DashMap's RefMut provides exclusive access
        assert_eq!(
            *table.get(&id).unwrap(),
            1000,
            "All 1000 increments should apply"
        );
    }

    #[test]
    fn test_reuse_removed_key() {
        // Bug class: ABA problem - removed key can be reused
        let table: HandleTable<String, i32> = HandleTable::new();

        table.insert("key".to_string(), 100);
        assert_eq!(*table.get(&"key".to_string()).unwrap(), 100);

        // Remove and verify
        let removed = table.remove(&"key".to_string());
        assert_eq!(removed, Some(100));
        assert!(table.get(&"key".to_string()).is_none());

        // Reinsert with new value
        table.insert("key".to_string(), 200);
        assert_eq!(*table.get(&"key".to_string()).unwrap(), 200);
    }

    #[test]
    fn test_get_mut_nonexistent() {
        // Bug class: get_mut on missing key could panic
        let table: HandleTable<u64, &str> = HandleTable::new_auto_id();

        // Should return None, not panic
        assert!(table.get_mut(&999).is_none());
    }

    #[test]
    fn test_concurrent_insert_remove_stress() {
        // Bug class: Race between insert and remove
        let table = Arc::new(HandleTable::<u64, i32>::new_auto_id());
        let mut handles = vec![];

        // Spawn inserters
        for i in 0..5 {
            let t = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    t.insert_auto(i * 100 + j);
                }
            }));
        }

        // Spawn removers that try to remove IDs 1-100
        for _ in 0..5 {
            let t = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                for id in 1..=100 {
                    t.remove(&id);
                }
            }));
        }

        // All threads should complete without panic or deadlock
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_retain_empty_table() {
        // Bug class: Retain on empty table could panic
        let table: HandleTable<u64, i32> = HandleTable::new_auto_id();

        // Should be a no-op, not panic
        table.retain(|_, _| true);
        assert!(table.is_empty());
    }

    #[test]
    fn test_clear_then_insert() {
        // Bug class: State corruption after clear
        let table: HandleTable<u64, String> = HandleTable::new_auto_id();

        // Insert some values
        let id1 = table.insert_auto("a".to_string());
        let id2 = table.insert_auto("b".to_string());
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        // Clear
        table.clear();
        assert!(table.is_empty());

        // ID counter should continue (not reset)
        let id3 = table.insert_auto("c".to_string());
        assert_eq!(id3, 3, "ID counter should continue after clear");
    }
}
