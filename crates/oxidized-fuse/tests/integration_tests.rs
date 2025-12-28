//! Integration tests for the oxidized-fuse crate.
//!
//! These tests verify the FUSE layer components work correctly together.
//! Note: Actual FUSE mounting requires specific system permissions,
//! so these tests focus on the logical behavior of the components.

use fuser::FileType;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use oxidized_fuse::attr::{AttrCache, DirCache, DirListingEntry};
use oxidized_fuse::error::FuseError;
use oxidized_fuse::inode::{InodeKind, InodeTable, ROOT_INODE};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

/// Creates a test FileAttr for testing.
fn make_test_attr(inode: u64, kind: FileType, size: u64) -> fuser::FileAttr {
    fuser::FileAttr {
        ino: inode,
        size,
        blocks: (size + 511) / 512,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind,
        perm: if kind == FileType::Directory {
            0o755
        } else {
            0o644
        },
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

mod inode_integration {
    use super::*;

    #[test]
    fn test_simulate_directory_traversal() {
        // Simulate: user runs `ls -la /mnt/vault/documents/reports`
        let table = InodeTable::new();
        let cache = AttrCache::with_defaults();

        // Step 1: Lookup "documents" in root
        let doc_path = VaultPath::new("documents");
        let doc_inode = table.get_or_insert(
            doc_path,
            InodeKind::Directory {
                dir_id: DirId::from_raw("doc-uuid"),
            },
        );
        cache.insert(doc_inode, make_test_attr(doc_inode, FileType::Directory, 0));

        // Step 2: Lookup "reports" in documents
        let reports_path = VaultPath::new("documents/reports");
        let reports_inode = table.get_or_insert(
            reports_path,
            InodeKind::Directory {
                dir_id: DirId::from_raw("reports-uuid"),
            },
        );
        cache.insert(
            reports_inode,
            make_test_attr(reports_inode, FileType::Directory, 0),
        );

        // Verify lookups work
        assert!(table.get(ROOT_INODE).is_some());
        assert!(table.get(doc_inode).is_some());
        assert!(table.get(reports_inode).is_some());

        // Verify we can get attributes
        assert!(cache.get(doc_inode).is_some());
        assert!(cache.get(reports_inode).is_some());

        // Verify inode numbers are distinct
        assert_ne!(doc_inode, ROOT_INODE);
        assert_ne!(reports_inode, doc_inode);
    }

    #[test]
    fn test_simulate_file_open_and_close() {
        let table = InodeTable::new();

        // Simulate: open, read, close a file
        let path = VaultPath::new("document.pdf");
        let kind = InodeKind::File {
            dir_id: DirId::root(),
            name: "document.pdf".to_string(),
        };

        // Open: lookup creates inode with nlookup=1
        let inode = table.get_or_insert(path.clone(), kind.clone());
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Another open: nlookup=2
        table.get_or_insert(path.clone(), kind.clone());
        assert_eq!(table.get(inode).unwrap().nlookup(), 2);

        // Close one handle: nlookup=1
        assert!(!table.forget(inode, 1)); // Not evicted
        assert_eq!(table.get(inode).unwrap().nlookup(), 1);

        // Close second handle: nlookup=0, evicted
        assert!(table.forget(inode, 1)); // Evicted
        assert!(table.get(inode).is_none());
    }

    #[test]
    fn test_simulate_rename_operation() {
        let table = InodeTable::new();

        // Create original file
        let old_path = VaultPath::new("old_name.txt");
        let kind = InodeKind::File {
            dir_id: DirId::root(),
            name: "old_name.txt".to_string(),
        };
        let inode = table.get_or_insert(old_path.clone(), kind);

        // Rename: mv old_name.txt new_name.txt
        let new_path = VaultPath::new("new_name.txt");
        table.update_path(inode, &old_path, new_path.clone());

        // Old path no longer resolves
        assert!(table.get_inode(&old_path).is_none());

        // New path resolves to same inode
        assert_eq!(table.get_inode(&new_path), Some(inode));

        // Entry has new path
        let entry = table.get(inode).unwrap();
        assert_eq!(entry.path, new_path);
    }

    #[test]
    fn test_simulate_delete_operation() {
        let table = InodeTable::new();
        let cache = AttrCache::with_defaults();

        // Create file
        let path = VaultPath::new("to_delete.txt");
        let kind = InodeKind::File {
            dir_id: DirId::root(),
            name: "to_delete.txt".to_string(),
        };
        let inode = table.get_or_insert(path.clone(), kind);
        cache.insert(inode, make_test_attr(inode, FileType::RegularFile, 100));

        // Delete: invalidate path (but inode stays until forget)
        table.invalidate_path(&path);
        cache.invalidate(inode);

        // Path no longer resolves
        assert!(table.get_inode(&path).is_none());
        assert!(cache.get(inode).is_none());

        // But inode entry still exists (kernel may still have references)
        assert!(table.get(inode).is_some());

        // After forget, inode is fully removed
        assert!(table.forget(inode, 1));
        assert!(table.get(inode).is_none());
    }

    #[test]
    fn test_symlink_handling() {
        let table = InodeTable::new();

        // Create symlink
        let path = VaultPath::new("link_to_file");
        let kind = InodeKind::Symlink {
            dir_id: DirId::root(),
            name: "link_to_file".to_string(),
        };
        let inode = table.get_or_insert(path, kind);

        let entry = table.get(inode).unwrap();
        assert!(matches!(entry.kind, InodeKind::Symlink { .. }));
        assert_eq!(entry.filename(), Some("link_to_file"));
    }
}

mod cache_integration {
    use super::*;

    #[test]
    fn test_readdir_with_caching() {
        let inode_table = InodeTable::new();
        let attr_cache = AttrCache::with_defaults();
        let dir_cache = DirCache::default();

        // Simulate readdir populating caches
        let entries: Vec<DirListingEntry> = (0..5)
            .map(|i| {
                let name = format!("file_{}.txt", i);
                let path = VaultPath::new(&name);
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: name.clone(),
                };
                let inode = inode_table.get_or_insert(path, kind);
                attr_cache.insert(inode, make_test_attr(inode, FileType::RegularFile, 1024));
                DirListingEntry {
                    inode,
                    file_type: FileType::RegularFile,
                    name,
                }
            })
            .collect();
        dir_cache.insert(ROOT_INODE, entries);

        // Subsequent readdir should hit cache
        let cached_entries = dir_cache.get(ROOT_INODE).unwrap();
        assert_eq!(cached_entries.len(), 5);

        // All attributes should be cached
        for entry in &cached_entries {
            assert!(attr_cache.get(entry.inode).is_some());
        }
    }

    #[test]
    fn test_negative_caching_flow() {
        let cache = AttrCache::with_defaults();

        // First lookup: file doesn't exist
        let parent = ROOT_INODE;
        let name = "nonexistent.txt";

        // Check negative cache (miss initially)
        assert!(!cache.is_negative(parent, name));

        // After ENOENT, add to negative cache
        cache.insert_negative(parent, name.to_string());

        // Subsequent lookups hit negative cache
        assert!(cache.is_negative(parent, name));

        // Create the file: remove from negative cache
        cache.remove_negative(parent, name);
        assert!(!cache.is_negative(parent, name));
    }

    #[test]
    fn test_cache_invalidation_on_write() {
        let attr_cache = AttrCache::with_defaults();
        let dir_cache = DirCache::default();

        let parent_inode = 2u64;
        let file_inode = 3u64;

        // Cache directory listing and file attributes
        dir_cache.insert(
            parent_inode,
            vec![DirListingEntry {
                inode: file_inode,
                file_type: FileType::RegularFile,
                name: "file.txt".to_string(),
            }],
        );
        attr_cache.insert(
            file_inode,
            make_test_attr(file_inode, FileType::RegularFile, 100),
        );

        // Write to file: invalidate attr (size changed)
        attr_cache.invalidate(file_inode);
        assert!(attr_cache.get(file_inode).is_none());

        // Create new file: invalidate directory cache
        dir_cache.invalidate(parent_inode);
        assert!(dir_cache.get(parent_inode).is_none());
    }
}

mod concurrent_access {
    use super::*;

    #[test]
    fn test_concurrent_inode_allocation() {
        let table = Arc::new(InodeTable::new());
        let mut handles = vec![];

        // 10 threads each allocating 100 inodes
        for t in 0..10 {
            let table = Arc::clone(&table);
            handles.push(thread::spawn(move || {
                let mut inodes = vec![];
                for i in 0..100 {
                    let path = VaultPath::new(format!("thread_{}_file_{}", t, i));
                    let kind = InodeKind::File {
                        dir_id: DirId::from_raw(format!("dir-{}", t)),
                        name: format!("file_{}", i),
                    };
                    inodes.push(table.get_or_insert(path, kind));
                }
                inodes
            }));
        }

        // Collect all inodes
        let all_inodes: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        // All 1000 inodes should be unique (plus root)
        let mut sorted = all_inodes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 1000);

        // Table should have 1001 entries (root + 1000 files)
        assert_eq!(table.len(), 1001);
    }

    #[test]
    fn test_concurrent_cache_access() {
        let cache = Arc::new(AttrCache::with_defaults());
        let mut handles = vec![];

        // Writers
        for t in 0..5 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let inode = (t * 100 + i) as u64;
                    cache.insert(inode, make_test_attr(inode, FileType::RegularFile, 100));
                }
            }));
        }

        // Readers
        for _ in 0..5 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for i in 0..500 {
                    let _ = cache.get(i);
                }
            }));
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All writes should have succeeded
        assert_eq!(cache.len(), 500);
    }

    #[test]
    fn test_concurrent_lookup_and_forget() {
        let table = Arc::new(InodeTable::new());

        // Pre-populate with high nlookup count to survive concurrent forgets
        let inodes: Vec<u64> = (0..100)
            .map(|i| {
                let path = VaultPath::new(format!("file_{}", i));
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: format!("file_{}", i),
                };
                let inode = table.get_or_insert(path.clone(), kind.clone());
                // Increase nlookup to 10 so forgets don't evict
                for _ in 0..9 {
                    table.get_or_insert(path.clone(), kind.clone());
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

mod error_handling {
    use super::*;

    #[test]
    fn test_fuse_error_variants() {
        // Verify all error variants have correct errno mappings
        let errors = [
            (FuseError::InvalidInode(1), libc::ENOENT),
            (FuseError::InvalidHandle(1), libc::EBADF),
            (FuseError::WrongHandleType, libc::EBADF),
            (
                FuseError::PathResolution("path".to_string()),
                libc::ENOENT,
            ),
            (
                FuseError::AlreadyExists("file".to_string()),
                libc::EEXIST,
            ),
            (FuseError::NotEmpty("dir".to_string()), libc::ENOTEMPTY),
            (FuseError::NotSupported, libc::ENOTSUP),
        ];

        for (error, expected_errno) in errors {
            assert_eq!(
                error.to_errno(),
                expected_errno,
                "Error {:?} should map to {}",
                error,
                expected_errno
            );
        }
    }

    #[test]
    fn test_io_error_passthrough() {
        use std::io;

        let io_err = io::Error::from_raw_os_error(libc::ENOSPC);
        let fuse_err = FuseError::Io(io_err);
        assert_eq!(fuse_err.to_errno(), libc::ENOSPC);
    }
}

mod edge_cases {
    use super::*;

    #[test]
    fn test_root_inode_special_handling() {
        let table = InodeTable::new();

        // Root should always exist
        assert!(table.get(ROOT_INODE).is_some());

        // Root should never be evicted
        assert!(!table.forget(ROOT_INODE, 1000));
        assert!(table.get(ROOT_INODE).is_some());

        // Root has special InodeKind
        let root = table.get(ROOT_INODE).unwrap();
        assert!(matches!(root.kind, InodeKind::Root));
        assert_eq!(root.dir_id(), Some(DirId::root()));
    }

    #[test]
    fn test_very_long_path() {
        let table = InodeTable::new();

        // Create a very deep path (100 levels)
        let path_parts: Vec<String> = (0..100).map(|i| format!("dir_{}", i)).collect();
        let long_path = VaultPath::new(path_parts.join("/"));

        let kind = InodeKind::File {
            dir_id: DirId::from_raw("deep-dir"),
            name: "file.txt".to_string(),
        };
        let inode = table.get_or_insert(long_path.clone(), kind);

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
            let inode = table.get_or_insert(path.clone(), kind);

            let entry = table.get(inode).unwrap();
            assert_eq!(entry.filename(), Some(name));
        }
    }

    #[test]
    fn test_empty_directory_cache() {
        let cache = DirCache::default();

        // Empty directory should be cacheable
        cache.insert(42, vec![]);

        let entries = cache.get(42).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_cache_ttl_boundary() {
        let cache = AttrCache::new(Duration::from_millis(100), Duration::from_millis(50));

        cache.insert(1, make_test_attr(1, FileType::RegularFile, 100));

        // Should be valid immediately
        assert!(cache.get(1).is_some());

        // Should still be valid just before TTL
        thread::sleep(Duration::from_millis(50));
        assert!(cache.get(1).is_some());

        // Should be invalid after TTL
        thread::sleep(Duration::from_millis(60));
        assert!(cache.get(1).is_none());
    }
}
