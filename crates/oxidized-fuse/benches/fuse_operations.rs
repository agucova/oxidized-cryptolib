//! Benchmarks for critical path operations in the FUSE filesystem.
//!
//! These benchmarks measure the performance of the most frequently called
//! operations in the FUSE layer:
//! - Inode table lookups and allocations
//! - Attribute cache operations
//! - Directory cache operations

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use fuser::FileType;
use oxidized_cryptolib::vault::path::{DirId, VaultPath};
use oxidized_fuse::attr::{AttrCache, DirCache, DirListingEntry};
use oxidized_fuse::inode::{InodeKind, InodeTable, ROOT_INODE};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

fn make_test_attr(inode: u64) -> fuser::FileAttr {
    fuser::FileAttr {
        ino: inode,
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

/// Benchmarks for InodeTable operations
fn inode_table_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("inode_table");

    // Benchmark: get_or_insert for new paths (allocation)
    group.bench_function("allocate_new_inode", |b| {
        let table = InodeTable::new();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let path = VaultPath::new(format!("file_{}", counter));
            let kind = InodeKind::File {
                dir_id: DirId::root(),
                name: format!("file_{}", counter),
            };
            black_box(table.get_or_insert(path, kind))
        });
    });

    // Benchmark: get_or_insert for existing paths (lookup + nlookup increment)
    group.bench_function("lookup_existing_inode", |b| {
        let table = InodeTable::new();
        let path = VaultPath::new("existing_file");
        let kind = InodeKind::File {
            dir_id: DirId::root(),
            name: "existing_file".to_string(),
        };
        table.get_or_insert(path.clone(), kind.clone());

        b.iter(|| black_box(table.get_or_insert(path.clone(), kind.clone())));
    });

    // Benchmark: get by inode number
    group.bench_function("get_by_inode", |b| {
        let table = InodeTable::new();
        let path = VaultPath::new("test_file");
        let kind = InodeKind::File {
            dir_id: DirId::root(),
            name: "test_file".to_string(),
        };
        let inode = table.get_or_insert(path, kind);

        b.iter(|| black_box(table.get(inode)));
    });

    // Benchmark: get root inode (most frequently accessed)
    group.bench_function("get_root_inode", |b| {
        let table = InodeTable::new();
        b.iter(|| black_box(table.get(ROOT_INODE)));
    });

    // Benchmark: get_inode by path
    group.bench_function("get_inode_by_path", |b| {
        let table = InodeTable::new();
        let path = VaultPath::new("test_file");
        let kind = InodeKind::File {
            dir_id: DirId::root(),
            name: "test_file".to_string(),
        };
        table.get_or_insert(path.clone(), kind);

        b.iter(|| black_box(table.get_inode(&path)));
    });

    // Benchmark: forget operation (nlookup decrement without eviction)
    group.bench_function("forget_partial", |b| {
        b.iter_batched(
            || {
                let table = InodeTable::new();
                let path = VaultPath::new("temp_file");
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: "temp_file".to_string(),
                };
                let inode = table.get_or_insert(path.clone(), kind.clone());
                // Increment nlookup so forget won't evict
                table.get_or_insert(path, kind);
                (table, inode)
            },
            |(table, inode)| black_box(table.forget(inode, 1)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark: concurrent access simulation
    group.bench_function("concurrent_lookup", |b| {
        let table = Arc::new(InodeTable::new());
        // Pre-populate with some entries
        for i in 0..100 {
            let path = VaultPath::new(format!("file_{}", i));
            let kind = InodeKind::File {
                dir_id: DirId::root(),
                name: format!("file_{}", i),
            };
            table.get_or_insert(path, kind);
        }

        b.iter(|| {
            // Simulate random lookups
            for i in 0..10 {
                let path = VaultPath::new(format!("file_{}", i * 10));
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: format!("file_{}", i * 10),
                };
                black_box(table.get_or_insert(path, kind));
            }
        });
    });

    group.finish();
}

/// Benchmarks for AttrCache operations
fn attr_cache_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_cache");

    // Benchmark: insert new attribute
    group.bench_function("insert", |b| {
        let cache = AttrCache::with_defaults();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            black_box(cache.insert(counter, make_test_attr(counter)));
        });
    });

    // Benchmark: get cached attribute (hit)
    group.bench_function("get_hit", |b| {
        let cache = AttrCache::with_defaults();
        cache.insert(42, make_test_attr(42));

        b.iter(|| black_box(cache.get(42)));
    });

    // Benchmark: get non-existent attribute (miss)
    group.bench_function("get_miss", |b| {
        let cache = AttrCache::with_defaults();
        b.iter(|| black_box(cache.get(99999)));
    });

    // Benchmark: invalidate
    group.bench_function("invalidate", |b| {
        b.iter_batched(
            || {
                let cache = AttrCache::with_defaults();
                cache.insert(42, make_test_attr(42));
                cache
            },
            |cache| black_box(cache.invalidate(42)),
            BatchSize::SmallInput,
        );
    });

    // Benchmark: negative cache insert
    group.bench_function("insert_negative", |b| {
        let cache = AttrCache::with_defaults();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            black_box(cache.insert_negative(1, format!("missing_{}", counter)));
        });
    });

    // Benchmark: negative cache check (hit)
    group.bench_function("is_negative_hit", |b| {
        let cache = AttrCache::with_defaults();
        cache.insert_negative(1, "missing".to_string());

        b.iter(|| black_box(cache.is_negative(1, "missing")));
    });

    // Benchmark: negative cache check (miss)
    group.bench_function("is_negative_miss", |b| {
        let cache = AttrCache::with_defaults();
        b.iter(|| black_box(cache.is_negative(1, "not_there")));
    });

    // Benchmark: concurrent access
    group.bench_function("concurrent_access", |b| {
        let cache = Arc::new(AttrCache::with_defaults());
        // Pre-populate
        for i in 0..100 {
            cache.insert(i, make_test_attr(i));
        }

        b.iter(|| {
            for i in 0..10 {
                black_box(cache.get(i * 10));
            }
        });
    });

    group.finish();
}

/// Benchmarks for DirCache operations
fn dir_cache_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("dir_cache");

    fn make_entries(count: usize) -> Vec<DirListingEntry> {
        (0..count)
            .map(|i| DirListingEntry {
                inode: (i + 2) as u64,
                file_type: if i % 5 == 0 {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                name: format!("entry_{}", i),
            })
            .collect()
    }

    // Benchmark: insert directory listing (10 entries)
    group.throughput(Throughput::Elements(10));
    group.bench_function("insert_10_entries", |b| {
        let cache = DirCache::default();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            black_box(cache.insert(counter, make_entries(10)));
        });
    });

    // Benchmark: insert directory listing (100 entries)
    group.throughput(Throughput::Elements(100));
    group.bench_function("insert_100_entries", |b| {
        let cache = DirCache::default();
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            black_box(cache.insert(counter, make_entries(100)));
        });
    });

    // Reset throughput
    group.throughput(Throughput::Elements(1));

    // Benchmark: get directory listing (hit)
    group.bench_function("get_hit", |b| {
        let cache = DirCache::default();
        cache.insert(1, make_entries(50));

        b.iter(|| black_box(cache.get(1)));
    });

    // Benchmark: get directory listing (miss)
    group.bench_function("get_miss", |b| {
        let cache = DirCache::default();
        b.iter(|| black_box(cache.get(99999)));
    });

    // Benchmark: invalidate
    group.bench_function("invalidate", |b| {
        b.iter_batched(
            || {
                let cache = DirCache::default();
                cache.insert(1, make_entries(50));
                cache
            },
            |cache| black_box(cache.invalidate(1)),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmarks simulating real FUSE operation patterns
fn realistic_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_patterns");

    // Simulate: readdir + lookup for each entry
    group.bench_function("readdir_then_lookup", |b| {
        let inode_table = InodeTable::new();
        let attr_cache = AttrCache::with_defaults();
        let dir_cache = DirCache::default();

        // Prepare a directory with entries
        let entries: Vec<DirListingEntry> = (0..20)
            .map(|i| {
                let name = format!("file_{}", i);
                let path = VaultPath::new(&name);
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: name.clone(),
                };
                let inode = inode_table.get_or_insert(path, kind);
                attr_cache.insert(inode, make_test_attr(inode));
                DirListingEntry {
                    inode,
                    file_type: FileType::RegularFile,
                    name,
                }
            })
            .collect();
        dir_cache.insert(ROOT_INODE, entries);

        b.iter(|| {
            // Get directory listing
            if let Some(entries) = dir_cache.get(ROOT_INODE) {
                // Lookup each entry (simulating stat)
                for entry in entries.iter() {
                    black_box(attr_cache.get(entry.inode));
                    black_box(inode_table.get(entry.inode));
                }
            }
        });
    });

    // Simulate: path traversal (e.g., /a/b/c/file.txt)
    group.bench_function("path_traversal_4_levels", |b| {
        let inode_table = InodeTable::new();
        let attr_cache = AttrCache::with_defaults();

        // Set up a 4-level path
        let components = ["dir1", "dir2", "dir3", "file.txt"];
        let mut inodes = vec![];

        for (i, name) in components.iter().enumerate() {
            let path = VaultPath::new(components[..=i].join("/"));
            let kind = if i < 3 {
                InodeKind::Directory {
                    dir_id: DirId::from_raw(format!("dir-{}", i)),
                }
            } else {
                InodeKind::File {
                    dir_id: DirId::from_raw("dir-2"),
                    name: name.to_string(),
                }
            };
            let inode = inode_table.get_or_insert(path, kind);
            attr_cache.insert(inode, make_test_attr(inode));
            inodes.push(inode);
        }

        b.iter(|| {
            // Traverse the path
            for inode in &inodes {
                black_box(inode_table.get(*inode));
                black_box(attr_cache.get(*inode));
            }
        });
    });

    // Simulate: many file opens in same directory
    group.bench_function("batch_open_same_dir", |b| {
        let inode_table = InodeTable::new();
        let attr_cache = AttrCache::with_defaults();

        // Pre-create 100 files
        let inodes: Vec<u64> = (0..100)
            .map(|i| {
                let path = VaultPath::new(format!("file_{}.txt", i));
                let kind = InodeKind::File {
                    dir_id: DirId::root(),
                    name: format!("file_{}.txt", i),
                };
                let inode = inode_table.get_or_insert(path, kind);
                attr_cache.insert(inode, make_test_attr(inode));
                inode
            })
            .collect();

        b.iter(|| {
            // Look up each file (simulating open)
            for inode in &inodes {
                black_box(inode_table.get(*inode));
                black_box(attr_cache.get(*inode));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    inode_table_benchmarks,
    attr_cache_benchmarks,
    dir_cache_benchmarks,
    realistic_patterns,
);
criterion_main!(benches);
