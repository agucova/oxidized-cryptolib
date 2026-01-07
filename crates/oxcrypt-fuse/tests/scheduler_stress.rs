//! Stress tests for the FUSE scheduler.
//!
//! These tests exercise the scheduler components under high concurrency
//! to verify correctness and detect race conditions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use oxcrypt_fuse::scheduler::{
    DeadlineHeap, PerFileOrdering, ReadCacheKey, ReadCache, ReadCacheConfig,
    RequestIdGenerator, RequestState, SchedulerStats,
    InFlightReads, ReadKey, AttachResult,
};

/// Number of threads for concurrent tests.
const THREAD_COUNT: usize = 8;

/// Number of operations per thread.
const OPS_PER_THREAD: usize = 1000;

// ============================================================================
// RequestState Stress Tests
// ============================================================================

#[test]
fn stress_request_state_claim_reply() {
    // Verify exactly-once semantics under high contention
    let state = Arc::new(RequestState::new());
    let success_count = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|_| {
            let state = Arc::clone(&state);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..OPS_PER_THREAD {
                    // Reset for each iteration by creating new state
                    // (can't reset AtomicBool, so we test single claim per state)
                }
                // Try to claim once
                if state.claim_reply() {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Exactly one thread should have succeeded
    assert_eq!(success_count.load(Ordering::Relaxed), 1);
}

#[test]
fn stress_request_state_many_instances() {
    // Test many RequestState instances concurrently
    let states: Vec<_> = (0..OPS_PER_THREAD)
        .map(|_| Arc::new(RequestState::new()))
        .collect();

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let states = states.clone();
            thread::spawn(move || {
                let mut claimed = 0u64;
                for (i, state) in states.iter().enumerate() {
                    // Each thread tries different states
                    if (i % THREAD_COUNT) == thread_id && state.claim_reply() {
                        claimed += 1;
                    }
                }
                claimed
            })
        })
        .collect();

    let total_claimed: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();

    // Each state should be claimed exactly once
    assert_eq!(total_claimed, OPS_PER_THREAD as u64);
}

// ============================================================================
// DeadlineHeap Stress Tests
// ============================================================================

#[test]
fn stress_deadline_heap_concurrent_insert_pop() {
    let heap = Arc::new(DeadlineHeap::new());
    let id_gen = Arc::new(RequestIdGenerator::new());
    let inserted = Arc::new(AtomicU64::new(0));
    let popped = Arc::new(AtomicU64::new(0));

    // Half threads insert, half threads pop
    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let heap = Arc::clone(&heap);
            let id_gen = Arc::clone(&id_gen);
            let inserted = Arc::clone(&inserted);
            let popped = Arc::clone(&popped);

            thread::spawn(move || {
                if thread_id % 2 == 0 {
                    // Insert thread - use very short deadlines
                    for _ in 0..OPS_PER_THREAD {
                        let id = id_gen.next();
                        let deadline = Instant::now() + Duration::from_nanos(1);
                        let _ = heap.insert(id, deadline);
                        inserted.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // Pop thread
                    thread::sleep(Duration::from_millis(10)); // Let some inserts happen
                    for _ in 0..OPS_PER_THREAD {
                        let expired = heap.pop_expired();
                        popped.fetch_add(expired.len() as u64, Ordering::Relaxed);
                        thread::yield_now();
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Drain remaining
    loop {
        let expired = heap.pop_expired();
        if expired.is_empty() {
            break;
        }
        popped.fetch_add(expired.len() as u64, Ordering::Relaxed);
    }

    // All inserted should eventually be popped
    let total_inserted = inserted.load(Ordering::Relaxed);
    let total_popped = popped.load(Ordering::Relaxed);
    assert_eq!(total_inserted, total_popped, "inserted={total_inserted}, popped={total_popped}");
}

#[test]
fn stress_deadline_heap_ordering() {
    // Verify deadlines are returned in order
    let heap = DeadlineHeap::new();
    let id_gen = RequestIdGenerator::new();
    let base = Instant::now();

    // Insert in random order
    let mut ids_and_deadlines: Vec<_> = (0..1000)
        .map(|i| {
            let id = id_gen.next();
            // Spread deadlines over 100ms
            let offset = Duration::from_micros((i * 100) as u64);
            (id, base + offset)
        })
        .collect();

    // Shuffle (simple reversal)
    ids_and_deadlines.reverse();

    for (id, deadline) in &ids_and_deadlines {
        let _ = heap.insert(*id, *deadline);
    }

    // Wait for all to expire
    thread::sleep(Duration::from_millis(150));

    // Pop all and verify ordering
    let mut last_id = 0u64;
    loop {
        let expired = heap.pop_expired();
        if expired.is_empty() {
            break;
        }
        for (id, _generation) in expired {
            // IDs should come out in roughly increasing order
            // (they were inserted with deadlines proportional to ID)
            assert!(id.raw() > last_id.saturating_sub(10), "out of order: {} after {}", id.raw(), last_id);
            last_id = id.raw();
        }
    }
}

// ============================================================================
// PerFileOrdering Stress Tests
// ============================================================================

#[test]
fn stress_per_file_ordering_single_file() {
    // Many threads competing for a single file
    let ordering = Arc::new(PerFileOrdering::new());
    let id_gen = Arc::new(RequestIdGenerator::new());
    let completed = Arc::new(AtomicU64::new(0));
    let inode = 1u64;

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|_| {
            let ordering = Arc::clone(&ordering);
            let id_gen = Arc::clone(&id_gen);
            let completed = Arc::clone(&completed);

            thread::spawn(move || {
                for _ in 0..OPS_PER_THREAD {
                    let id = id_gen.next();

                    // Try to start operation
                    match ordering.try_start(inode, id) {
                        Ok(None) => {
                            // Got immediate access - do work and complete
                            thread::yield_now(); // Simulate work
                            ordering.complete(inode, None);
                            completed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Some(mut rx)) => {
                            // Wait for turn (with timeout to prevent deadlock in test)
                            let start = Instant::now();
                            while start.elapsed() < Duration::from_secs(1) {
                                if rx.try_recv().is_ok() {
                                    thread::yield_now(); // Simulate work
                                    ordering.complete(inode, None);
                                    completed.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                thread::yield_now();
                            }
                        }
                        Err(_) => {
                            // Error propagation case - skip
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let total = completed.load(Ordering::Relaxed);
    let expected = (THREAD_COUNT * OPS_PER_THREAD) as u64;
    assert!(
        total > expected / 2,
        "too few completions: {total} < {}", expected / 2
    );
}

#[test]
fn stress_per_file_ordering_many_files() {
    // Many threads, many files - should have minimal contention
    let ordering = Arc::new(PerFileOrdering::new());
    let id_gen = Arc::new(RequestIdGenerator::new());
    let completed = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let ordering = Arc::clone(&ordering);
            let id_gen = Arc::clone(&id_gen);
            let completed = Arc::clone(&completed);

            thread::spawn(move || {
                for i in 0..OPS_PER_THREAD {
                    // Each thread works on different files
                    let inode = (thread_id * OPS_PER_THREAD + i) as u64;
                    let id = id_gen.next();

                    match ordering.try_start(inode, id) {
                        Ok(None) => {
                            ordering.complete(inode, None);
                            completed.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Some(_)) => {
                            // Shouldn't happen with unique inodes
                            panic!("unexpected wait on unique inode");
                        }
                        Err(_) => {}
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // All should complete since each file is unique
    let total = completed.load(Ordering::Relaxed);
    let expected = (THREAD_COUNT * OPS_PER_THREAD) as u64;
    assert_eq!(total, expected);
}

// ============================================================================
// ReadCache Stress Tests
// ============================================================================

#[test]
fn stress_read_cache_concurrent_access() {
    let config = ReadCacheConfig {
        max_bytes: 10 * 1024 * 1024, // 10 MiB
        ttl: Duration::from_secs(60),
    };
    let cache = Arc::new(ReadCache::with_config(config));

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let cache = Arc::clone(&cache);

            thread::spawn(move || {
                for i in 0..OPS_PER_THREAD {
                    let inode = (i % 100) as u64; // Reuse inodes for cache hits
                    let offset = (i * 4096) as u64;
                    let data_size = 4096;
                    let key = ReadCacheKey::new(inode, offset, data_size);

                    // Mix of reads and writes
                    if thread_id % 2 == 0 {
                        // Write thread
                        let data = bytes::Bytes::from(vec![thread_id as u8; data_size]);
                        cache.insert(key, data);
                    } else {
                        // Read thread
                        let _ = cache.get(&key);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify cache stats are reasonable
    let stats = cache.stats();
    let hits = stats.hits.load(Ordering::Relaxed);
    let misses = stats.misses.load(Ordering::Relaxed);
    let inserts = stats.inserts.load(Ordering::Relaxed);

    assert!(inserts > 0, "no inserts recorded");
    assert!(hits + misses > 0, "no reads recorded");
}

#[test]
fn stress_read_cache_eviction() {
    // Small cache to force eviction
    let config = ReadCacheConfig {
        max_bytes: 64 * 1024, // 64 KiB
        ttl: Duration::from_secs(60),
    };
    let cache = Arc::new(ReadCache::with_config(config));

    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let cache = Arc::clone(&cache);

            thread::spawn(move || {
                for i in 0..1000 {
                    let inode = (thread_id * 1000 + i) as u64;
                    let data_size = 1024;
                    let key = ReadCacheKey::new(inode, 0, data_size);
                    let data = bytes::Bytes::from(vec![0u8; data_size]); // 1 KiB each
                    cache.insert(key, data);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Cache should stay bounded (allow some slack for Moka's async eviction)
    let size = cache.weighted_size();
    assert!(
        size <= 128 * 1024, // Allow 2x for eviction lag
        "cache exceeded bounds: {} bytes", size
    );
}

// ============================================================================
// InFlightReads (Single-Flight) Stress Tests
// ============================================================================

#[test]
fn stress_single_flight_deduplication() {
    let in_flight = Arc::new(InFlightReads::new());
    let leaders = Arc::new(AtomicU64::new(0));
    let waiters = Arc::new(AtomicU64::new(0));

    // All threads try to read the same key
    let key = ReadKey::new(1, 0, 4096);

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|_| {
            let in_flight = Arc::clone(&in_flight);
            let leaders = Arc::clone(&leaders);
            let waiters = Arc::clone(&waiters);

            thread::spawn(move || {
                match in_flight.try_attach(key) {
                    AttachResult::Leader => {
                        leaders.fetch_add(1, Ordering::Relaxed);
                        // Simulate work
                        thread::sleep(Duration::from_millis(10));
                        in_flight.complete(&key, Ok(bytes::Bytes::from_static(b"data")));
                    }
                    AttachResult::Waiter(_rx) => {
                        waiters.fetch_add(1, Ordering::Relaxed);
                        // In real use, would wait on rx
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Exactly one leader
    assert_eq!(leaders.load(Ordering::Relaxed), 1);
    // Rest are waiters
    assert_eq!(waiters.load(Ordering::Relaxed), (THREAD_COUNT - 1) as u64);
}

#[test]
fn stress_single_flight_many_keys() {
    let in_flight = Arc::new(InFlightReads::new());
    let total_leaders = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let in_flight = Arc::clone(&in_flight);
            let total_leaders = Arc::clone(&total_leaders);

            thread::spawn(move || {
                for i in 0..OPS_PER_THREAD {
                    // Unique key per operation
                    let key = ReadKey::new(thread_id as u64, i as u64, 4096);

                    match in_flight.try_attach(key) {
                        AttachResult::Leader => {
                            total_leaders.fetch_add(1, Ordering::Relaxed);
                            in_flight.complete(&key, Ok(bytes::Bytes::from_static(b"data")));
                        }
                        AttachResult::Waiter(_) => {
                            // Shouldn't happen with unique keys
                            panic!("unexpected waiter on unique key");
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // All should be leaders with unique keys
    let total = total_leaders.load(Ordering::Relaxed);
    let expected = (THREAD_COUNT * OPS_PER_THREAD) as u64;
    assert_eq!(total, expected);
}

// ============================================================================
// SchedulerStats Stress Tests
// ============================================================================

#[test]
fn stress_scheduler_stats_concurrent_updates() {
    let stats = Arc::new(SchedulerStats::new());

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let stats = Arc::clone(&stats);

            thread::spawn(move || {
                for _ in 0..OPS_PER_THREAD {
                    stats.record_accept();
                    if thread_id % 3 == 0 {
                        stats.record_reject(thread_id % 5);
                    }
                    if thread_id % 5 == 0 {
                        stats.record_timeout();
                    }
                    stats.inc_in_flight(thread_id % 5);
                    stats.dec_in_flight(thread_id % 5);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    // Verify counts are consistent
    let accepted = stats.requests_accepted.load(Ordering::Relaxed);
    let expected_accepted = (THREAD_COUNT * OPS_PER_THREAD) as u64;
    assert_eq!(accepted, expected_accepted);

    // In-flight should be zero (all inc/dec paired)
    assert_eq!(stats.total_in_flight(), 0);
}

// ============================================================================
// Mixed Workload Test
// ============================================================================

#[test]
fn stress_mixed_workload() {
    // Simulate realistic mixed operations
    let ordering = Arc::new(PerFileOrdering::new());
    let cache = Arc::new(ReadCache::with_config(ReadCacheConfig {
        max_bytes: 10 * 1024 * 1024,
        ttl: Duration::from_secs(60),
    }));
    let in_flight = Arc::new(InFlightReads::new());
    let stats = Arc::new(SchedulerStats::new());
    let id_gen = Arc::new(RequestIdGenerator::new());

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|thread_id| {
            let ordering = Arc::clone(&ordering);
            let cache = Arc::clone(&cache);
            let in_flight = Arc::clone(&in_flight);
            let stats = Arc::clone(&stats);
            let id_gen = Arc::clone(&id_gen);

            thread::spawn(move || {
                for i in 0..OPS_PER_THREAD {
                    let op_type = i % 4;

                    match op_type {
                        0 => {
                            // Cache read
                            let key = ReadCacheKey::new(i as u64, 0, 1024);
                            let _ = cache.get(&key);
                            stats.record_accept();
                        }
                        1 => {
                            // Cache write
                            let key = ReadCacheKey::new(i as u64, 0, 1024);
                            cache.insert(key, bytes::Bytes::from(vec![0u8; 1024]));
                            stats.record_accept();
                        }
                        2 => {
                            // Single-flight dedup
                            let key = ReadKey::new((i % 10) as u64, 0, 4096);
                            match in_flight.try_attach(key) {
                                AttachResult::Leader => {
                                    thread::yield_now();
                                    in_flight.complete(&key, Ok(bytes::Bytes::from_static(b"data")));
                                }
                                AttachResult::Waiter(_) => {}
                            }
                            stats.record_accept();
                        }
                        3 => {
                            // Per-file ordering
                            let inode = (thread_id * 10 + (i % 10)) as u64;
                            let req_id = id_gen.next();
                            if let Ok(None) = ordering.try_start(inode, req_id) {
                                thread::yield_now();
                                ordering.complete(inode, None);
                            }
                            stats.record_accept();
                        }
                        _ => unreachable!(),
                    }
                }
            })
        })
        .collect();

    let start = Instant::now();

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed = start.elapsed();
    let total_ops = (THREAD_COUNT * OPS_PER_THREAD) as u64;

    // Should complete in reasonable time (< 10s for 8000 ops)
    assert!(
        elapsed < Duration::from_secs(10),
        "mixed workload too slow: {:?}", elapsed
    );

    // All operations should be recorded
    let accepted = stats.requests_accepted.load(Ordering::Relaxed);
    assert_eq!(accepted, total_ops);

    println!(
        "Mixed workload: {} ops in {:?} ({:.0} ops/sec)",
        total_ops,
        elapsed,
        total_ops as f64 / elapsed.as_secs_f64()
    );
}
