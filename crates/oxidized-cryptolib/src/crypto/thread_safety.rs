//! Thread safety implementations for cryptographic types.
//!
//! This module provides the `unsafe impl Send` and `unsafe impl Sync` for `MasterKey`.
//! These implementations are sound because:
//!
//! 1. **RwLock protection**: All access to the underlying `MemSafe` data goes through
//!    `RwLock`, which provides proper synchronization.
//!
//! 2. **No concurrent raw pointer access**: The raw pointer in `MemSafe` is only used
//!    for memory protection operations (mlock, mprotect), which are thread-safe at the OS level.
//!    The actual data access goes through the `MemSafe::read()` method which the RwLock protects.
//!
//! 3. **No data races**: The RwLock ensures that:
//!    - Multiple readers can access concurrently (via `read()`)
//!    - Writers get exclusive access (via `write()`)
//!    - The raw pointer is never dereferenced without holding the lock
//!
//! # Safety Rationale
//!
//! The `MemSafe` type from the `memsafe` crate contains a raw pointer (`*mut T`) because
//! it manages memory protection at the OS level. This raw pointer prevents automatic
//! `Send` and `Sync` implementations. However, our usage is safe because:
//!
//! - We wrap each `MemSafe` in an `RwLock` to synchronize all access
//! - The memory protection operations (`mlock`, `mprotect`, `MADV_DONTDUMP`) are
//!   themselves thread-safe system calls
//! - We never expose the raw pointer or create aliased references to the protected memory

use super::keys::MasterKey;

// SAFETY: MasterKey can be sent between threads because:
// - All fields are wrapped in RwLock which synchronizes access
// - The underlying MemSafe's raw pointer points to memory that is valid
//   regardless of which thread accesses it
// - Memory protection operations (mlock, mprotect) are thread-safe
unsafe impl Send for MasterKey {}

// SAFETY: MasterKey can be shared between threads because:
// - All access to the key material goes through RwLock::read() or RwLock::write()
// - RwLock ensures no data races can occur
// - The raw pointer in MemSafe is never accessed without holding the lock
// - This is exactly what RwLock is designed to protect
unsafe impl Sync for MasterKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn master_key_is_send() {
        assert_send::<MasterKey>();
    }

    #[test]
    fn master_key_is_sync() {
        assert_sync::<MasterKey>();
    }

    #[test]
    fn arc_master_key_is_send() {
        assert_send::<Arc<MasterKey>>();
    }

    #[test]
    fn can_share_across_threads() {
        let key = MasterKey::generate().expect("generate key");
        let key = Arc::new(key);

        let key1 = Arc::clone(&key);
        let key2 = Arc::clone(&key);

        let handle1 = thread::spawn(move || {
            key1.with_aes_key(|k| k[0]).expect("access key")
        });

        let handle2 = thread::spawn(move || {
            key2.with_mac_key(|k| k[0]).expect("access key")
        });

        let _result1 = handle1.join().expect("thread 1");
        let _result2 = handle2.join().expect("thread 2");
    }

    #[test]
    fn concurrent_reads() {
        let key = MasterKey::generate().expect("generate key");
        let key = Arc::new(key);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let key = Arc::clone(&key);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    key.with_aes_key(|k| k[0]).expect("access key");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread completed");
        }
    }
}
