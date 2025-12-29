//! Concurrent Editor Workload
//!
//! Simulates multiple processes accessing vault simultaneously:
//! - Editor: continuous read-modify-write
//! - File watcher: periodic stat storms
//! - Build process: periodic full reads + writes
//! - Terminal: random reads and directory listings
//!
//! Tests cache coherency, concurrent metadata access, and write invalidation visibility.

use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::Result;
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const NUM_FILES: usize = 30;
const EDITOR_HOT_FILES: usize = 3;
const OUTPUT_FILES: usize = 5;
const WORKLOAD_DURATION: Duration = Duration::from_secs(30);

/// Dynamic thread count based on available CPU cores.
fn thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get().clamp(2, 8))
        .unwrap_or(4)
}

/// Concurrent Editor Workload.
///
/// Spawns multiple threads simulating different application behaviors:
/// - Thread 1 (Editor): Continuous read-modify-write on 3 hot files
/// - Thread 2 (File watcher): Stat all files periodically
/// - Thread 3 (Build process): Periodic full reads + output writes
/// - Thread 4 (Terminal): Random file reads and directory listings
pub struct ConcurrentWorkload {
    seed: u64,
}

impl ConcurrentWorkload {
    pub fn new() -> Self {
        Self { seed: 0xC0_C0 }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_concurrent_workload")
    }

    fn source_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("src")
    }

    fn output_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("output")
    }

    fn file_path(&self, mount_point: &Path, index: usize) -> PathBuf {
        self.source_dir(mount_point)
            .join(format!("source_{:03}.txt", index))
    }

    #[allow(dead_code)]
    fn output_path(&self, mount_point: &Path, index: usize) -> PathBuf {
        self.output_dir(mount_point)
            .join(format!("output_{:03}.o", index))
    }

    /// Generate initial file content.
    fn generate_content(&self, rng: &mut ChaCha8Rng, index: usize) -> Vec<u8> {
        let size = 5 * 1024 + rng.random_range(0..10 * 1024); // 5KB-15KB
        let mut content = Vec::with_capacity(size);

        writeln!(content, "// Source file {}", index).unwrap();
        writeln!(content, "// Version: 1").unwrap();
        writeln!(content).unwrap();

        while content.len() < size {
            let line: String = (0..70)
                .map(|_| (b'a' + (rng.random::<u8>() % 26)) as char)
                .collect();
            writeln!(content, "{}", line).unwrap();
        }

        content.truncate(size);
        content
    }
}

impl Default for ConcurrentWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for ConcurrentWorkload {
    fn name(&self) -> &str {
        "Concurrent Access"
    }

    fn operation(&self) -> OperationType {
        OperationType::ConcurrentWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("files".to_string(), NUM_FILES.to_string());
        params.insert("hot_files".to_string(), EDITOR_HOT_FILES.to_string());
        params.insert("threads".to_string(), thread_count().to_string());
        params.insert(
            "duration_secs".to_string(),
            WORKLOAD_DURATION.as_secs().to_string(),
        );
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create directories
        fs::create_dir_all(self.source_dir(mount_point))?;
        fs::create_dir_all(self.output_dir(mount_point))?;

        // Create source files
        for i in 0..NUM_FILES {
            let content = self.generate_content(&mut rng, i);
            let path = self.file_path(mount_point, i);
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let start = Instant::now();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let mount_point = mount_point.to_path_buf();

        // Clone paths for threads
        let source_dir = self.source_dir(&mount_point);
        let output_dir = self.output_dir(&mount_point);

        let mut handles: Vec<thread::JoinHandle<u64>> = Vec::new();

        // Thread 1: Editor - continuous read-modify-write on hot files
        {
            let stop = stop_flag.clone();
            let mp = mount_point.clone();
            let handle = thread::spawn(move || {
                let mut version = 1u64;

                while !stop.load(Ordering::Relaxed) {
                    for hot_idx in 0..EDITOR_HOT_FILES {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }

                        let path = mp.join("bench_concurrent_workload/src")
                            .join(format!("source_{:03}.txt", hot_idx));

                        // Read
                        if let Ok(mut content) = fs::read(&path) {
                            // Modify
                            let edit = format!("\n// Edit v{} by editor\n", version);
                            content.extend_from_slice(edit.as_bytes());
                            version += 1;

                            // Write back
                            if let Ok(mut file) = File::create(&path) {
                                let _ = file.write_all(&content);
                                let _ = safe_sync(&file);
                            }
                        }

                        // Brief pause between operations
                        thread::sleep(Duration::from_millis(100));
                    }
                }

                version
            });
            handles.push(handle);
        }

        // Thread 2: File watcher - stat all files periodically
        {
            let stop = stop_flag.clone();
            let src_dir = source_dir.clone();
            let handle = thread::spawn(move || {
                let mut stat_count = 0u64;

                while !stop.load(Ordering::Relaxed) {
                    if let Ok(entries) = fs::read_dir(&src_dir) {
                        for entry in entries.flatten() {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            if let Ok(metadata) = entry.metadata() {
                                let _ = std::hint::black_box(metadata.modified());
                                stat_count += 1;
                            }
                        }
                    }

                    // Poll every 500ms
                    thread::sleep(Duration::from_millis(500));
                }

                stat_count
            });
            handles.push(handle);
        }

        // Thread 3: Build process - periodic full reads + output writes
        {
            let stop = stop_flag.clone();
            let src_dir = source_dir.clone();
            let out_dir = output_dir.clone();
            let handle = thread::spawn(move || {
                let mut rng = ChaCha8Rng::seed_from_u64(0xB0_1D);
                let mut build_count = 0u64;

                while !stop.load(Ordering::Relaxed) {
                    // Read all source files (simulate compile)
                    if let Ok(entries) = fs::read_dir(&src_dir) {
                        for entry in entries.flatten() {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            if let Ok(content) = fs::read(entry.path()) {
                                std::hint::black_box(&content);
                            }
                        }
                    }

                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    // Write output files
                    for i in 0..OUTPUT_FILES {
                        let path = out_dir.join(format!("output_{:03}.o", i));
                        let size = 10 * 1024 + rng.random_range(0..20 * 1024);
                        let mut content = vec![0u8; size];
                        rng.fill_bytes(&mut content);

                        if let Ok(mut file) = File::create(&path) {
                            let _ = file.write_all(&content);
                            let _ = safe_sync(&file);
                        }
                    }

                    build_count += 1;

                    // Build every 5 seconds
                    for _ in 0..50 {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }

                build_count
            });
            handles.push(handle);
        }

        // Thread 4: Terminal - random reads and directory listings
        {
            let stop = stop_flag.clone();
            let src_dir = source_dir.clone();
            let handle = thread::spawn(move || {
                let mut rng = ChaCha8Rng::seed_from_u64(0x7E_A0);
                let mut op_count = 0u64;

                while !stop.load(Ordering::Relaxed) {
                    // Random file read (cat simulation)
                    let file_idx = rng.random_range(0..NUM_FILES);
                    let path = src_dir.join(format!("source_{:03}.txt", file_idx));
                    if let Ok(content) = fs::read(&path) {
                        std::hint::black_box(&content);
                        op_count += 1;
                    }

                    // Directory listing (ls simulation)
                    if let Ok(entries) = fs::read_dir(&src_dir) {
                        let count = entries.count();
                        std::hint::black_box(count);
                        op_count += 1;
                    }

                    // Random delays between operations
                    let delay = 50 + rng.random_range(0..150);
                    thread::sleep(Duration::from_millis(delay));
                }

                op_count
            });
            handles.push(handle);
        }

        // Run for specified duration
        thread::sleep(WORKLOAD_DURATION);

        // Signal all threads to stop
        stop_flag.store(true, Ordering::Relaxed);

        // Wait for all threads to finish
        for handle in handles {
            let _ = handle.join();
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        0 // No warmup for timed concurrent workload
    }
}
