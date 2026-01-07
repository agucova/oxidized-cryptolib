//! Concurrent Editor Workload
//!
//! Simulates multiple processes accessing vault simultaneously:
//! - Editor: continuous read-modify-write
//! - File watcher: periodic stat storms
//! - Build process: periodic full reads + writes
//! - Terminal: random reads and directory listings
//!
//! Tests cache coherency, concurrent metadata access, and write invalidation visibility.

use crate::bench::workloads::WorkloadConfig;
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

// Base values for full-scale workload
const BASE_NUM_FILES: usize = 30;
const BASE_EDITOR_HOT_FILES: usize = 3;
const BASE_OUTPUT_FILES: usize = 5;
const BASE_WORKLOAD_DURATION: Duration = Duration::from_secs(30);

// Minimum values
const MIN_NUM_FILES: usize = 10;
const MIN_EDITOR_HOT_FILES: usize = 2;
const MIN_OUTPUT_FILES: usize = 2;
const MIN_WORKLOAD_DURATION: Duration = Duration::from_secs(5);

/// Dynamic thread count based on available CPU cores.
fn thread_count() -> usize {
    thread::available_parallelism()
        .map(|p| p.get().clamp(2, 8))
        .unwrap_or(4)
}

/// Concurrent Editor Workload.
///
/// Spawns multiple threads simulating different application behaviors:
/// - Thread 1 (Editor): Continuous read-modify-write on hot files
/// - Thread 2 (File watcher): Stat all files periodically
/// - Thread 3 (Build process): Periodic full reads + output writes
/// - Thread 4 (Terminal): Random file reads and directory listings
pub struct ConcurrentWorkload {
    config: WorkloadConfig,
    seed: u64,
    num_files: usize,
    editor_hot_files: usize,
    output_files: usize,
    workload_duration: Duration,
}

impl ConcurrentWorkload {
    pub fn new(config: WorkloadConfig) -> Self {
        let num_files = config.scale_count(BASE_NUM_FILES, MIN_NUM_FILES);
        let editor_hot_files = config.scale_count(BASE_EDITOR_HOT_FILES, MIN_EDITOR_HOT_FILES);
        let output_files = config.scale_count(BASE_OUTPUT_FILES, MIN_OUTPUT_FILES);
        let workload_duration = config.scale_duration(BASE_WORKLOAD_DURATION, MIN_WORKLOAD_DURATION);

        Self {
            config,
            seed: 0xC0_C0,
            num_files,
            editor_hot_files,
            output_files,
            workload_duration,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_concurrent_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn source_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("src")
    }

    fn output_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("output")
    }

    fn file_path(&self, mount_point: &Path, iteration: usize, index: usize) -> PathBuf {
        self.source_dir(mount_point, iteration)
            .join(format!("source_{index:03}.txt"))
    }

    #[allow(dead_code)]
    fn output_path(&self, mount_point: &Path, iteration: usize, index: usize) -> PathBuf {
        self.output_dir(mount_point, iteration)
            .join(format!("output_{index:03}.o"))
    }

    /// Generate initial file content.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn generate_content(&self, rng: &mut ChaCha8Rng, index: usize) -> Vec<u8> {
        let size = 5 * 1024 + rng.random_range(0..10 * 1024); // 5KB-15KB
        let mut content = Vec::with_capacity(size);

        writeln!(content, "// Source file {index}")
            .expect("Failed to write to in-memory buffer - system OOM");
        writeln!(content, "// Version: 1")
            .expect("Failed to write to in-memory buffer - system OOM");
        writeln!(content)
            .expect("Failed to write to in-memory buffer - system OOM");

        while content.len() < size {
            let line: String = (0..70)
                .map(|_| (b'a' + (rng.random::<u8>() % 26)) as char)
                .collect();
            writeln!(content, "{line}")
                .expect("Failed to write to in-memory buffer - system OOM");
        }

        content.truncate(size);
        content
    }
}

impl Default for ConcurrentWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for ConcurrentWorkload {
    fn name(&self) -> &'static str {
        "Multi-Process"
    }

    fn operation(&self) -> OperationType {
        OperationType::ConcurrentWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("files".to_string(), self.num_files.to_string());
        params.insert("hot_files".to_string(), self.editor_hot_files.to_string());
        params.insert("threads".to_string(), thread_count().to_string());
        params.insert(
            "duration_secs".to_string(),
            self.workload_duration.as_secs().to_string(),
        );
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create directories
        fs::create_dir_all(self.source_dir(mount_point, iteration))?;
        fs::create_dir_all(self.output_dir(mount_point, iteration))?;

        // Create source files
        for i in 0..self.num_files {
            let content = self.generate_content(&mut rng, i);
            let path = self.file_path(mount_point, iteration, i);
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let start = Instant::now();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let mount_point = mount_point.to_path_buf();

        // Clone paths for threads
        let source_dir = self.source_dir(&mount_point, iteration);
        let output_dir = self.output_dir(&mount_point, iteration);

        let mut handles: Vec<thread::JoinHandle<u64>> = Vec::new();

        // Thread 1: Editor - continuous read-modify-write on hot files
        {
            let stop = stop_flag.clone();
            let mp = mount_point.clone();
            let editor_hot_files = self.editor_hot_files;
            let handle = thread::spawn(move || {
                let mut version = 1u64;

                while !stop.load(Ordering::Relaxed) {
                    for hot_idx in 0..editor_hot_files {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }

                        let path = mp.join("bench_concurrent_workload/src")
                            .join(format!("source_{hot_idx:03}.txt"));

                        // Read
                        if let Ok(mut content) = fs::read(&path) {
                            // Modify - prevent unbounded growth by truncating old content
                            const MAX_CONTENT_SIZE: usize = 50 * 1024; // 50KB limit
                            let edit = format!("\n// Edit v{version} by editor\n");

                            // If file would exceed limit, remove old content from the beginning
                            if content.len() + edit.len() > MAX_CONTENT_SIZE {
                                let excess = (content.len() + edit.len()) - MAX_CONTENT_SIZE;
                                content.drain(0..excess);
                            }

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
            let output_files = self.output_files;
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
                    for i in 0..output_files {
                        let path = out_dir.join(format!("output_{i:03}.o"));
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
            let num_files = self.num_files;
            let handle = thread::spawn(move || {
                let mut rng = ChaCha8Rng::seed_from_u64(0x7E_A0);
                let mut op_count = 0u64;

                while !stop.load(Ordering::Relaxed) {
                    // Random file read (cat simulation)
                    let file_idx = rng.random_range(0..num_files);
                    let path = src_dir.join(format!("source_{file_idx:03}.txt"));
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
        thread::sleep(self.workload_duration);

        // Signal all threads to stop
        stop_flag.store(true, Ordering::Relaxed);

        // Wait for all threads to finish
        for handle in handles {
            let _ = handle.join();
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        0 // No warmup for timed concurrent workload
    }
}
