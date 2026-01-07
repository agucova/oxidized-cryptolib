//! Working Set Workload
//!
//! Simulates application access patterns following the 80/20 rule (Zipf distribution).
//! Hot files are accessed frequently, warm files occasionally, cold files rarely.
//! This exercises cache effectiveness and measures the benefit of keeping hot data cached.

// Allow numeric casts for percentage calculations
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use crate::bench::workloads::WorkloadConfig;
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
use crate::config::OperationType;
use anyhow::Result;
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Base values for full-scale workload
const BASE_TOTAL_FILES: usize = 1000;
const BASE_NUM_OPERATIONS: usize = 500;

// Minimum values
const MIN_TOTAL_FILES: usize = 100;
const MIN_NUM_OPERATIONS: usize = 50;

// Access probabilities
const HOT_PROBABILITY: f64 = 0.80;
const WARM_PROBABILITY: f64 = 0.15;
// Cold = 1.0 - HOT - WARM = 0.05

// Operation type probabilities
const READ_FULL_PROB: f64 = 0.70;
const READ_PARTIAL_PROB: f64 = 0.20;
// Write = 1.0 - READ_FULL - READ_PARTIAL = 0.10

/// Working set workload phases for progress reporting.
const WORKING_SET_PHASES: &[&str] = &[
    "Zipf operations",
];

/// Working Set Workload.
///
/// Creates files with varying sizes and accesses them according to Zipf distribution:
/// - Hot set (5% of files): 80% of accesses
/// - Warm set (15% of files): 15% of accesses
/// - Cold set (80% of files): 5% of accesses
///
/// Operations: 70% full read, 20% partial read, 10% write
pub struct WorkingSetWorkload {
    config: WorkloadConfig,
    seed: u64,
    total_files: usize,
    hot_set_size: usize,
    warm_set_size: usize,
    cold_set_size: usize,
    num_operations: usize,
}

impl WorkingSetWorkload {
    pub fn new(config: WorkloadConfig) -> Self {
        let total_files = config.scale_count(BASE_TOTAL_FILES, MIN_TOTAL_FILES);

        // Calculate proportional set sizes (5%, 15%, 80%)
        let hot_set_size = (total_files as f64 * 0.05).round() as usize;
        let warm_set_size = (total_files as f64 * 0.15).round() as usize;
        let cold_set_size = total_files - hot_set_size - warm_set_size;

        let num_operations = config.scale_count(BASE_NUM_OPERATIONS, MIN_NUM_OPERATIONS);

        Self {
            config,
            seed: 0x50_5E7,
            total_files,
            hot_set_size,
            warm_set_size,
            cold_set_size,
            num_operations,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, _iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_working_set_{}", self.config.session_id))
    }

    fn file_path(&self, mount_point: &Path, iteration: usize, index: usize) -> PathBuf {
        // Distribute files across subdirectories to avoid huge single directories
        let subdir = index / 100;
        self.workload_dir(mount_point, iteration)
            .join(format!("dir_{subdir:02}"))
            .join(format!("file_{index:04}.dat"))
    }

    /// Generate file size: mix of 1KB-1MB with bias toward smaller files.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn generate_file_size(&self, rng: &mut ChaCha8Rng) -> usize {
        let choice = rng.random::<f64>();
        if choice < 0.50 {
            // 50%: 1KB-10KB (small files)
            1024 + rng.random_range(0..9 * 1024)
        } else if choice < 0.80 {
            // 30%: 10KB-100KB (medium files)
            10 * 1024 + rng.random_range(0..90 * 1024)
        } else if choice < 0.95 {
            // 15%: 100KB-500KB (larger files)
            100 * 1024 + rng.random_range(0..400 * 1024)
        } else {
            // 5%: 500KB-1MB (large files)
            500 * 1024 + rng.random_range(0..512 * 1024)
        }
    }

    /// Select a file index based on Zipf-like distribution.
    fn select_file_index(&self, rng: &mut ChaCha8Rng) -> usize {
        let roll = rng.random::<f64>();

        if roll < HOT_PROBABILITY {
            // Hot set: indices 0..hot_set_size
            rng.random_range(0..self.hot_set_size)
        } else if roll < HOT_PROBABILITY + WARM_PROBABILITY {
            // Warm set: indices hot_set_size..(hot_set_size + warm_set_size)
            self.hot_set_size + rng.random_range(0..self.warm_set_size)
        } else {
            // Cold set: indices (hot_set_size + warm_set_size)..total_files
            self.hot_set_size + self.warm_set_size + rng.random_range(0..self.cold_set_size)
        }
    }

    /// Select operation type: full read, partial read, or write.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn select_operation(&self, rng: &mut ChaCha8Rng) -> Operation {
        let roll = rng.random::<f64>();

        if roll < READ_FULL_PROB {
            Operation::ReadFull
        } else if roll < READ_FULL_PROB + READ_PARTIAL_PROB {
            Operation::ReadPartial
        } else {
            Operation::Write
        }
    }
}

impl Default for WorkingSetWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    ReadFull,
    ReadPartial,
    Write,
}

impl Benchmark for WorkingSetWorkload {
    fn name(&self) -> &'static str {
        "Working Set"
    }

    fn operation(&self) -> OperationType {
        OperationType::WorkingSetWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("total_files".to_string(), self.total_files.to_string());
        params.insert("hot_set".to_string(), self.hot_set_size.to_string());
        params.insert("warm_set".to_string(), self.warm_set_size.to_string());
        params.insert("cold_set".to_string(), self.cold_set_size.to_string());
        params.insert("operations".to_string(), self.num_operations.to_string());
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create subdirectories
        for subdir in 0..self.total_files.div_ceil(100) {
            let dir = self.workload_dir(mount_point, iteration).join(format!("dir_{subdir:02}"));
            fs::create_dir_all(&dir)?;
        }

        // Create files with varying sizes
        for i in 0..self.total_files {
            let size = self.generate_file_size(&mut rng);
            let mut content = vec![0u8; size];
            rng.fill_bytes(&mut content);

            let path = self.file_path(mount_point, iteration, i);
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        // Track which files have been accessed (for cache analysis if needed)
        let mut _access_counts = vec![0usize; self.total_files];

        for _op_num in 0..self.num_operations {
            let file_idx = self.select_file_index(&mut rng);
            let operation = self.select_operation(&mut rng);
            let path = self.file_path(mount_point, iteration, file_idx);

            _access_counts[file_idx] += 1;

            match operation {
                Operation::ReadFull => {
                    // Read entire file
                    let content = fs::read(&path)?;
                    std::hint::black_box(&content);
                }
                Operation::ReadPartial => {
                    // Read a portion of the file
                    let metadata = fs::metadata(&path)?;
                    let file_size = metadata.len() as usize;

                    if file_size > 0 {
                        let read_size = 4096.min(file_size);
                        let max_offset = file_size.saturating_sub(read_size);
                        let offset = if max_offset > 0 {
                            rng.random_range(0..max_offset)
                        } else {
                            0
                        };

                        let mut file = File::open(&path)?;
                        file.seek(SeekFrom::Start(offset as u64))?;
                        let mut buffer = vec![0u8; read_size];
                        let _ = file.read(&mut buffer)?;
                        std::hint::black_box(&buffer);
                    }
                }
                Operation::Write => {
                    // Read-modify-write pattern (common in real applications)
                    let mut content = fs::read(&path)?;

                    // Modify a portion of the content
                    let modify_offset = rng.random_range(0..content.len().max(1));
                    let modify_size = 256.min(content.len() - modify_offset);
                    for i in 0..modify_size {
                        content[modify_offset + i] = rng.random();
                    }

                    // Write back
                    let mut file = File::create(&path)?;
                    file.write_all(&content)?;
                    safe_sync(&file)?;
                }
            }
        }

        Ok(start.elapsed())
    }

    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(WORKING_SET_PHASES)
    }

    fn run_with_progress(
        &self,
        mount_point: &Path,
        iteration: usize,
        progress: Option<PhaseProgressCallback<'_>>,
    ) -> Result<Duration> {
        let report = |items_done: usize, items_total: usize| {
            if let Some(cb) = progress {
                cb(PhaseProgress {
                    phase_name: WORKING_SET_PHASES[0],
                    phase_index: 0,
                    total_phases: WORKING_SET_PHASES.len(),
                    items_completed: Some(items_done),
                    items_total: Some(items_total),
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        // Track which files have been accessed (for cache analysis if needed)
        let mut _access_counts = vec![0usize; self.total_files];

        report(0, self.num_operations);

        for op_num in 0..self.num_operations {
            let file_idx = self.select_file_index(&mut rng);
            let operation = self.select_operation(&mut rng);
            let path = self.file_path(mount_point, iteration, file_idx);

            _access_counts[file_idx] += 1;

            match operation {
                Operation::ReadFull => {
                    // Read entire file
                    let content = fs::read(&path)?;
                    std::hint::black_box(&content);
                }
                Operation::ReadPartial => {
                    // Read a portion of the file
                    let metadata = fs::metadata(&path)?;
                    let file_size = metadata.len() as usize;

                    if file_size > 0 {
                        let read_size = 4096.min(file_size);
                        let max_offset = file_size.saturating_sub(read_size);
                        let offset = if max_offset > 0 {
                            rng.random_range(0..max_offset)
                        } else {
                            0
                        };

                        let mut file = File::open(&path)?;
                        file.seek(SeekFrom::Start(offset as u64))?;
                        let mut buffer = vec![0u8; read_size];
                        let _ = file.read(&mut buffer)?;
                        std::hint::black_box(&buffer);
                    }
                }
                Operation::Write => {
                    // Read-modify-write pattern (common in real applications)
                    let mut content = fs::read(&path)?;

                    // Modify a portion of the content
                    let modify_offset = rng.random_range(0..content.len().max(1));
                    let modify_size = 256.min(content.len() - modify_offset);
                    for i in 0..modify_size {
                        content[modify_offset + i] = rng.random();
                    }

                    // Write back
                    let mut file = File::create(&path)?;
                    file.write_all(&content)?;
                    safe_sync(&file)?;
                }
            }

            // Report progress every 25 operations or at the end
            if (op_num + 1) % 25 == 0 || op_num + 1 == self.num_operations {
                report(op_num + 1, self.num_operations);
            }
        }

        Ok(start.elapsed())
    }
}
