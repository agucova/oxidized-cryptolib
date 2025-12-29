//! Working Set Workload
//!
//! Simulates application access patterns following the 80/20 rule (Zipf distribution).
//! Hot files are accessed frequently, warm files occasionally, cold files rarely.
//! This exercises cache effectiveness and measures the benefit of keeping hot data cached.

use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::Result;
use oxidized_mount_common::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const TOTAL_FILES: usize = 1000;
const HOT_SET_SIZE: usize = 50;      // 5% of files, accessed 80% of time
const WARM_SET_SIZE: usize = 150;    // 15% of files, accessed 15% of time
const COLD_SET_SIZE: usize = 800;    // 80% of files, accessed 5% of time
const NUM_OPERATIONS: usize = 500;

// Access probabilities
const HOT_PROBABILITY: f64 = 0.80;
const WARM_PROBABILITY: f64 = 0.15;
// Cold = 1.0 - HOT - WARM = 0.05

// Operation type probabilities
const READ_FULL_PROB: f64 = 0.70;
const READ_PARTIAL_PROB: f64 = 0.20;
// Write = 1.0 - READ_FULL - READ_PARTIAL = 0.10

/// Working Set Workload.
///
/// Creates 1000 files with varying sizes and accesses them according to Zipf distribution:
/// - Hot set (50 files): 80% of accesses
/// - Warm set (150 files): 15% of accesses
/// - Cold set (800 files): 5% of accesses
///
/// Operations: 70% full read, 20% partial read, 10% write
pub struct WorkingSetWorkload {
    seed: u64,
}

impl WorkingSetWorkload {
    pub fn new() -> Self {
        Self { seed: 0x50_5E7 }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_working_set")
    }

    fn file_path(&self, mount_point: &Path, index: usize) -> PathBuf {
        // Distribute files across subdirectories to avoid huge single directories
        let subdir = index / 100;
        self.workload_dir(mount_point)
            .join(format!("dir_{:02}", subdir))
            .join(format!("file_{:04}.dat", index))
    }

    /// Generate file size: mix of 1KB-1MB with bias toward smaller files.
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
            // Hot set: indices 0..HOT_SET_SIZE
            rng.random_range(0..HOT_SET_SIZE)
        } else if roll < HOT_PROBABILITY + WARM_PROBABILITY {
            // Warm set: indices HOT_SET_SIZE..(HOT_SET_SIZE + WARM_SET_SIZE)
            HOT_SET_SIZE + rng.random_range(0..WARM_SET_SIZE)
        } else {
            // Cold set: indices (HOT_SET_SIZE + WARM_SET_SIZE)..TOTAL_FILES
            HOT_SET_SIZE + WARM_SET_SIZE + rng.random_range(0..COLD_SET_SIZE)
        }
    }

    /// Select operation type: full read, partial read, or write.
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
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    ReadFull,
    ReadPartial,
    Write,
}

impl Benchmark for WorkingSetWorkload {
    fn name(&self) -> &str {
        "Working Set"
    }

    fn operation(&self) -> OperationType {
        OperationType::WorkingSetWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("total_files".to_string(), TOTAL_FILES.to_string());
        params.insert("hot_set".to_string(), HOT_SET_SIZE.to_string());
        params.insert("warm_set".to_string(), WARM_SET_SIZE.to_string());
        params.insert("cold_set".to_string(), COLD_SET_SIZE.to_string());
        params.insert("operations".to_string(), NUM_OPERATIONS.to_string());
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create subdirectories
        for subdir in 0..TOTAL_FILES.div_ceil(100) {
            let dir = self.workload_dir(mount_point).join(format!("dir_{:02}", subdir));
            fs::create_dir_all(&dir)?;
        }

        // Create files with varying sizes
        for i in 0..TOTAL_FILES {
            let size = self.generate_file_size(&mut rng);
            let mut content = vec![0u8; size];
            rng.fill_bytes(&mut content);

            let path = self.file_path(mount_point, i);
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        // Track which files have been accessed (for cache analysis if needed)
        let mut _access_counts = vec![0usize; TOTAL_FILES];

        for _op_num in 0..NUM_OPERATIONS {
            let file_idx = self.select_file_index(&mut rng);
            let operation = self.select_operation(&mut rng);
            let path = self.file_path(mount_point, file_idx);

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

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }
}
