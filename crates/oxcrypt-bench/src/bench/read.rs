//! Read operation benchmarks.

use crate::bench::Benchmark;
use crate::config::{FileSize, OperationType};
use anyhow::Result;
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Sequential read benchmark.
pub struct SequentialReadBenchmark {
    file_size: FileSize,
    buffer_size: usize,
    #[allow(dead_code)]
    test_file: Option<PathBuf>,
}

impl SequentialReadBenchmark {
    /// Create a new sequential read benchmark.
    pub fn new(file_size: FileSize) -> Self {
        Self {
            file_size,
            buffer_size: 64 * 1024, // 64KB buffer
            test_file: None,
        }
    }

    /// Get the test file path.
    fn test_file_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_seq_read_{}_iter{}.bin", self.file_size.name(), iteration))
    }
}

impl Benchmark for SequentialReadBenchmark {
    fn name(&self) -> &'static str {
        "Sequential Read"
    }

    fn operation(&self) -> OperationType {
        OperationType::SequentialRead
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("file_size".to_string(), self.file_size.name().to_string());
        params.insert("buffer_size".to_string(), format!("{}KB", self.buffer_size / 1024));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let file_path = self.test_file_path(mount_point, iteration);

        // Generate deterministic content
        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        let mut content = vec![0u8; self.file_size.bytes()];
        rng.fill_bytes(&mut content);

        // Write test file
        let mut file = File::create(&file_path)?;
        file.write_all(&content)?;
        safe_sync(&file)?;

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let file_path = self.test_file_path(mount_point, iteration);
        let mut buffer = vec![0u8; self.buffer_size];

        let start = Instant::now();

        let mut file = File::open(&file_path)?;
        let mut total_read = 0;

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total_read += n;
            // Prevent optimization
            std::hint::black_box(&buffer[..n]);
        }

        let elapsed = start.elapsed();

        // Verify we read the expected amount
        if total_read != self.file_size.bytes() {
            anyhow::bail!(
                "Read {} bytes, expected {}",
                total_read,
                self.file_size.bytes()
            );
        }

        Ok(elapsed)
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let file_path = self.test_file_path(mount_point, iteration);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }
        Ok(())
    }
}

/// Random read benchmark.
pub struct RandomReadBenchmark {
    file_size: FileSize,
    chunk_size: usize,
    num_reads: usize,
    seed: u64,
}

impl RandomReadBenchmark {
    /// Create a new random read benchmark.
    pub fn new(file_size: FileSize) -> Self {
        Self {
            file_size,
            chunk_size: 4096, // 4KB chunks
            num_reads: 100,   // 100 random reads
            seed: 12345,
        }
    }

    /// Get the test file path.
    fn test_file_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_rand_read_{}_iter{}.bin", self.file_size.name(), iteration))
    }
}

impl Benchmark for RandomReadBenchmark {
    fn name(&self) -> &'static str {
        "Random Read"
    }

    fn operation(&self) -> OperationType {
        OperationType::RandomRead
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("file_size".to_string(), self.file_size.name().to_string());
        params.insert("chunk_size".to_string(), format!("{}B", self.chunk_size));
        params.insert("num_reads".to_string(), format!("{}", self.num_reads));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let file_path = self.test_file_path(mount_point, iteration);

        // Generate deterministic content
        let mut rng = ChaCha8Rng::seed_from_u64(42 + iteration as u64);
        let mut content = vec![0u8; self.file_size.bytes()];
        rng.fill_bytes(&mut content);

        // Write test file
        let mut file = File::create(&file_path)?;
        file.write_all(&content)?;
        safe_sync(&file)?;

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let file_path = self.test_file_path(mount_point, iteration);
        let max_offset = self.file_size.bytes().saturating_sub(self.chunk_size);
        let mut buffer = vec![0u8; self.chunk_size];

        // Generate random offsets
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let offsets: Vec<u64> = (0..self.num_reads)
            .map(|_| rng.random_range(0..=max_offset) as u64)
            .collect();

        let start = Instant::now();

        let mut file = File::open(&file_path)?;

        for offset in offsets {
            file.seek(SeekFrom::Start(offset))?;
            let n = file.read(&mut buffer)?;
            std::hint::black_box(&buffer[..n]);
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let file_path = self.test_file_path(mount_point, iteration);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }
        Ok(())
    }
}
