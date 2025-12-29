//! IDE Simulation Workload
//!
//! Simulates opening a project, editing files, saving, and building.
//! Exercises cache warming, working set locality, and mixed read/write patterns.

use crate::bench::Benchmark;
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

const NUM_SOURCE_FILES: usize = 50;
const HOT_FILE_COUNT: usize = 5;
const EDIT_CYCLES: usize = 20;
const OUTPUT_FILE_COUNT: usize = 10;

/// IDE Simulation Workload.
///
/// Phases:
/// 1. Project Open - Read directory tree, read all source files twice (indexing + syntax highlighting)
/// 2. Active Editing - Pick hot files, perform read-modify-write cycles with occasional cold file reads
/// 3. Save & Build - Write modified files, read all for build, write output files
pub struct IdeWorkload {
    seed: u64,
}

impl IdeWorkload {
    pub fn new() -> Self {
        Self { seed: 0x1DE0 }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_ide_workload")
    }

    fn source_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("src")
    }

    fn output_dir(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("build")
    }

    fn source_file_path(&self, mount_point: &Path, index: usize) -> PathBuf {
        self.source_dir(mount_point)
            .join(format!("module_{:03}.rs", index))
    }

    fn output_file_path(&self, mount_point: &Path, index: usize) -> PathBuf {
        self.output_dir(mount_point)
            .join(format!("output_{:03}.o", index))
    }

    /// Generate realistic source file content (10KB-100KB).
    fn generate_source_content(&self, rng: &mut ChaCha8Rng, index: usize) -> Vec<u8> {
        let size = 10 * 1024 + rng.random_range(0..90 * 1024); // 10KB-100KB
        let mut content = Vec::with_capacity(size);

        // Generate pseudo-code content
        writeln!(content, "// Module {} - Generated source file", index).unwrap();
        writeln!(content, "// Size: {} bytes\n", size).unwrap();

        let mut current_size = content.len();
        let mut func_num = 0;

        while current_size < size {
            let func_code = format!(
                r#"
pub fn function_{}_{:04}(x: i32, y: i32) -> i32 {{
    let result = x * y + {};
    if result > 1000 {{
        return result / 2;
    }}
    result
}}
"#,
                index,
                func_num,
                rng.random_range(1..1000)
            );
            content.extend_from_slice(func_code.as_bytes());
            current_size = content.len();
            func_num += 1;
        }

        content.truncate(size);
        content
    }
}

impl Default for IdeWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for IdeWorkload {
    fn name(&self) -> &str {
        "IDE Simulation"
    }

    fn operation(&self) -> OperationType {
        OperationType::IdeWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("source_files".to_string(), NUM_SOURCE_FILES.to_string());
        params.insert("hot_files".to_string(), HOT_FILE_COUNT.to_string());
        params.insert("edit_cycles".to_string(), EDIT_CYCLES.to_string());
        params.insert("output_files".to_string(), OUTPUT_FILE_COUNT.to_string());
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create directories
        fs::create_dir_all(self.source_dir(mount_point))?;
        fs::create_dir_all(self.output_dir(mount_point))?;

        // Create source files with varying sizes
        for i in 0..NUM_SOURCE_FILES {
            let content = self.generate_source_content(&mut rng, i);
            let path = self.source_file_path(mount_point, i);
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        // ===== Phase 1: Project Open (cache warming) =====

        // Read directory tree (simulates project indexing)
        let source_dir = self.source_dir(mount_point);
        let entries: Vec<_> = fs::read_dir(&source_dir)?.collect();
        std::hint::black_box(entries.len());

        // First pass: read all source files (simulates initial indexing)
        let mut file_contents: Vec<Vec<u8>> = Vec::with_capacity(NUM_SOURCE_FILES);
        for i in 0..NUM_SOURCE_FILES {
            let path = self.source_file_path(mount_point, i);
            let content = fs::read(&path)?;
            file_contents.push(content);
        }

        // Second pass: re-read all source files (simulates syntax highlighting)
        for i in 0..NUM_SOURCE_FILES {
            let path = self.source_file_path(mount_point, i);
            let content = fs::read(&path)?;
            std::hint::black_box(&content);
        }

        // ===== Phase 2: Active Editing (working set) =====

        // Select hot files (the ones being actively edited)
        let hot_indices: Vec<usize> = (0..HOT_FILE_COUNT).collect();

        for _cycle in 0..EDIT_CYCLES {
            // Pick a hot file to edit
            let hot_idx = hot_indices[rng.random_range(0..hot_indices.len())];
            let hot_path = self.source_file_path(mount_point, hot_idx);

            // Read random portion (cursor navigation)
            let mut file = File::open(&hot_path)?;
            let file_len = file.metadata()?.len() as usize;
            let read_offset = rng.random_range(0..file_len.saturating_sub(1024).max(1));
            let read_size = 1024.min(file_len - read_offset);

            file.seek(SeekFrom::Start(read_offset as u64))?;
            let mut buffer = vec![0u8; read_size];
            file.read_exact(&mut buffer)?;
            std::hint::black_box(&buffer);
            drop(file);

            // Small write (typing) - append a comment
            let comment = format!("\n// Edit cycle timestamp: {}\n", _cycle);
            file_contents[hot_idx].extend_from_slice(comment.as_bytes());

            // Read nearby portion (autocomplete/context)
            let nearby_offset = read_offset.saturating_sub(512);
            let mut file = File::open(&hot_path)?;
            file.seek(SeekFrom::Start(nearby_offset as u64))?;
            let mut nearby_buf = vec![0u8; 512.min(file_len - nearby_offset)];
            let _ = file.read(&mut nearby_buf)?;
            std::hint::black_box(&nearby_buf);

            // Occasional cold file read (reference lookup) - 20% chance
            if rng.random_bool(0.2) {
                let cold_idx = rng.random_range(HOT_FILE_COUNT..NUM_SOURCE_FILES);
                let cold_path = self.source_file_path(mount_point, cold_idx);
                let cold_content = fs::read(&cold_path)?;
                std::hint::black_box(&cold_content);
            }
        }

        // ===== Phase 3: Save & Build =====

        // Write all modified hot files
        for &hot_idx in &hot_indices {
            let path = self.source_file_path(mount_point, hot_idx);
            let mut file = File::create(&path)?;
            file.write_all(&file_contents[hot_idx])?;
            safe_sync(&file)?;
        }

        // Read all files (build/compile simulation)
        for i in 0..NUM_SOURCE_FILES {
            let path = self.source_file_path(mount_point, i);
            let content = fs::read(&path)?;
            std::hint::black_box(&content);
        }

        // Write output files
        for i in 0..OUTPUT_FILE_COUNT {
            let path = self.output_file_path(mount_point, i);
            // Output files are compiled versions - generate some binary-like content
            let mut output_content = vec![0u8; 50 * 1024 + rng.random_range(0..50 * 1024)];
            rng.fill_bytes(&mut output_content);
            let mut file = File::create(&path)?;
            file.write_all(&output_content)?;
            safe_sync(&file)?;
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
        1 // Workloads need fewer warmup iterations
    }
}
