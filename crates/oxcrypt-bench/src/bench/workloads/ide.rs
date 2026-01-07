//! IDE Simulation Workload
//!
//! Simulates opening a project, editing files, saving, and building.
//! Exercises cache warming, working set locality, and mixed read/write patterns.

// Allow numeric casts and underscore bindings in IDE simulation
#![allow(clippy::cast_possible_truncation, clippy::used_underscore_binding)]

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
const BASE_NUM_SOURCE_FILES: usize = 50;
const BASE_HOT_FILE_COUNT: usize = 5;
const BASE_EDIT_CYCLES: usize = 20;
const BASE_OUTPUT_FILE_COUNT: usize = 10;

// Minimum values to ensure workload is still meaningful
const MIN_SOURCE_FILES: usize = 10;
const MIN_HOT_FILE_COUNT: usize = 2;
const MIN_EDIT_CYCLES: usize = 5;
const MIN_OUTPUT_FILE_COUNT: usize = 2;

/// IDE workload phases for progress reporting.
const IDE_PHASES: &[&str] = &[
    "Project Open",
    "Active Editing",
    "Save & Build",
];

/// IDE Simulation Workload.
///
/// Phases:
/// 1. Project Open - Read directory tree, read all source files twice (indexing + syntax highlighting)
/// 2. Active Editing - Pick hot files, perform read-modify-write cycles with occasional cold file reads
/// 3. Save & Build - Write modified files, read all for build, write output files
pub struct IdeWorkload {
    config: WorkloadConfig,
    seed: u64,
    num_source_files: usize,
    hot_file_count: usize,
    edit_cycles: usize,
    output_file_count: usize,
}

impl IdeWorkload {
    pub fn new(config: WorkloadConfig) -> Self {
        let num_source_files = config.scale_count(BASE_NUM_SOURCE_FILES, MIN_SOURCE_FILES);
        let hot_file_count = config.scale_count(BASE_HOT_FILE_COUNT, MIN_HOT_FILE_COUNT);
        let edit_cycles = config.scale_count(BASE_EDIT_CYCLES, MIN_EDIT_CYCLES);
        let output_file_count = config.scale_count(BASE_OUTPUT_FILE_COUNT, MIN_OUTPUT_FILE_COUNT);

        Self {
            config,
            seed: 0x1DE0,
            num_source_files,
            hot_file_count,
            edit_cycles,
            output_file_count,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_ide_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn source_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("src")
    }

    fn output_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("build")
    }

    fn source_file_path(&self, mount_point: &Path, iteration: usize, index: usize) -> PathBuf {
        self.source_dir(mount_point, iteration)
            .join(format!("module_{index:03}.rs"))
    }

    fn output_file_path(&self, mount_point: &Path, iteration: usize, index: usize) -> PathBuf {
        self.output_dir(mount_point, iteration)
            .join(format!("output_{index:03}.o"))
    }

    /// Generate realistic source file content (10KB-100KB).
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn generate_source_content(&self, rng: &mut ChaCha8Rng, index: usize) -> Vec<u8> {
        let size = 10 * 1024 + rng.random_range(0..90 * 1024); // 10KB-100KB
        let mut content = Vec::with_capacity(size);

        // Generate pseudo-code content
        writeln!(content, "// Module {index} - Generated source file")
            .expect("Failed to write to in-memory buffer - system OOM");
        writeln!(content, "// Size: {size} bytes\n")
            .expect("Failed to write to in-memory buffer - system OOM");

        let mut current_size = content.len();
        let mut func_num = 0;

        while current_size < size {
            let func_code = format!(
                r"
pub fn function_{}_{:04}(x: i32, y: i32) -> i32 {{
    let result = x * y + {};
    if result > 1000 {{
        return result / 2;
    }}
    result
}}
",
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
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for IdeWorkload {
    fn name(&self) -> &'static str {
        "Code Editor"
    }

    fn operation(&self) -> OperationType {
        OperationType::IdeWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("source_files".to_string(), self.num_source_files.to_string());
        params.insert("hot_files".to_string(), self.hot_file_count.to_string());
        params.insert("edit_cycles".to_string(), self.edit_cycles.to_string());
        params.insert("output_files".to_string(), self.output_file_count.to_string());
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create directories
        fs::create_dir_all(self.source_dir(mount_point, iteration))?;
        fs::create_dir_all(self.output_dir(mount_point, iteration))?;

        // Create source files with varying sizes
        for i in 0..self.num_source_files {
            let content = self.generate_source_content(&mut rng, i);
            let path = self.source_file_path(mount_point, iteration, i);
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        // ===== Phase 1: Project Open (cache warming) =====

        // Read directory tree (simulates project indexing)
        let source_dir = self.source_dir(mount_point, iteration);
        let entries: Vec<_> = fs::read_dir(&source_dir)?.collect();
        std::hint::black_box(entries.len());

        // First pass: read all source files (simulates initial indexing)
        let mut file_contents: Vec<Vec<u8>> = Vec::with_capacity(self.num_source_files);
        for i in 0..self.num_source_files {
            let path = self.source_file_path(mount_point, iteration, i);
            let content = fs::read(&path)?;
            file_contents.push(content);
        }

        // Second pass: re-read all source files (simulates syntax highlighting)
        for i in 0..self.num_source_files {
            let path = self.source_file_path(mount_point, iteration, i);
            let content = fs::read(&path)?;
            std::hint::black_box(&content);
        }

        // ===== Phase 2: Active Editing (working set) =====

        // Select hot files (the ones being actively edited)
        let hot_indices: Vec<usize> = (0..self.hot_file_count).collect();

        for _cycle in 0..self.edit_cycles {
            // Pick a hot file to edit
            let hot_idx = hot_indices[rng.random_range(0..hot_indices.len())];
            let hot_path = self.source_file_path(mount_point, iteration, hot_idx);

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
            let comment = format!("\n// Edit cycle timestamp: {_cycle}\n");
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
                let cold_idx = rng.random_range(self.hot_file_count..self.num_source_files);
                let cold_path = self.source_file_path(mount_point, iteration, cold_idx);
                let cold_content = fs::read(&cold_path)?;
                std::hint::black_box(&cold_content);
            }
        }

        // ===== Phase 3: Save & Build =====

        // Write all modified hot files
        for &hot_idx in &hot_indices {
            let path = self.source_file_path(mount_point, iteration, hot_idx);
            let mut file = File::create(&path)?;
            file.write_all(&file_contents[hot_idx])?;
            safe_sync(&file)?;
        }

        // Read all files (build/compile simulation)
        for i in 0..self.num_source_files {
            let path = self.source_file_path(mount_point, iteration, i);
            let content = fs::read(&path)?;
            std::hint::black_box(&content);
        }

        // Write output files
        for i in 0..self.output_file_count {
            let path = self.output_file_path(mount_point, iteration, i);
            // Output files are compiled versions - generate some binary-like content
            let mut output_content = vec![0u8; 50 * 1024 + rng.random_range(0..50 * 1024)];
            rng.fill_bytes(&mut output_content);
            let mut file = File::create(&path)?;
            file.write_all(&output_content)?;
            safe_sync(&file)?;
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
        1 // Workloads need fewer warmup iterations
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(IDE_PHASES)
    }

    fn run_with_progress(
        &self,
        mount_point: &Path,
        iteration: usize,
        progress: Option<PhaseProgressCallback<'_>>,
    ) -> Result<Duration> {
        let report = |phase_idx: usize, items_done: Option<usize>, items_total: Option<usize>| {
            if let Some(cb) = progress {
                cb(PhaseProgress {
                    phase_name: IDE_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: IDE_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        // ===== Phase 1: Project Open (cache warming) =====
        // Total items: directory read + 2 passes over all source files
        let phase1_total = 1 + (2 * self.num_source_files);
        report(0, Some(0), Some(phase1_total));

        // Read directory tree (simulates project indexing)
        let source_dir = self.source_dir(mount_point, iteration);
        let entries: Vec<_> = fs::read_dir(&source_dir)?.collect();
        std::hint::black_box(entries.len());
        report(0, Some(1), Some(phase1_total));

        // First pass: read all source files (simulates initial indexing)
        let mut file_contents: Vec<Vec<u8>> = Vec::with_capacity(self.num_source_files);
        for i in 0..self.num_source_files {
            let path = self.source_file_path(mount_point, iteration, i);
            let content = fs::read(&path)?;
            file_contents.push(content);
            if i % 10 == 0 || i == self.num_source_files - 1 {
                report(0, Some(1 + i + 1), Some(phase1_total));
            }
        }

        // Second pass: re-read all source files (simulates syntax highlighting)
        for i in 0..self.num_source_files {
            let path = self.source_file_path(mount_point, iteration, i);
            let content = fs::read(&path)?;
            std::hint::black_box(&content);
            if i % 10 == 0 || i == self.num_source_files - 1 {
                report(0, Some(1 + self.num_source_files + i + 1), Some(phase1_total));
            }
        }

        // ===== Phase 2: Active Editing (working set) =====
        report(1, Some(0), Some(self.edit_cycles));

        let hot_indices: Vec<usize> = (0..self.hot_file_count).collect();

        for cycle in 0..self.edit_cycles {
            // Pick a hot file to edit
            let hot_idx = hot_indices[rng.random_range(0..hot_indices.len())];
            let hot_path = self.source_file_path(mount_point, iteration, hot_idx);

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
            let comment = format!("\n// Edit cycle timestamp: {cycle}\n");
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
                let cold_idx = rng.random_range(self.hot_file_count..self.num_source_files);
                let cold_path = self.source_file_path(mount_point, iteration, cold_idx);
                let cold_content = fs::read(&cold_path)?;
                std::hint::black_box(&cold_content);
            }

            report(1, Some(cycle + 1), Some(self.edit_cycles));
        }

        // ===== Phase 3: Save & Build =====
        // Total items: save hot files + read all files + write output files
        let phase3_total = self.hot_file_count + self.num_source_files + self.output_file_count;
        report(2, Some(0), Some(phase3_total));
        let mut completed = 0;

        // Write all modified hot files
        for &hot_idx in &hot_indices {
            let path = self.source_file_path(mount_point, iteration, hot_idx);
            let mut file = File::create(&path)?;
            file.write_all(&file_contents[hot_idx])?;
            safe_sync(&file)?;
            completed += 1;
            report(2, Some(completed), Some(phase3_total));
        }

        // Read all files (build/compile simulation)
        for i in 0..self.num_source_files {
            let path = self.source_file_path(mount_point, iteration, i);
            let content = fs::read(&path)?;
            std::hint::black_box(&content);
            completed += 1;
            if i % 10 == 0 || i == self.num_source_files - 1 {
                report(2, Some(completed), Some(phase3_total));
            }
        }

        // Write output files
        for i in 0..self.output_file_count {
            let path = self.output_file_path(mount_point, iteration, i);
            let mut output_content = vec![0u8; 50 * 1024 + rng.random_range(0..50 * 1024)];
            rng.fill_bytes(&mut output_content);
            let mut file = File::create(&path)?;
            file.write_all(&output_content)?;
            safe_sync(&file)?;
            completed += 1;
            report(2, Some(completed), Some(phase3_total));
        }

        Ok(start.elapsed())
    }
}
