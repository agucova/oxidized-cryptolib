//! Media Streaming Workload
//!
//! Simulates video player access patterns:
//! - Initial buffering (large sequential read)
//! - Steady playback (sequential reads with pauses)
//! - User seeks (random position jumps)
//! - Resume playback after seeks
//!
//! Supports real video assets (Blender Foundation CC-BY) for authentic MP4
//! container seeking patterns, or synthetic fallback for CI/quick mode.
//!
//! Tests large sequential reads, prefetch behavior, and seek performance.

// Allow numeric casts for file sizes
#![allow(clippy::cast_possible_truncation)]

use crate::assets::{AssetDownloader, manifest};
use crate::bench::workloads::{copy_file_contents, WorkloadConfig};
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
use crate::config::OperationType;
use anyhow::{Context, Result};
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Base values for full-scale workload
const BASE_MEDIA_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB media file (synthetic)
const BASE_INITIAL_BUFFER_SIZE: usize = 2 * 1024 * 1024; // 2MB initial buffer
const BASE_PLAYBACK_READ_TOTAL: usize = 20 * 1024 * 1024; // 20MB playback
const BASE_NUM_SEEKS: usize = 5;
const BASE_SEEK_READ_SIZE: usize = 1024 * 1024; // 1MB per seek
const BASE_RESUME_READ_SIZE: usize = 10 * 1024 * 1024; // 10MB resume

// Minimum values
const MIN_MEDIA_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MIN_INITIAL_BUFFER_SIZE: usize = 512 * 1024; // 512KB
const MIN_PLAYBACK_READ_TOTAL: usize = 2 * 1024 * 1024; // 2MB
const MIN_NUM_SEEKS: usize = 2;
const MIN_SEEK_READ_SIZE: usize = 256 * 1024; // 256KB
const MIN_RESUME_READ_SIZE: usize = 1024 * 1024; // 1MB

// Fixed technical parameters (not scaled)
const CHUNK_SIZE: usize = 256 * 1024; // 256KB streaming chunks (player buffer size)
const PLAYBACK_PAUSE_MS: u64 = 50; // Reduced from 500ms for faster benchmarks

/// Media workload phases for progress reporting.
const MEDIA_PHASES: &[&str] = &[
    "Initial buffering",
    "Steady playback",
    "User seeks",
    "Resume playback",
];

/// Media Streaming Workload.
///
/// Phases:
/// 1. Initial buffering - Sequential read of first 2MB
/// 2. Steady playback - Sequential 256KB chunks with brief pauses
/// 3. User seeks - Jump to 5 random positions, read 1MB each
/// 4. Resume playback - Sequential read 10MB from last position
///
/// When `use_real_assets` is enabled, downloads and uses real Blender
/// Foundation videos (Big Buck Bunny, Sintel) which provide authentic
/// MP4 container seeking patterns.
pub struct MediaStreamingWorkload {
    config: WorkloadConfig,
    seed: u64,
    use_real_assets: bool,
    media_file_size: usize,
    initial_buffer_size: usize,
    playback_read_total: usize,
    num_seeks: usize,
    seek_read_size: usize,
    resume_read_size: usize,
}

impl MediaStreamingWorkload {
    /// Create a new media streaming workload.
    pub fn new(config: WorkloadConfig) -> Self {
        let use_real_assets = config.real_assets;
        let media_file_size = config.scale_count(BASE_MEDIA_FILE_SIZE, MIN_MEDIA_FILE_SIZE);
        let initial_buffer_size = config.scale_count(BASE_INITIAL_BUFFER_SIZE, MIN_INITIAL_BUFFER_SIZE);
        let playback_read_total = config.scale_count(BASE_PLAYBACK_READ_TOTAL, MIN_PLAYBACK_READ_TOTAL);
        let num_seeks = config.scale_count(BASE_NUM_SEEKS, MIN_NUM_SEEKS);
        let seek_read_size = config.scale_count(BASE_SEEK_READ_SIZE, MIN_SEEK_READ_SIZE);
        let resume_read_size = config.scale_count(BASE_RESUME_READ_SIZE, MIN_RESUME_READ_SIZE);

        Self {
            config,
            seed: 0x00ED_1A57,
            use_real_assets,
            media_file_size,
            initial_buffer_size,
            playback_read_total,
            num_seeks,
            seek_read_size,
            resume_read_size,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_media_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn media_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("video.mp4")
    }

    /// Download real video asset and return the local path.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn download_real_asset(&self) -> Result<PathBuf> {
        let downloader = AssetDownloader::new()?;

        // Use Big Buck Bunny 480p (~150MB) as primary asset
        let path = downloader
            .ensure(&manifest::MEDIA_BBB_480P)
            .context("Failed to download Big Buck Bunny video")?;

        Ok(path)
    }

    /// Generate pseudo-media file content.
    /// Real video files have structured headers and variable-rate data.
    fn generate_media_content(&self, rng: &mut ChaCha8Rng) -> Vec<u8> {
        let mut content = Vec::with_capacity(self.media_file_size);

        // Fake MP4 header (first 1KB)
        let mut header = vec![0u8; 1024];
        header[0..4].copy_from_slice(b"\x00\x00\x00\x20"); // Box size
        header[4..8].copy_from_slice(b"ftyp"); // File type box
        header[8..12].copy_from_slice(b"mp42"); // Brand
        rng.fill_bytes(&mut header[12..]);
        content.extend_from_slice(&header);

        // Fill rest with pseudo-random "compressed video data"
        // Real video has variable compression, but we use random data
        // to prevent filesystem-level deduplication
        while content.len() < self.media_file_size {
            let chunk_size = 64 * 1024; // 64KB chunks
            let mut chunk = vec![0u8; chunk_size.min(self.media_file_size - content.len())];
            rng.fill_bytes(&mut chunk);
            content.extend_from_slice(&chunk);
        }

        content
    }
}

impl Default for MediaStreamingWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for MediaStreamingWorkload {
    fn name(&self) -> &'static str {
        "Video Playback"
    }

    fn operation(&self) -> OperationType {
        OperationType::MediaStreamingWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        let file_size = if self.use_real_assets {
            manifest::MEDIA_BBB_480P.size as usize
        } else {
            self.media_file_size
        };
        params.insert(
            "file_size".to_string(),
            format!("{}MB", file_size / (1024 * 1024)),
        );
        params.insert(
            "initial_buffer".to_string(),
            format!("{}MB", self.initial_buffer_size / (1024 * 1024)),
        );
        params.insert(
            "chunk_size".to_string(),
            format!("{}KB", CHUNK_SIZE / 1024),
        );
        params.insert(
            "playback_read".to_string(),
            format!("{}MB", self.playback_read_total / (1024 * 1024)),
        );
        params.insert("seeks".to_string(), self.num_seeks.to_string());
        params.insert(
            "seek_read_size".to_string(),
            format!("{}MB", self.seek_read_size / (1024 * 1024)),
        );
        params.insert(
            "resume_read_size".to_string(),
            format!("{}MB", self.resume_read_size / (1024 * 1024)),
        );
        params.insert(
            "asset_type".to_string(),
            if self.use_real_assets { "real" } else { "synthetic" }.to_string(),
        );
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        // Create workload directory
        fs::create_dir_all(self.workload_dir(mount_point, iteration))?;

        let media_dest = self.media_path(mount_point, iteration);

        if self.use_real_assets {
            // Download and copy real video asset
            tracing::info!("Using real video asset for media streaming workload");
            let asset_path = self.download_real_asset()?;

            // Copy to vault (can't use hardlink across filesystems)
            copy_file_contents(&asset_path, &media_dest)
                .with_context(|| format!("Failed to copy {} to vault", asset_path.display()))?;
        } else {
            // Generate synthetic media content
            let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
            let content = self.generate_media_content(&mut rng);
            let mut file = File::create(&media_dest)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let media_path = self.media_path(mount_point, iteration);
        let mut file = File::open(&media_path)?;

        // Get actual file size for seek calculations
        let file_size = file.metadata()?.len() as usize;

        // ===== Phase 1: Initial buffering =====
        {
            let buffer_size = self.initial_buffer_size.min(file_size);
            let mut buffer = vec![0u8; buffer_size];
            file.read_exact(&mut buffer)?;
            std::hint::black_box(&buffer);
        }

        // ===== Phase 2: Steady playback =====
        {
            let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
            let mut total_read = self.initial_buffer_size;
            let playback_target = self.playback_read_total.min(file_size.saturating_sub(self.initial_buffer_size));

            while total_read < self.initial_buffer_size + playback_target {
                let n = file.read(&mut chunk_buffer)?;
                if n == 0 {
                    break;
                }
                std::hint::black_box(&chunk_buffer[..n]);
                total_read += n;

                // Brief pause to simulate playback consumption
                std::thread::sleep(Duration::from_millis(PLAYBACK_PAUSE_MS));
            }
        }

        // ===== Phase 3: User seeks =====
        let mut last_seek_position = 0u64;
        {
            let mut seek_buffer = vec![0u8; self.seek_read_size];

            for _ in 0..self.num_seeks {
                // Random seek position (avoiding the very end)
                let max_offset = file_size.saturating_sub(self.seek_read_size);
                if max_offset == 0 {
                    break;
                }
                let seek_pos = rng.random_range(0..max_offset) as u64;

                file.seek(SeekFrom::Start(seek_pos))?;
                file.read_exact(&mut seek_buffer)?;
                std::hint::black_box(&seek_buffer);

                last_seek_position = seek_pos + self.seek_read_size as u64;

                // Brief pause (user watching at new position)
                std::thread::sleep(Duration::from_millis(PLAYBACK_PAUSE_MS * 2));
            }
        }

        // ===== Phase 4: Resume playback from last seek =====
        {
            // Seek to continue from last position
            file.seek(SeekFrom::Start(last_seek_position))?;

            let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
            let mut total_read = 0;

            while total_read < self.resume_read_size {
                let n = file.read(&mut chunk_buffer)?;
                if n == 0 {
                    break;
                }
                std::hint::black_box(&chunk_buffer[..n]);
                total_read += n;

                // Brief pause
                std::thread::sleep(Duration::from_millis(PLAYBACK_PAUSE_MS));
            }
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
        0 // No warmup - media streaming is stateful
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(MEDIA_PHASES)
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
                    phase_name: MEDIA_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: MEDIA_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let media_path = self.media_path(mount_point, iteration);
        let mut file = File::open(&media_path)?;

        // Get actual file size for seek calculations
        let file_size = file.metadata()?.len() as usize;

        // ===== Phase 1: Initial buffering =====
        report(0, Some(0), Some(self.initial_buffer_size));
        {
            let buffer_size = self.initial_buffer_size.min(file_size);
            let mut buffer = vec![0u8; buffer_size];
            file.read_exact(&mut buffer)?;
            std::hint::black_box(&buffer);
        }
        report(0, Some(self.initial_buffer_size), Some(self.initial_buffer_size));

        // ===== Phase 2: Steady playback =====
        let playback_target = self.playback_read_total.min(file_size.saturating_sub(self.initial_buffer_size));
        report(1, Some(0), Some(playback_target));
        {
            let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
            let mut total_read = 0;

            while total_read < playback_target {
                let n = file.read(&mut chunk_buffer)?;
                if n == 0 {
                    break;
                }
                std::hint::black_box(&chunk_buffer[..n]);
                total_read += n;

                if total_read % (CHUNK_SIZE * 4) == 0 || total_read >= playback_target {
                    report(1, Some(total_read), Some(playback_target));
                }

                std::thread::sleep(Duration::from_millis(PLAYBACK_PAUSE_MS));
            }
        }

        // ===== Phase 3: User seeks =====
        report(2, Some(0), Some(self.num_seeks));
        let mut last_seek_position = 0u64;
        {
            let mut seek_buffer = vec![0u8; self.seek_read_size];

            for i in 0..self.num_seeks {
                let max_offset = file_size.saturating_sub(self.seek_read_size);
                if max_offset == 0 {
                    break;
                }
                let seek_pos = rng.random_range(0..max_offset) as u64;

                file.seek(SeekFrom::Start(seek_pos))?;
                file.read_exact(&mut seek_buffer)?;
                std::hint::black_box(&seek_buffer);

                last_seek_position = seek_pos + self.seek_read_size as u64;
                report(2, Some(i + 1), Some(self.num_seeks));

                std::thread::sleep(Duration::from_millis(PLAYBACK_PAUSE_MS * 2));
            }
        }

        // ===== Phase 4: Resume playback from last seek =====
        report(3, Some(0), Some(self.resume_read_size));
        {
            file.seek(SeekFrom::Start(last_seek_position))?;

            let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
            let mut total_read = 0;

            while total_read < self.resume_read_size {
                let n = file.read(&mut chunk_buffer)?;
                if n == 0 {
                    break;
                }
                std::hint::black_box(&chunk_buffer[..n]);
                total_read += n;

                if total_read % (CHUNK_SIZE * 4) == 0 || total_read >= self.resume_read_size {
                    report(3, Some(total_read), Some(self.resume_read_size));
                }

                std::thread::sleep(Duration::from_millis(PLAYBACK_PAUSE_MS));
            }
        }

        Ok(start.elapsed())
    }
}
