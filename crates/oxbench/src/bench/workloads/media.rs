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

use crate::assets::{AssetDownloader, manifest};
use crate::bench::Benchmark;
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

const MEDIA_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB media file (synthetic)
const INITIAL_BUFFER_SIZE: usize = 2 * 1024 * 1024; // 2MB initial buffer
const CHUNK_SIZE: usize = 256 * 1024; // 256KB streaming chunks
const PLAYBACK_READ_TOTAL: usize = 20 * 1024 * 1024; // 20MB playback
const NUM_SEEKS: usize = 5;
const SEEK_READ_SIZE: usize = 1024 * 1024; // 1MB per seek
const RESUME_READ_SIZE: usize = 10 * 1024 * 1024; // 10MB resume
const PLAYBACK_PAUSE_MS: u64 = 50; // Reduced from 500ms for faster benchmarks

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
    seed: u64,
    /// Whether to use real downloaded video assets.
    use_real_assets: bool,
}

impl MediaStreamingWorkload {
    /// Create a new media streaming workload with synthetic content.
    pub fn new() -> Self {
        Self {
            seed: 0x00ED_1A57,
            use_real_assets: false,
        }
    }

    /// Create a new media streaming workload with real downloaded assets.
    ///
    /// Downloads real Blender Foundation videos (CC-BY licensed) for
    /// authentic MP4 container structure and seeking patterns.
    pub fn with_real_assets() -> Self {
        Self {
            seed: 0x00ED_1A57,
            use_real_assets: true,
        }
    }

    /// Set whether to use real assets.
    pub fn set_real_assets(&mut self, use_real: bool) {
        self.use_real_assets = use_real;
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_media_workload")
    }

    fn media_path(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("video.mp4")
    }

    /// Download real video asset and return the local path.
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
        let mut content = Vec::with_capacity(MEDIA_FILE_SIZE);

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
        while content.len() < MEDIA_FILE_SIZE {
            let chunk_size = 64 * 1024; // 64KB chunks
            let mut chunk = vec![0u8; chunk_size.min(MEDIA_FILE_SIZE - content.len())];
            rng.fill_bytes(&mut chunk);
            content.extend_from_slice(&chunk);
        }

        content
    }
}

impl Default for MediaStreamingWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for MediaStreamingWorkload {
    fn name(&self) -> &str {
        "Media Streaming"
    }

    fn operation(&self) -> OperationType {
        OperationType::MediaStreamingWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        let file_size = if self.use_real_assets {
            manifest::MEDIA_BBB_480P.size as usize
        } else {
            MEDIA_FILE_SIZE
        };
        params.insert(
            "file_size".to_string(),
            format!("{}MB", file_size / (1024 * 1024)),
        );
        params.insert(
            "initial_buffer".to_string(),
            format!("{}MB", INITIAL_BUFFER_SIZE / (1024 * 1024)),
        );
        params.insert(
            "chunk_size".to_string(),
            format!("{}KB", CHUNK_SIZE / 1024),
        );
        params.insert(
            "playback_read".to_string(),
            format!("{}MB", PLAYBACK_READ_TOTAL / (1024 * 1024)),
        );
        params.insert("seeks".to_string(), NUM_SEEKS.to_string());
        params.insert(
            "asset_type".to_string(),
            if self.use_real_assets { "real" } else { "synthetic" }.to_string(),
        );
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        // Create workload directory
        fs::create_dir_all(self.workload_dir(mount_point))?;

        let media_dest = self.media_path(mount_point);

        if self.use_real_assets {
            // Download and copy real video asset
            tracing::info!("Using real video asset for media streaming workload");
            let asset_path = self.download_real_asset()?;

            // Copy to vault (can't use hardlink across filesystems)
            std::fs::copy(&asset_path, &media_dest)
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

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let media_path = self.media_path(mount_point);
        let mut file = File::open(&media_path)?;

        // Get actual file size for seek calculations
        let file_size = file.metadata()?.len() as usize;

        // ===== Phase 1: Initial buffering =====
        {
            let buffer_size = INITIAL_BUFFER_SIZE.min(file_size);
            let mut buffer = vec![0u8; buffer_size];
            file.read_exact(&mut buffer)?;
            std::hint::black_box(&buffer);
        }

        // ===== Phase 2: Steady playback =====
        {
            let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
            let mut total_read = INITIAL_BUFFER_SIZE;
            let playback_target = PLAYBACK_READ_TOTAL.min(file_size.saturating_sub(INITIAL_BUFFER_SIZE));

            while total_read < INITIAL_BUFFER_SIZE + playback_target {
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
            let mut seek_buffer = vec![0u8; SEEK_READ_SIZE];

            for _ in 0..NUM_SEEKS {
                // Random seek position (avoiding the very end)
                let max_offset = file_size.saturating_sub(SEEK_READ_SIZE);
                if max_offset == 0 {
                    break;
                }
                let seek_pos = rng.random_range(0..max_offset) as u64;

                file.seek(SeekFrom::Start(seek_pos))?;
                file.read_exact(&mut seek_buffer)?;
                std::hint::black_box(&seek_buffer);

                last_seek_position = seek_pos + SEEK_READ_SIZE as u64;

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

            while total_read < RESUME_READ_SIZE {
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

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        0 // No warmup - media streaming is stateful
    }
}
