//! Photo Library Workload
//!
//! Simulates a photo management application:
//! - Import (copy photos to vault)
//! - Thumbnail scan (read first 64KB - EXIF region)
//! - Metadata reads (repeated small reads at file headers)
//! - Full resolution load (read entire files)
//! - Slideshow (sequential reads with timing gaps)
//! - Export (copy files out)
//!
//! Supports real photo assets (Kodak True Color, CC0) or synthetic
//! fallback with JPEG-like headers for CI/quick mode.
//!
//! Tests small random reads, large sequential reads, and copy operations.

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
const BASE_NUM_SMALL_PHOTOS: usize = 50;
const BASE_NUM_MEDIUM_PHOTOS: usize = 20;
const BASE_NUM_LARGE_PHOTOS: usize = 10;
const BASE_FULL_LOAD_SAMPLE: usize = 10;
const BASE_SLIDESHOW_COUNT: usize = 20;
const BASE_EXPORT_COUNT: usize = 5;

// Minimum values
const MIN_NUM_SMALL_PHOTOS: usize = 10;
const MIN_NUM_MEDIUM_PHOTOS: usize = 5;
const MIN_NUM_LARGE_PHOTOS: usize = 2;
const MIN_FULL_LOAD_SAMPLE: usize = 2;
const MIN_SLIDESHOW_COUNT: usize = 5;
const MIN_EXPORT_COUNT: usize = 2;

// Photo sizes (not scaled - individual photo sizes should remain realistic)
const SMALL_PHOTO_SIZE: usize = 2 * 1024 * 1024;    // 2MB (typical JPEG)
const MEDIUM_PHOTO_SIZE: usize = 8 * 1024 * 1024;   // 8MB (high-res JPEG)
const LARGE_PHOTO_SIZE: usize = 25 * 1024 * 1024;   // 25MB (RAW simulation)

// Fixed technical parameters (not scaled)
const EXIF_REGION_SIZE: usize = 64 * 1024;  // First 64KB contains EXIF
const METADATA_READ_SIZE: usize = 256;       // Small EXIF tag read
const SLIDESHOW_PAUSE_MS: u64 = 100;         // Pause between slides

/// Photo workload phases for progress reporting.
const PHOTO_PHASES: &[&str] = &[
    "Thumbnail scan",
    "Metadata reads",
    "Full resolution",
    "Slideshow",
    "Export",
];

/// Photo Library Workload.
///
/// Phases:
/// 1. Import - Write photos to vault
/// 2. Thumbnail scan - Read first 64KB of each file (EXIF region)
/// 3. Metadata reads - Read small chunks at file headers
/// 4. Full resolution load - Read entire files
/// 5. Slideshow - Sequential reads with timing gaps
/// 6. Export - Copy files to temp directory
///
/// When `use_real_assets` is enabled, downloads and uses real photos
/// from the Kodak True Color suite (Public Domain) for authentic
/// JPEG/PNG file structure patterns.
pub struct PhotoLibraryWorkload {
    config: WorkloadConfig,
    seed: u64,
    use_real_assets: bool,
    num_small_photos: usize,
    num_medium_photos: usize,
    num_large_photos: usize,
    full_load_sample: usize,
    slideshow_count: usize,
    export_count: usize,
}

impl PhotoLibraryWorkload {
    /// Create a new photo library workload.
    pub fn new(config: WorkloadConfig) -> Self {
        let use_real_assets = config.real_assets;
        let num_small_photos = config.scale_count(BASE_NUM_SMALL_PHOTOS, MIN_NUM_SMALL_PHOTOS);
        let num_medium_photos = config.scale_count(BASE_NUM_MEDIUM_PHOTOS, MIN_NUM_MEDIUM_PHOTOS);
        let num_large_photos = config.scale_count(BASE_NUM_LARGE_PHOTOS, MIN_NUM_LARGE_PHOTOS);
        let full_load_sample = config.scale_count(BASE_FULL_LOAD_SAMPLE, MIN_FULL_LOAD_SAMPLE);
        let slideshow_count = config.scale_count(BASE_SLIDESHOW_COUNT, MIN_SLIDESHOW_COUNT);
        let export_count = config.scale_count(BASE_EXPORT_COUNT, MIN_EXPORT_COUNT);

        Self {
            config,
            seed: 0x0F07_01AB,
            use_real_assets,
            num_small_photos,
            num_medium_photos,
            num_large_photos,
            full_load_sample,
            slideshow_count,
            export_count,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_photo_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn photos_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("photos")
    }

    fn export_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("export")
    }

    /// Download real photo assets and return list of paths.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn download_real_assets(&self) -> Result<Vec<PathBuf>> {
        let downloader = AssetDownloader::new()?;

        // Try to get Kodak images first
        match downloader.ensure(&manifest::PHOTO_KODAK) {
            Ok(archive_path) => {
                // Extract the archive to get individual images
                let cache_dir = archive_path.parent()
                    .context("Invalid archive path")?;
                let extract_dir = cache_dir.join("kodak-extracted");

                if !extract_dir.exists() {
                    // Extract tar.gz
                    let file = File::open(&archive_path)?;
                    let gz = flate2::read::GzDecoder::new(file);
                    let mut archive = tar::Archive::new(gz);
                    archive.unpack(&extract_dir)?;
                }

                // Collect extracted image files (recursive to handle nested archives).
                let mut images = Vec::new();
                let mut pending_dirs = vec![extract_dir.clone()];
                while let Some(dir) = pending_dirs.pop() {
                    for entry in fs::read_dir(&dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() {
                            pending_dirs.push(path);
                            continue;
                        }

                        if let Some(ext) = path.extension() {
                            let ext = ext.to_string_lossy().to_lowercase();
                            if ext == "png" || ext == "jpg" || ext == "jpeg" {
                                images.push(path);
                            }
                        }
                    }
                }

                if images.is_empty() {
                    anyhow::bail!("No images found in Kodak archive");
                }

                Ok(images)
            }
            Err(e) => {
                tracing::warn!("Failed to download Kodak images: {}, using synthetic", e);
                Err(e)
            }
        }
    }

    /// Generate synthetic photo content with JPEG-like headers.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn generate_synthetic_photo(&self, rng: &mut ChaCha8Rng, size: usize) -> Vec<u8> {
        let mut content = Vec::with_capacity(size);

        // JPEG-like magic bytes and fake EXIF header
        // Real JPEG: FF D8 FF E1 <len> "Exif\0\0" + TIFF header
        content.extend_from_slice(&[
            0xFF, 0xD8, 0xFF, 0xE1,  // JPEG SOI + APP1 marker
            0x00, 0x60,              // APP1 length (96 bytes for fake EXIF)
            b'E', b'x', b'i', b'f', 0x00, 0x00,  // "Exif\0\0"
            // Fake TIFF header (big-endian)
            0x4D, 0x4D,  // "MM" (big-endian)
            0x00, 0x2A,  // TIFF magic
            0x00, 0x00, 0x00, 0x08,  // Offset to first IFD
        ]);

        // Fill rest of EXIF region with structured-looking data
        while content.len() < EXIF_REGION_SIZE.min(size) {
            // Fake EXIF tags (tag, type, count, value)
            let tag: u16 = rng.random_range(0x0100..0x9999);
            content.extend_from_slice(&tag.to_be_bytes());
            content.extend_from_slice(&[0x00, 0x02]);  // ASCII type
            content.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);  // count
            // Random value bytes
            let mut val = [0u8; 4];
            rng.fill_bytes(&mut val);
            content.extend_from_slice(&val);
        }

        // Fill rest with "compressed image data"
        while content.len() < size {
            let chunk_size = 64 * 1024;
            let remaining = size - content.len();
            let mut chunk = vec![0u8; chunk_size.min(remaining)];
            rng.fill_bytes(&mut chunk);
            content.extend_from_slice(&chunk);
        }

        // JPEG EOI marker at end
        if content.len() >= 2 {
            let len = content.len();
            content[len - 2] = 0xFF;
            content[len - 1] = 0xD9;
        }

        content
    }

    /// Get list of photo files in the workload directory.
    fn list_photos(&self, mount_point: &Path, iteration: usize) -> Result<Vec<PathBuf>> {
        let photos_dir = self.photos_dir(mount_point, iteration);
        let mut photos = Vec::new();

        for entry in fs::read_dir(&photos_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                photos.push(path);
            }
        }

        photos.sort();
        Ok(photos)
    }
}

impl Default for PhotoLibraryWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for PhotoLibraryWorkload {
    fn name(&self) -> &'static str {
        "Photo Library"
    }

    fn operation(&self) -> OperationType {
        OperationType::PhotoLibraryWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();

        if self.use_real_assets {
            params.insert("asset_type".to_string(), "real".to_string());
            params.insert("source".to_string(), "Kodak True Color".to_string());
        } else {
            let total_photos = self.num_small_photos + self.num_medium_photos + self.num_large_photos;
            let total_size = self.num_small_photos * SMALL_PHOTO_SIZE
                + self.num_medium_photos * MEDIUM_PHOTO_SIZE
                + self.num_large_photos * LARGE_PHOTO_SIZE;

            params.insert("asset_type".to_string(), "synthetic".to_string());
            params.insert("small_photos".to_string(), self.num_small_photos.to_string());
            params.insert("medium_photos".to_string(), self.num_medium_photos.to_string());
            params.insert("large_photos".to_string(), self.num_large_photos.to_string());
            params.insert("photo_count".to_string(), total_photos.to_string());
            params.insert(
                "total_size".to_string(),
                format!("{}MB", total_size / (1024 * 1024)),
            );
        }

        params.insert("full_load_sample".to_string(), self.full_load_sample.to_string());
        params.insert("slideshow_count".to_string(), self.slideshow_count.to_string());
        params.insert("export_count".to_string(), self.export_count.to_string());
        params.insert(
            "exif_region".to_string(),
            format!("{}KB", EXIF_REGION_SIZE / 1024),
        );
        params.insert("scale".to_string(), format!("{:.2}", self.config.scale));
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        // Create directories
        fs::create_dir_all(self.photos_dir(mount_point, iteration))?;
        fs::create_dir_all(self.export_dir(mount_point, iteration))?;

        let photos_dir = self.photos_dir(mount_point, iteration);

        if self.use_real_assets {
            // Try to download and copy real photos
            match self.download_real_assets() {
                Ok(asset_paths) => {
                    tracing::info!("Using {} real photo assets", asset_paths.len());
                    for (i, src_path) in asset_paths.iter().enumerate() {
                        let filename = src_path.file_name().map_or_else(|| format!("photo_{i:04}.jpg"), |n| n.to_string_lossy().to_string());
                        let dest_path = photos_dir.join(&filename);
                        copy_file_contents(src_path, &dest_path)
                            .with_context(|| format!("Failed to copy {}", src_path.display()))?;
                    }
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to get real assets, falling back to synthetic: {}", e);
                }
            }
        }

        // Generate synthetic photos
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let mut photo_num = 0;

        // Small photos (typical JPEGs)
        for _ in 0..self.num_small_photos {
            let content = self.generate_synthetic_photo(&mut rng, SMALL_PHOTO_SIZE);
            let path = photos_dir.join(format!("photo_{photo_num:04}.jpg"));
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
            photo_num += 1;
        }

        // Medium photos (high-res)
        for _ in 0..self.num_medium_photos {
            let content = self.generate_synthetic_photo(&mut rng, MEDIUM_PHOTO_SIZE);
            let path = photos_dir.join(format!("photo_{photo_num:04}.jpg"));
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
            photo_num += 1;
        }

        // Large photos (RAW simulation)
        for _ in 0..self.num_large_photos {
            let content = self.generate_synthetic_photo(&mut rng, LARGE_PHOTO_SIZE);
            let path = photos_dir.join(format!("photo_{photo_num:04}.raw"));
            let mut file = File::create(&path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
            photo_num += 1;
        }

        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let photos = self.list_photos(mount_point, iteration)?;
        if photos.is_empty() {
            anyhow::bail!("No photos found in workload directory");
        }

        // ===== Phase 1: Thumbnail scan (EXIF region reads) =====
        // Simulates photo app building thumbnail cache
        {
            let mut exif_buffer = vec![0u8; EXIF_REGION_SIZE];
            for photo_path in &photos {
                let mut file = File::open(photo_path)?;
                let bytes_read = file.read(&mut exif_buffer)?;
                std::hint::black_box(&exif_buffer[..bytes_read]);
            }
        }

        // ===== Phase 2: Metadata reads (small random reads) =====
        // Simulates reading specific EXIF tags
        {
            let mut metadata_buffer = vec![0u8; METADATA_READ_SIZE];
            let offsets = [0, 12, 64, 128, 256, 512, 1024, 2048, 4096];

            for photo_path in &photos {
                let mut file = File::open(photo_path)?;
                let file_size = file.metadata()?.len() as usize;

                for &offset in &offsets {
                    if offset + METADATA_READ_SIZE <= file_size {
                        file.seek(SeekFrom::Start(offset as u64))?;
                        file.read_exact(&mut metadata_buffer)?;
                        std::hint::black_box(&metadata_buffer);
                    }
                }
            }
        }

        // ===== Phase 3: Full resolution load =====
        // Simulates user opening photos for editing
        {
            let sample_count = self.full_load_sample.min(photos.len());
            let mut indices: Vec<usize> = (0..photos.len()).collect();
            indices.shuffle(&mut rng);

            for &idx in indices.iter().take(sample_count) {
                let photo_path = &photos[idx];
                let content = fs::read(photo_path)?;
                std::hint::black_box(&content);
            }
        }

        // ===== Phase 4: Slideshow =====
        // Sequential reads with timing gaps
        {
            let slideshow_count = self.slideshow_count.min(photos.len());
            let mut buffer = Vec::new();

            for photo_path in photos.iter().take(slideshow_count) {
                buffer.clear();
                let mut file = File::open(photo_path)?;
                file.read_to_end(&mut buffer)?;
                std::hint::black_box(&buffer);

                // Brief pause between slides
                std::thread::sleep(Duration::from_millis(SLIDESHOW_PAUSE_MS));
            }
        }

        // ===== Phase 5: Export (copy to export directory) =====
        // Simulates exporting selected photos
        {
            let export_dir = self.export_dir(mount_point, iteration);
            let export_count = self.export_count.min(photos.len());
            let mut indices: Vec<usize> = (0..photos.len()).collect();
            indices.shuffle(&mut rng);

            for &idx in indices.iter().take(export_count) {
                let src_path = &photos[idx];
                if let Some(filename) = src_path.file_name() {
                    let dest_path = export_dir.join(filename);
                    copy_file_contents(src_path, &dest_path)?;
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
        0 // No warmup - photo library is stateful
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(PHOTO_PHASES)
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
                    phase_name: PHOTO_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: PHOTO_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let photos = self.list_photos(mount_point, iteration)?;
        if photos.is_empty() {
            anyhow::bail!("No photos found in workload directory");
        }

        // ===== Phase 1: Thumbnail scan (EXIF region reads) =====
        report(0, Some(0), Some(photos.len()));
        {
            let mut exif_buffer = vec![0u8; EXIF_REGION_SIZE];
            for (i, photo_path) in photos.iter().enumerate() {
                let mut file = File::open(photo_path)?;
                let bytes_read = file.read(&mut exif_buffer)?;
                std::hint::black_box(&exif_buffer[..bytes_read]);
                if i % 10 == 0 || i == photos.len() - 1 {
                    report(0, Some(i + 1), Some(photos.len()));
                }
            }
        }

        // ===== Phase 2: Metadata reads (small random reads) =====
        let offsets = [0, 12, 64, 128, 256, 512, 1024, 2048, 4096];
        let total_reads = photos.len() * offsets.len();
        report(1, Some(0), Some(total_reads));
        {
            let mut metadata_buffer = vec![0u8; METADATA_READ_SIZE];
            let mut completed = 0;

            for photo_path in &photos {
                let mut file = File::open(photo_path)?;
                let file_size = file.metadata()?.len() as usize;

                for &offset in &offsets {
                    if offset + METADATA_READ_SIZE <= file_size {
                        file.seek(SeekFrom::Start(offset as u64))?;
                        file.read_exact(&mut metadata_buffer)?;
                        std::hint::black_box(&metadata_buffer);
                    }
                    completed += 1;
                }
                if completed % 50 == 0 {
                    report(1, Some(completed), Some(total_reads));
                }
            }
            report(1, Some(total_reads), Some(total_reads));
        }

        // ===== Phase 3: Full resolution load =====
        let sample_count = self.full_load_sample.min(photos.len());
        report(2, Some(0), Some(sample_count));
        {
            let mut indices: Vec<usize> = (0..photos.len()).collect();
            indices.shuffle(&mut rng);

            for (i, &idx) in indices.iter().take(sample_count).enumerate() {
                let photo_path = &photos[idx];
                let content = fs::read(photo_path)?;
                std::hint::black_box(&content);
                report(2, Some(i + 1), Some(sample_count));
            }
        }

        // ===== Phase 4: Slideshow =====
        let slideshow_count = self.slideshow_count.min(photos.len());
        report(3, Some(0), Some(slideshow_count));
        {
            let mut buffer = Vec::new();

            for (i, photo_path) in photos.iter().take(slideshow_count).enumerate() {
                buffer.clear();
                let mut file = File::open(photo_path)?;
                file.read_to_end(&mut buffer)?;
                std::hint::black_box(&buffer);

                std::thread::sleep(Duration::from_millis(SLIDESHOW_PAUSE_MS));
                report(3, Some(i + 1), Some(slideshow_count));
            }
        }

        // ===== Phase 5: Export (copy to export directory) =====
        let export_count = self.export_count.min(photos.len());
        report(4, Some(0), Some(export_count));
        {
            let export_dir = self.export_dir(mount_point, iteration);
            let mut indices: Vec<usize> = (0..photos.len()).collect();
            indices.shuffle(&mut rng);

            for (i, &idx) in indices.iter().take(export_count).enumerate() {
                let src_path = &photos[idx];
                if let Some(filename) = src_path.file_name() {
                    let dest_path = export_dir.join(filename);
                    copy_file_contents(src_path, &dest_path)?;
                }
                report(4, Some(i + 1), Some(export_count));
            }
        }

        Ok(start.elapsed())
    }
}
