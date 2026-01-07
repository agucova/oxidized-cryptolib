//! Asset downloader with verification.
//!
//! Downloads benchmark assets with progress tracking and SHA256 verification.

use super::cache::AssetCache;
use super::manifest::Asset;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

/// Progress callback for download updates.
pub type ProgressCallback = Arc<dyn Fn(DownloadProgress) + Send + Sync>;

/// Download progress information.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Asset being downloaded.
    pub asset_id: String,
    /// Asset name for display.
    pub asset_name: String,
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// Total bytes to download.
    pub total: u64,
    /// Current download speed in bytes per second.
    pub bytes_per_sec: f64,
    /// Whether the download is complete.
    pub complete: bool,
}

impl DownloadProgress {
    /// Get progress as a percentage (0-100).
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.downloaded as f64 / self.total as f64) * 100.0
        }
    }
}

/// Asset downloader.
pub struct AssetDownloader {
    cache: AssetCache,
    progress_callback: Option<ProgressCallback>,
    /// Skip hash verification (for testing).
    skip_verify: bool,
}

impl AssetDownloader {
    /// Create a new downloader with the default cache.
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: AssetCache::new()?,
            progress_callback: None,
            skip_verify: false,
        })
    }

    /// Create a downloader with a custom cache.
    pub fn with_cache(cache: AssetCache) -> Self {
        Self {
            cache,
            progress_callback: None,
            skip_verify: false,
        }
    }

    /// Set a progress callback.
    #[must_use]
    pub fn with_progress(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Skip hash verification (for development/testing).
    #[must_use]
    pub fn skip_verification(mut self) -> Self {
        self.skip_verify = true;
        self
    }

    /// Get the cache.
    pub fn cache(&self) -> &AssetCache {
        &self.cache
    }

    /// Ensure an asset is downloaded and return its local path.
    ///
    /// If already cached and valid, returns immediately.
    pub fn ensure(&self, asset: &Asset) -> Result<PathBuf> {
        let path = self.cache.asset_path(asset);

        // Check if already cached
        if self.cache.is_cached(asset) {
            tracing::debug!("Asset {} already cached at {:?}", asset.id, path);
            return Ok(path);
        }

        // Ensure cache directories exist
        self.cache.ensure_dirs()?;

        // Download the asset
        self.download(asset)?;

        Ok(path)
    }

    /// Force re-download an asset even if cached.
    pub fn refresh(&self, asset: &Asset) -> Result<PathBuf> {
        // Remove existing cached file
        self.cache.remove(asset)?;

        // Download fresh
        self.ensure(asset)
    }

    /// Download an asset.
    fn download(&self, asset: &Asset) -> Result<()> {
        let dest_path = self.cache.asset_path(asset);

        tracing::info!("Downloading {} (~{})", asset.name, super::cache::format_size(asset.size));

        // Try each URL until one succeeds
        let mut last_error = None;
        for url in asset.all_urls() {
            tracing::debug!("Trying URL: {}", url);

            match self.download_from_url(asset, url, &dest_path) {
                Ok(()) => {
                    // Verify the download
                    if !self.skip_verify {
                        Self::verify(asset, &dest_path)?;
                    }
                    tracing::info!("Downloaded {} successfully", asset.name);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Download from {} failed: {}", url, e);
                    last_error = Some(e);
                    // Clean up partial download
                    let _ = fs::remove_file(&dest_path);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No URLs available for {}", asset.id)))
    }

    /// Download from a specific URL.
    fn download_from_url(&self, asset: &Asset, url: &str, dest_path: &PathBuf) -> Result<()> {
        let response = ureq::get(url)
            .call()
            .with_context(|| format!("Failed to connect to {url}"))?;

        let total_size = response
            .headers()
            .get("Content-Length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(asset.size);

        let mut reader = response.into_body().into_reader();
        let mut file = File::create(dest_path)
            .with_context(|| format!("Failed to create {}", dest_path.display()))?;

        let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer
        let mut downloaded = 0u64;
        let mut last_progress_time = std::time::Instant::now();
        let mut last_progress_bytes = 0u64;
        let start_time = std::time::Instant::now();

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .context("Failed to read from network")?;

            if bytes_read == 0 {
                break;
            }

            file.write_all(&buffer[..bytes_read])
                .context("Failed to write to file")?;

            downloaded += bytes_read as u64;

            // Report progress
            if let Some(ref callback) = self.progress_callback {
                let now = std::time::Instant::now();
                let elapsed = now.duration_since(last_progress_time).as_secs_f64();

                // Update speed every 100ms
                let bytes_per_sec = if elapsed > 0.1 {
                    let speed = (downloaded - last_progress_bytes) as f64 / elapsed;
                    last_progress_time = now;
                    last_progress_bytes = downloaded;
                    speed
                } else {
                    // Use overall average speed
                    let total_elapsed = now.duration_since(start_time).as_secs_f64();
                    if total_elapsed > 0.0 {
                        downloaded as f64 / total_elapsed
                    } else {
                        0.0
                    }
                };

                callback(DownloadProgress {
                    asset_id: asset.id.to_string(),
                    asset_name: asset.name.to_string(),
                    downloaded,
                    total: total_size,
                    bytes_per_sec,
                    complete: false,
                });
            }
        }

        file.sync_all().context("Failed to sync file")?;

        // Final progress update
        if let Some(ref callback) = self.progress_callback {
            let total_elapsed = start_time.elapsed().as_secs_f64();
            callback(DownloadProgress {
                asset_id: asset.id.to_string(),
                asset_name: asset.name.to_string(),
                downloaded,
                total: total_size,
                bytes_per_sec: if total_elapsed > 0.0 {
                    downloaded as f64 / total_elapsed
                } else {
                    0.0
                },
                complete: true,
            });
        }

        Ok(())
    }

    /// Verify a downloaded file's SHA256 hash.
    fn verify(asset: &Asset, path: &PathBuf) -> Result<()> {
        tracing::debug!("Verifying hash for {}", asset.name);

        let mut file = File::open(path)
            .with_context(|| format!("Failed to open {} for verification", path.display()))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash);

        if asset.sha256.len() != 64 || !asset.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "Invalid SHA256 for {} ({}): expected 64 hex chars, got {}",
                asset.name,
                asset.id,
                asset.sha256
            );
        }

        if hash_hex != asset.sha256 {
            bail!(
                "Hash mismatch for {}: expected {}, got {}",
                asset.name,
                asset.sha256,
                hash_hex
            );
        }

        Ok(())
    }

    /// Download multiple assets in parallel.
    pub fn ensure_all(&self, assets: &[&Asset]) -> Result<Vec<PathBuf>> {
        // For now, download sequentially to avoid overwhelming the network
        // Could be parallelized with tokio in the future
        let mut paths = Vec::with_capacity(assets.len());
        for asset in assets {
            paths.push(self.ensure(asset)?);
        }
        Ok(paths)
    }
}

impl Default for AssetDownloader {
    fn default() -> Self {
        Self::new().expect("Failed to create default downloader")
    }
}

/// Download all assets for a category.
pub fn download_category(
    downloader: &AssetDownloader,
    category: super::manifest::AssetCategory,
) -> Result<Vec<PathBuf>> {
    let assets = super::manifest::assets_by_category(category);
    let mut paths = Vec::with_capacity(assets.len());

    for asset in assets {
        paths.push(downloader.ensure(asset)?);
    }

    Ok(paths)
}

/// Download all benchmark assets.
pub fn download_all(downloader: &AssetDownloader) -> Result<Vec<PathBuf>> {
    let assets = super::manifest::all_assets();
    let mut paths = Vec::with_capacity(assets.len());

    for asset in assets {
        paths.push(downloader.ensure(asset)?);
    }

    Ok(paths)
}
