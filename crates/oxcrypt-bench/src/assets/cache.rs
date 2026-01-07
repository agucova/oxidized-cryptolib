//! Asset cache management.
//!
//! Handles local storage of downloaded benchmark assets.

use super::manifest::{Asset, AssetCategory};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Cache directory for benchmark assets.
///
/// Default location: `~/.cache/oxbench/assets/`
#[derive(Debug, Clone)]
pub struct AssetCache {
    base_dir: PathBuf,
}

impl AssetCache {
    /// Create a new asset cache at the default location.
    pub fn new() -> Result<Self> {
        let base_dir = dirs::cache_dir()
            .context("Could not determine cache directory")?
            .join("oxbench")
            .join("assets");
        Ok(Self { base_dir })
    }

    /// Create a new asset cache at a custom location.
    pub fn with_path(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Get the base cache directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Get the directory for a specific category.
    pub fn category_dir(&self, category: AssetCategory) -> PathBuf {
        self.base_dir.join(category.dir_name())
    }

    /// Get the full path for an asset.
    pub fn asset_path(&self, asset: &Asset) -> PathBuf {
        self.category_dir(asset.category).join(asset.cache_filename())
    }

    /// Check if an asset is cached.
    pub fn is_cached(&self, asset: &Asset) -> bool {
        let path = self.asset_path(asset);
        if !path.exists() {
            return false;
        }

        // Verify file size matches expected
        if let Ok(metadata) = fs::metadata(&path) {
            // Allow some tolerance for size (within 1%)
            let expected = asset.size;
            let actual = metadata.len();
            let tolerance = expected / 100;
            actual >= expected.saturating_sub(tolerance) && actual <= expected.saturating_add(tolerance)
        } else {
            false
        }
    }

    /// Check if an asset is cached and has the correct hash.
    pub fn is_valid(&self, asset: &Asset) -> Result<bool> {
        if !self.is_cached(asset) {
            return Ok(false);
        }

        // For now, just check size. Full hash verification is expensive
        // and done during download.
        Ok(true)
    }

    /// Ensure the cache directory exists.
    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.base_dir)
            .context("Failed to create cache directory")?;

        // Create category subdirectories
        for category in &[
            AssetCategory::Media,
            AssetCategory::Photo,
            AssetCategory::Archive,
            AssetCategory::GitRepo,
            AssetCategory::Database,
        ] {
            fs::create_dir_all(self.category_dir(*category))
                .with_context(|| format!("Failed to create {category} cache directory"))?;
        }

        Ok(())
    }

    /// Get the total size of the cache in bytes.
    pub fn size(&self) -> Result<u64> {
        if !self.base_dir.exists() {
            return Ok(0);
        }
        dir_size(&self.base_dir)
    }

    /// Get the size of a specific category in bytes.
    pub fn category_cache_size(&self, category: AssetCategory) -> Result<u64> {
        let dir = self.category_dir(category);
        if !dir.exists() {
            return Ok(0);
        }
        dir_size(&dir)
    }

    /// Clear the entire cache.
    pub fn clear(&self) -> Result<()> {
        if self.base_dir.exists() {
            fs::remove_dir_all(&self.base_dir)
                .context("Failed to clear cache")?;
        }
        Ok(())
    }

    /// Clear a specific category.
    pub fn clear_category(&self, category: AssetCategory) -> Result<()> {
        let dir = self.category_dir(category);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .context("Failed to clear category cache")?;
        }
        Ok(())
    }

    /// Remove a specific asset from the cache.
    pub fn remove(&self, asset: &Asset) -> Result<()> {
        let path = self.asset_path(asset);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove {}", asset.name))?;
        }
        Ok(())
    }

    /// Garbage collect old versions of assets.
    ///
    /// Removes files that don't match current asset versions.
    pub fn gc(&self) -> Result<GcStats> {
        let mut stats = GcStats::default();

        if !self.base_dir.exists() {
            return Ok(stats);
        }

        // Get current asset filenames
        let current_files: std::collections::HashSet<String> = super::manifest::all_assets()
            .iter()
            .map(|a| a.cache_filename())
            .collect();

        // Walk each category directory
        for category in &[
            AssetCategory::Media,
            AssetCategory::Photo,
            AssetCategory::Archive,
            AssetCategory::GitRepo,
            AssetCategory::Database,
        ] {
            let dir = self.category_dir(*category);
            if !dir.exists() {
                continue;
            }

            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let filename = entry.file_name().to_string_lossy().to_string();

                if !current_files.contains(&filename) {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    fs::remove_file(entry.path())?;
                    stats.files_removed += 1;
                    stats.bytes_freed += size;
                }
            }
        }

        Ok(stats)
    }

    /// Get status of all assets.
    pub fn status(&self) -> Vec<AssetStatus> {
        super::manifest::all_assets()
            .into_iter()
            .map(|asset| {
                let path = self.asset_path(asset);
                let cached = path.exists();
                let size_on_disk = if cached {
                    fs::metadata(&path).map(|m| m.len()).ok()
                } else {
                    None
                };

                AssetStatus {
                    asset,
                    cached,
                    size_on_disk,
                }
            })
            .collect()
    }
}

impl Default for AssetCache {
    fn default() -> Self {
        Self::new().expect("Failed to create default cache")
    }
}

/// Statistics from garbage collection.
#[derive(Debug, Default)]
pub struct GcStats {
    /// Number of files removed.
    pub files_removed: usize,
    /// Total bytes freed.
    pub bytes_freed: u64,
}

/// Status of a single asset.
#[derive(Debug)]
pub struct AssetStatus {
    /// The asset.
    pub asset: &'static Asset,
    /// Whether it's cached.
    pub cached: bool,
    /// Size on disk (if cached).
    pub size_on_disk: Option<u64>,
}

/// Calculate the total size of a directory recursively.
fn dir_size(path: &Path) -> Result<u64> {
    let mut size = 0;

    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            size += dir_size(&path)?;
        } else {
            size += entry.metadata()?.len();
        }
    }

    Ok(size)
}

/// Format bytes as human-readable size.
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.00 GB");
    }
}
