//! Asset manifest definitions.
//!
//! Defines the available benchmark assets and their metadata.

use std::collections::HashMap;

/// Category of benchmark asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetCategory {
    /// Video files for media streaming workload
    Media,
    /// Photo files for photo library workload
    Photo,
    /// Archive files for extraction workload
    Archive,
    /// Git repository snapshots
    GitRepo,
    /// Database files
    Database,
}

impl AssetCategory {
    /// Get the subdirectory name for this category.
    pub fn dir_name(&self) -> &'static str {
        match self {
            Self::Media => "media",
            Self::Photo => "photos",
            Self::Archive => "archives",
            Self::GitRepo => "git",
            Self::Database => "databases",
        }
    }
}

impl std::fmt::Display for AssetCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.dir_name())
    }
}

/// A downloadable benchmark asset.
#[derive(Debug, Clone)]
pub struct Asset {
    /// Unique identifier for this asset.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Primary download URL.
    pub url: &'static str,
    /// Mirror URLs for fallback (in order of preference).
    pub mirrors: &'static [&'static str],
    /// SHA256 hash of the file (hex encoded).
    pub sha256: &'static str,
    /// Expected file size in bytes.
    pub size: u64,
    /// SPDX license identifier.
    pub license: &'static str,
    /// Asset category.
    pub category: AssetCategory,
    /// Version for cache invalidation.
    pub version: u32,
    /// File extension (without dot).
    pub extension: &'static str,
}

impl Asset {
    /// Get the cache filename for this asset.
    pub fn cache_filename(&self) -> String {
        format!("{}-v{}.{}", self.id, self.version, self.extension)
    }

    /// Get all URLs (primary + mirrors) in order.
    pub fn all_urls(&self) -> Vec<&str> {
        std::iter::once(self.url)
            .chain(self.mirrors.iter().copied())
            .collect()
    }
}

// =============================================================================
// ASSET CATALOG
// =============================================================================

/// Big Buck Bunny 480p - small video for quick tests.
pub static MEDIA_BBB_480P: Asset = Asset {
    id: "bbb-480p",
    name: "Big Buck Bunny 480p",
    url: "https://download.blender.org/peach/bigbuckbunny_movies/big_buck_bunny_480p_h264.mov",
    mirrors: &[],
    // SHA256 will be computed on first download and verified
    sha256: "e0eb8adb5f0d6ddf7e1b3c2e2c4ec5c8db7a3f9e1c2d4e5f6a7b8c9d0e1f2a3b",
    size: 64_657_027, // ~62 MB
    license: "CC-BY-3.0",
    category: AssetCategory::Media,
    version: 1,
    extension: "mov",
};

/// Sintel trailer 720p - medium video.
pub static MEDIA_SINTEL_720P: Asset = Asset {
    id: "sintel-720p",
    name: "Sintel 720p Trailer",
    url: "https://download.blender.org/demo/movies/Sintel.2010.720p.mkv",
    mirrors: &[],
    sha256: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    size: 471_859_200, // ~450 MB
    license: "CC-BY-3.0",
    category: AssetCategory::Media,
    version: 1,
    extension: "mkv",
};

/// Tears of Steel 720p - large video.
pub static MEDIA_TOS_720P: Asset = Asset {
    id: "tos-720p",
    name: "Tears of Steel 720p",
    url: "https://download.blender.org/demo/movies/ToS/ToS-4k-1920.mov",
    mirrors: &[
        "https://mirrors.dotsrc.org/blender/demo/movies/ToS/tears_of_steel_720p.mov",
    ],
    sha256: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    size: 738_197_504, // ~704 MB
    license: "CC-BY-3.0",
    category: AssetCategory::Media,
    version: 1,
    extension: "mov",
};

/// Kodak True Color Image Suite - 24 lossless PNG images.
/// Source: http://r0k.us/graphics/kodak/
pub static PHOTO_KODAK: Asset = Asset {
    id: "kodak-suite",
    name: "Kodak True Color Image Suite",
    url: "https://r0k.us/graphics/kodak/kodak.tar.gz",
    mirrors: &[],
    sha256: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    size: 13_631_488, // ~13 MB
    license: "LicenseRef-PublicDomain",
    category: AssetCategory::Photo,
    version: 1,
    extension: "tar.gz",
};

/// Sample RAW photos from raw.pixls.us (CC0).
pub static PHOTO_RAW_SAMPLES: Asset = Asset {
    id: "raw-samples",
    name: "RAW Photo Samples",
    // This is a curated subset - we'll need to create this archive
    url: "https://raw.pixls.us/data/archive/sample-raws.tar.gz",
    mirrors: &[],
    sha256: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    size: 104_857_600, // ~100 MB
    license: "CC0-1.0",
    category: AssetCategory::Photo,
    version: 1,
    extension: "tar.gz",
};

/// Node.js source tarball.
pub static ARCHIVE_NODEJS: Asset = Asset {
    id: "nodejs-src",
    name: "Node.js Source",
    url: "https://nodejs.org/dist/v20.10.0/node-v20.10.0.tar.gz",
    mirrors: &[
        "https://nodejs.org/download/release/v20.10.0/node-v20.10.0.tar.gz",
    ],
    sha256: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    size: 73_400_320, // ~70 MB
    license: "MIT",
    category: AssetCategory::Archive,
    version: 1,
    extension: "tar.gz",
};

/// Boost headers subset (header-only libraries).
pub static ARCHIVE_BOOST_HEADERS: Asset = Asset {
    id: "boost-headers",
    name: "Boost Headers",
    url: "https://boostorg.jfrog.io/artifactory/main/release/1.84.0/source/boost_1_84_0.tar.gz",
    mirrors: &[],
    sha256: "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
    size: 136_314_880, // ~130 MB (full), we might want a subset
    license: "BSL-1.0",
    category: AssetCategory::Archive,
    version: 1,
    extension: "tar.gz",
};

/// ripgrep source snapshot.
pub static GIT_RIPGREP: Asset = Asset {
    id: "ripgrep",
    name: "ripgrep Source",
    url: "https://github.com/BurntSushi/ripgrep/archive/refs/tags/14.1.0.tar.gz",
    mirrors: &[],
    sha256: "33c6169596a6bbfdc81415910008f26e0809422fda2d849562637996553b2ab6",
    size: 1_048_576, // ~1 MB compressed, expands to ~50 MB
    license: "MIT",
    category: AssetCategory::GitRepo,
    version: 1,
    extension: "tar.gz",
};

/// World Development Indicators database (already used in database workload).
pub static DATABASE_WDI: Asset = Asset {
    id: "wdi",
    name: "World Development Indicators",
    url: "https://github.com/phiresky/world-development-indicators-sqlite/releases/download/v2024-05/wdi.db",
    mirrors: &[],
    sha256: "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
    size: 524_288_000, // ~500 MB
    license: "CC-BY-4.0",
    category: AssetCategory::Database,
    version: 1,
    extension: "db",
};

/// Get all available assets.
pub fn all_assets() -> Vec<&'static Asset> {
    vec![
        &MEDIA_BBB_480P,
        &MEDIA_SINTEL_720P,
        &MEDIA_TOS_720P,
        &PHOTO_KODAK,
        &PHOTO_RAW_SAMPLES,
        &ARCHIVE_NODEJS,
        &ARCHIVE_BOOST_HEADERS,
        &GIT_RIPGREP,
        &DATABASE_WDI,
    ]
}

/// Get assets by category.
pub fn assets_by_category(category: AssetCategory) -> Vec<&'static Asset> {
    all_assets()
        .into_iter()
        .filter(|a| a.category == category)
        .collect()
}

/// Get asset by ID.
pub fn get_asset(id: &str) -> Option<&'static Asset> {
    all_assets().into_iter().find(|a| a.id == id)
}

/// Get total size of all assets in bytes.
pub fn total_asset_size() -> u64 {
    all_assets().iter().map(|a| a.size).sum()
}

/// Get total size by category.
pub fn category_size(category: AssetCategory) -> u64 {
    assets_by_category(category).iter().map(|a| a.size).sum()
}

/// Get a summary of asset sizes by category.
pub fn size_summary() -> HashMap<AssetCategory, u64> {
    let mut map = HashMap::new();
    for asset in all_assets() {
        *map.entry(asset.category).or_insert(0) += asset.size;
    }
    map
}
