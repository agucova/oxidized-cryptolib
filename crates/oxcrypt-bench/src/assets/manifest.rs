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
    sha256: "b2acb9bddcb384f9762f919af8f6d8b4be781e40ad2f35a37cc12beef55b9a27",
    size: 249_229_883, // ~238 MB
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
    sha256: "60cff51761641626e82eeb4e1c248c471375b2536bb1089f49825b7fb58d8723",
    size: 673_935_402, // ~643 MB
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
    sha256: "bd2b5bc6c16d4085034f47ef7e4b3938afe86b4eec4ac3cf2685367d3b0b23b0",
    size: 738_876_331, // ~705 MB
    license: "CC-BY-3.0",
    category: AssetCategory::Media,
    version: 1,
    extension: "mov",
};

/// Kodak True Color Image Suite - 24 lossless PNG images.
/// Source: https://github.com/threeonetree/mini-imagenet-and-kodak-datasets
pub static PHOTO_KODAK: Asset = Asset {
    id: "kodak-suite",
    name: "Kodak True Color Image Suite",
    url: "https://codeload.github.com/threeonetree/mini-imagenet-and-kodak-datasets/tar.gz/main",
    mirrors: &[],
    sha256: "e524448a5fa48779a12cac02533457a1c6e38c18a8b78dffc7f45275c88affc9",
    size: 15_393_546, // ~15 MB
    license: "LicenseRef-PublicDomain",
    category: AssetCategory::Photo,
    version: 1,
    extension: "tar.gz",
};

/// Sample RAW photo from raw.pixls.us (CC0).
pub static PHOTO_RAW_SAMPLES: Asset = Asset {
    id: "raw-samples",
    name: "RAW Photo Sample (iPhone 8)",
    url: "https://raw.pixls.us/data/Apple/iPhone%208/RAW_2018_11_07_14_43_14_820_noflash.dng",
    mirrors: &[],
    sha256: "75cc053e427c3ca2dfa8526dc6c9c77fdb265bc5d005af1fd408b5084250a9fc",
    size: 10_533_870, // ~10 MB
    license: "CC0-1.0",
    category: AssetCategory::Photo,
    version: 1,
    extension: "dng",
};

/// Node.js source tarball.
pub static ARCHIVE_NODEJS: Asset = Asset {
    id: "nodejs-src",
    name: "Node.js Source",
    url: "https://nodejs.org/dist/v20.10.0/node-v20.10.0.tar.gz",
    mirrors: &[
        "https://nodejs.org/download/release/v20.10.0/node-v20.10.0.tar.gz",
    ],
    sha256: "89680f4ebbf36e0a199be4ed416701fa167aad8f86111c87a3db9207b5d56baa",
    size: 88_359_142, // ~84 MB
    license: "MIT",
    category: AssetCategory::Archive,
    version: 1,
    extension: "tar.gz",
};

/// Boost headers subset (header-only libraries).
pub static ARCHIVE_BOOST_HEADERS: Asset = Asset {
    id: "boost-headers",
    name: "Boost Headers",
    url: "https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.gz",
    mirrors: &[],
    sha256: "a5800f405508f5df8114558ca9855d2640a2de8f0445f051fa1c7c3383045724",
    size: 145_151_722, // ~138 MB (full), we might want a subset
    license: "BSL-1.0",
    category: AssetCategory::Archive,
    version: 1,
    extension: "tar.gz",
};

/// ripgrep source snapshot.
pub static GIT_RIPGREP: Asset = Asset {
    id: "ripgrep",
    name: "ripgrep Source",
    url: "https://github.com/BurntSushi/ripgrep/archive/refs/tags/14.1.0.zip",
    mirrors: &[],
    sha256: "821cb40ecddb6d539f6d8ea2490acc6b5e2a45723f884f5e14a0c115d1523b4d",
    size: 680_096, // ~0.7 MB compressed, expands to ~50 MB
    license: "MIT",
    category: AssetCategory::GitRepo,
    version: 1,
    extension: "zip",
};

/// Northwind sample database (SQLite).
pub static DATABASE_NORTHWIND: Asset = Asset {
    id: "northwind",
    name: "Northwind Database",
    url: "https://raw.githubusercontent.com/jpwhite3/northwind-SQLite3/main/dist/northwind.db",
    mirrors: &[],
    sha256: "2f4f5c68dfcd33ba27373eae48c7a4869800c68095ee0f9f0da494f83382a877",
    size: 24_702_976, // ~24 MB
    license: "MIT",
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
        &DATABASE_NORTHWIND,
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
