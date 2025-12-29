//! Benchmark asset management.
//!
//! This module provides infrastructure for downloading, caching, and verifying
//! benchmark assets such as video files, photos, and code archives.
//!
//! # Overview
//!
//! Assets are downloaded on-demand and cached locally at `~/.cache/oxbench/assets/`.
//! Each asset has a SHA256 hash for verification and supports multiple mirror URLs.
//!
//! # Usage
//!
//! ```rust,no_run
//! use oxbench::assets::{AssetDownloader, manifest};
//!
//! let downloader = AssetDownloader::new()?;
//!
//! // Download a specific asset
//! let video_path = downloader.ensure(&manifest::MEDIA_BBB_480P)?;
//!
//! // Download all assets in a category
//! let photo_paths = downloader.ensure_all(
//!     &manifest::assets_by_category(manifest::AssetCategory::Photo)
//! )?;
//! ```

mod cache;
mod downloader;
pub mod manifest;

pub use cache::{format_size, AssetCache, AssetStatus, GcStats};
pub use downloader::{download_all, download_category, AssetDownloader, DownloadProgress};
pub use manifest::{all_assets, assets_by_category, get_asset, Asset, AssetCategory};
