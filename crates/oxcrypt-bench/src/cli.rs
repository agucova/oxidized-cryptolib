//! Command-line interface for the benchmark harness.

// Allow CLI-specific patterns
#![allow(clippy::struct_excessive_bools, clippy::unused_self, clippy::assigning_clones)]

use crate::assets::{AssetCache, AssetDownloader, AssetCategory};
use crate::config::{BenchmarkConfig, BenchmarkSuite, Implementation};
#[cfg(all(target_os = "macos", feature = "fileprovider"))]
use crate::mount::MountBackend;
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;

/// Cross-implementation filesystem benchmark harness for Cryptomator vaults.
///
/// Compares performance between oxcrypt-fuse, oxcrypt-fskit (macOS 15.4+),
/// oxcrypt-webdav, oxcrypt-nfs, and the official Cryptomator application.
#[derive(Parser, Debug)]
#[command(name = "oxbench")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the Cryptomator vault.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,

    /// Implementations to benchmark.
    ///
    /// Valid values: fuse, fskit, webdav, nfs, fileprovider (or fp), external
    /// If not specified, auto-detects available implementations.
    #[arg(value_name = "IMPL")]
    pub implementations: Vec<String>,

    /// Mount point prefix for auto-generated mount points.
    #[arg(short = 'm', long, default_value = "/tmp/oxbench")]
    pub mount_prefix: PathBuf,

    /// Path to an already-mounted external vault.
    ///
    /// Use this to benchmark any external Cryptomator client (e.g., official
    /// Cryptomator app, Mountain Duck, etc.) that you've already mounted.
    #[arg(short = 'e', long = "external-vault")]
    pub external_vault: Option<PathBuf>,

    /// Vault password.
    ///
    /// Can also be set via OXBENCH_PASSWORD environment variable.
    #[arg(short = 'p', long, env = "OXBENCH_PASSWORD")]
    pub password: Option<String>,

    /// Benchmark suite to run.
    ///
    /// Valid values:
    /// - quick: Fast sanity check (1MB read, small directory listing)
    /// - read: Read-only synthetic benchmarks
    /// - write: Write-only synthetic benchmarks
    /// - synthetic: All synthetic benchmarks (default)
    /// - metadata: Metadata operations only (readdir, stat)
    /// - large: Large file stress tests (100MB-1GB)
    /// - workload: Realistic application workloads only
    /// - complete: Synthetic + realistic workloads (everything)
    #[arg(short = 's', long, default_value = "synthetic")]
    pub suite: String,

    /// Run specific workload(s) by name.
    ///
    /// Can be specified multiple times. Any workload can be run individually.
    ///
    /// Synthetic workloads:
    /// seq-read, rand-read, seq-write, rand-write, readdir, stat, create, delete
    ///
    /// Realistic workloads:
    /// ide, working-set, git, tree, concurrent, database, media, photo, archive, backup, coldstart
    ///
    /// Example: --workload readdir --workload stat --workload database
    #[arg(short = 'w', long = "workload", value_name = "NAME")]
    pub workloads: Vec<String>,

    /// Number of iterations per benchmark.
    #[arg(long, default_value = "50")]
    pub iterations: usize,

    /// Disable warmup iterations.
    #[arg(long)]
    pub no_warmup: bool,

    /// Export results to JSON file.
    #[arg(long, value_name = "PATH")]
    pub json: Option<PathBuf>,

    /// Disable colored output.
    #[arg(long, conflicts_with = "color")]
    pub no_color: bool,

    /// Force colored output (even when not a TTY).
    #[arg(long, conflicts_with = "no_color")]
    pub color: bool,

    /// Verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Enable CPU flamegraph profiling for each benchmark.
    ///
    /// Generates SVG flamegraphs showing where CPU time is spent.
    /// Requires Unix (macOS/Linux). Outputs per-benchmark and
    /// aggregate per-implementation flamegraphs.
    #[arg(long)]
    pub flamegraph: bool,

    /// Directory for flamegraph output.
    ///
    /// Defaults to ./profiles/ or alongside JSON output if --json is specified.
    #[arg(long, value_name = "DIR")]
    pub flamegraph_dir: Option<PathBuf>,

    /// Profiler sampling frequency in Hz.
    ///
    /// Higher values give more detail but slightly more overhead.
    /// Use prime numbers (997, 1009, 4999) to avoid aliasing with periodic system events.
    #[arg(long, default_value = "997")]
    pub profile_frequency: i32,

    // ===== Asset Management =====
    /// Use real downloaded assets for workloads instead of synthetic data.
    ///
    /// Real assets provide more authentic benchmarks (real video seeking patterns,
    /// actual photo EXIF layouts, etc.) but require downloading ~1GB of data.
    /// Enabled by default. Use --no-real-assets to use synthetic data instead.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub real_assets: bool,

    /// Scale factor for workload sizes and durations (0.01-1.0).
    ///
    /// Controls the size of realistic workloads to balance thoroughness and speed.
    /// 1.0 = full workload (e.g., 1000 files), 0.1 = 10% workload (100 files).
    /// Useful for quick tests or when benchmarking slow backends.
    #[arg(long, default_value = "0.1")]
    pub workload_scale: f64,

    /// Download benchmark assets without running benchmarks.
    ///
    /// Downloads all required assets for the selected workloads to the local cache.
    /// Assets are verified with SHA256 hashes and stored in ~/.cache/oxbench/assets/.
    #[arg(long)]
    pub download_assets: bool,

    /// Show asset cache status (size, contents, validation).
    ///
    /// Displays cached assets, their sizes, and verification status.
    #[arg(long)]
    pub cache_status: bool,

    /// Clear the asset cache.
    ///
    /// Removes all downloaded benchmark assets from ~/.cache/oxbench/assets/.
    #[arg(long)]
    pub clear_cache: bool,

    /// Asset category to download (used with --download-assets).
    ///
    /// Valid values: media, photo, archive, git, database, all
    /// If not specified with --download-assets, downloads all categories.
    #[arg(long, value_name = "CATEGORY")]
    pub asset_category: Option<String>,
}

impl Cli {
    /// Check if this is an asset management command (doesn't require vault).
    pub fn is_asset_command(&self) -> bool {
        self.download_assets || self.cache_status || self.clear_cache
    }

    /// Execute asset management commands.
    ///
    /// Returns `Ok(true)` if an asset command was executed (no benchmark needed),
    /// `Ok(false)` if no asset command was specified.
    pub fn execute_asset_command(&self) -> Result<bool> {
        if self.clear_cache {
            self.handle_clear_cache()?;
            return Ok(true);
        }

        if self.cache_status {
            self.handle_cache_status()?;
            return Ok(true);
        }

        if self.download_assets {
            self.handle_download_assets()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Handle --clear-cache command.
    fn handle_clear_cache(&self) -> Result<()> {
        let cache = AssetCache::new()?;
        let total_size = cache.size()?;
        cache.clear()?;
        println!("Cleared asset cache ({})", crate::assets::format_size(total_size));
        Ok(())
    }

    /// Handle --cache-status command.
    fn handle_cache_status(&self) -> Result<()> {
        let cache = AssetCache::new()?;
        let total_size = cache.size()?;
        let statuses = cache.status();
        let cached_count = statuses.iter().filter(|s| s.cached).count();

        println!("Asset Cache Status");
        println!("==================");
        println!("Location: {}", cache.base_dir().display());
        println!("Total size: {}", crate::assets::format_size(total_size));
        println!("Cached assets: {}/{}", cached_count, statuses.len());
        println!();

        // Show status by category
        for category in [
            AssetCategory::Media,
            AssetCategory::Photo,
            AssetCategory::Archive,
            AssetCategory::GitRepo,
            AssetCategory::Database,
        ] {
            let assets = crate::assets::assets_by_category(category);
            let mut cached = 0;
            let mut cached_size = 0u64;

            for asset in &assets {
                if cache.is_cached(asset) {
                    cached += 1;
                    if let Ok(path) = std::fs::metadata(cache.asset_path(asset)) {
                        cached_size += path.len();
                    }
                }
            }

            println!(
                "{:12} {}/{} assets ({})",
                format!("{:?}:", category),
                cached,
                assets.len(),
                crate::assets::format_size(cached_size)
            );
        }

        Ok(())
    }

    /// Handle --download-assets command.
    fn handle_download_assets(&self) -> Result<()> {
        let downloader = AssetDownloader::new()?;

        let category = match &self.asset_category {
            Some(cat) => match cat.to_lowercase().as_str() {
                "media" => Some(AssetCategory::Media),
                "photo" => Some(AssetCategory::Photo),
                "archive" => Some(AssetCategory::Archive),
                "git" => Some(AssetCategory::GitRepo),
                "database" => Some(AssetCategory::Database),
                "all" => None,
                _ => bail!(
                    "Unknown asset category: {cat}. Valid options: media, photo, archive, git, database, all"
                ),
            },
            None => None,
        };

        if let Some(cat) = category {
            println!("Downloading {cat:?} assets...");
            let paths = crate::assets::download_category(&downloader, cat)?;
            println!("Downloaded {} assets", paths.len());
        } else {
            println!("Downloading all benchmark assets...");
            let paths = crate::assets::download_all(&downloader)?;
            println!("Downloaded {} assets", paths.len());
        }

        Ok(())
    }

    /// Parse CLI arguments and build configuration.
    pub fn into_config(self) -> Result<BenchmarkConfig> {
        // Validate vault path
        if !self.vault.exists() {
            bail!("Vault path does not exist: {}", self.vault.display());
        }

        let vault_cryptomator = self.vault.join("vault.cryptomator");
        if !vault_cryptomator.exists() {
            bail!(
                "Not a valid Cryptomator vault (missing vault.cryptomator): {}",
                self.vault.display()
            );
        }

        // Get password
        let password = match &self.password {
            Some(p) => p.clone(),
            None => {
                // Prompt for password
                rpassword::prompt_password("Vault password: ")
                    .context("Failed to read password")?
            }
        };

        // Parse suite
        let suite: BenchmarkSuite = self
            .suite
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;

        // Parse implementations
        let implementations = self.parse_implementations()?;

        // Check color support (--color forces it on, --no-color forces it off)
        let color = self.color || (!self.no_color && supports_color());

        // Clone values we need before moving self
        let external_vault_path = self.external_vault.clone();
        let vault = self.vault.clone();
        let mount_prefix = self.mount_prefix.clone();

        let mut config = BenchmarkConfig::new(vault, password);
        config.mount_prefix = mount_prefix;
        config.external_vault_path = external_vault_path;
        config.implementations = implementations;
        config.suite = suite;
        config.iterations = self.iterations;
        config.warmup_iterations = if self.no_warmup { 0 } else { 3 };
        config.color = color;
        config.verbose = self.verbose;
        config.real_assets = self.real_assets;
        config.workload_scale = self.workload_scale.clamp(0.01, 1.0);
        config.selected_workloads = self.workloads.clone();

        // Flamegraph profiling settings
        config.flamegraph_enabled = self.flamegraph;
        config.profile_frequency = self.profile_frequency;
        if let Some(dir) = self.flamegraph_dir.clone() {
            config.flamegraph_dir = dir;
        } else if let Some(ref json_path) = self.json {
            // Default to same directory as JSON output
            if let Some(parent) = json_path.parent() {
                config.flamegraph_dir = parent.join("profiles");
            }
        }

        // Validate configuration
        self.validate_config(&config)?;

        Ok(config)
    }

    /// Parse implementation strings into enum values.
    fn parse_implementations(&self) -> Result<Vec<Implementation>> {
        if self.implementations.is_empty() {
            // Auto-detect available implementations
            return Ok(self.detect_implementations());
        }

        let mut impls = Vec::new();
        for s in &self.implementations {
            let impl_type = match s.to_lowercase().as_str() {
                "fuse" => Implementation::OxidizedFuse,
                "fskit" => {
                    #[cfg(not(target_os = "macos"))]
                    bail!("FSKit is only available on macOS 15.4+");

                    #[cfg(target_os = "macos")]
                    {
                        if !crate::platform::fskit_available() {
                            bail!("FSKit requires macOS 15.4 or later");
                        }
                        Implementation::OxidizedFsKit
                    }
                }
                "webdav" => Implementation::OxidizedWebDav,
                "nfs" => {
                    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                    bail!("NFS is only available on macOS and Linux");

                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    Implementation::OxidizedNfs
                }
                "fileprovider" | "fp" => {
                    #[cfg(not(all(target_os = "macos", feature = "fileprovider")))]
                    bail!("FileProvider is only available on macOS 13+ (enable 'fileprovider' feature)");

                    #[cfg(all(target_os = "macos", feature = "fileprovider"))]
                    {
                        if !crate::mount::fileprovider_backend().is_available() {
                            bail!("FileProvider extension is not enabled. Enable in System Settings → Extensions → File Provider");
                        }
                        Implementation::OxidizedFileProvider
                    }
                }
                "external" | "cryptomator" => Implementation::OfficialCryptomator,
                _ => bail!("Unknown implementation: {s}. Valid options: fuse, fskit, webdav, nfs, fileprovider, external"),
            };
            if !impls.contains(&impl_type) {
                impls.push(impl_type);
            }
        }

        Ok(impls)
    }

    /// Auto-detect available implementations.
    fn detect_implementations(&self) -> Vec<Implementation> {
        let mut impls = vec![Implementation::OxidizedFuse];

        #[cfg(target_os = "macos")]
        {
            if crate::platform::fskit_available() {
                impls.push(Implementation::OxidizedFsKit);
            }
        }

        // WebDAV is always available (no kernel extensions needed)
        impls.push(Implementation::OxidizedWebDav);

        // NFS is available on macOS and Linux
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            impls.push(Implementation::OxidizedNfs);
        }

        // FileProvider is available on macOS 13+ with the feature enabled
        #[cfg(all(target_os = "macos", feature = "fileprovider"))]
        {
            if crate::mount::fileprovider_backend().is_available() {
                impls.push(Implementation::OxidizedFileProvider);
            }
        }

        // Only include Cryptomator if path is provided
        if self.external_vault.is_some() {
            impls.push(Implementation::OfficialCryptomator);
        }

        impls
    }

    /// Validate the configuration.
    fn validate_config(&self, config: &BenchmarkConfig) -> Result<()> {
        // Check external vault path if that implementation is requested
        if config.implementations.contains(&Implementation::OfficialCryptomator) {
            match &config.external_vault_path {
                Some(path) => {
                    if !path.exists() {
                        bail!("External vault path does not exist: {}", path.display());
                    }
                    // Check if it's actually a mount point
                    if !is_mount_point(path)? {
                        tracing::warn!(
                            "Path may not be a mount point: {}. Proceeding anyway.",
                            path.display()
                        );
                    }
                }
                None => {
                    bail!(
                        "External implementation requested but no mount path provided. \
                         Use --external-vault <PATH> to specify the mounted vault path."
                    );
                }
            }
        }

        // Validate iterations
        if config.iterations == 0 {
            bail!("Iterations must be at least 1");
        }

        // Validate workload names (if specified)
        if !config.selected_workloads.is_empty() {
            let valid_names = crate::bench::workload_names();
            let unknown: Vec<_> = config
                .selected_workloads
                .iter()
                .filter(|name| {
                    // Check if this name (or its alias) is valid
                    crate::bench::workloads::create_workload_by_name(
                        name,
                        &crate::bench::workloads::WorkloadConfig::default(),
                    )
                    .is_none()
                })
                .collect();

            if !unknown.is_empty() {
                bail!(
                    "Unknown workload(s): {}. Valid options: {}",
                    unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                    valid_names.join(", ")
                );
            }
        }

        Ok(())
    }
}

/// Check if the terminal supports colors.
fn supports_color() -> bool {
    // Check NO_COLOR environment variable (https://no-color.org/)
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check FORCE_COLOR environment variable (common convention)
    if std::env::var("FORCE_COLOR").is_ok() {
        return true;
    }

    // Check if stdout is a TTY
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::isatty(std::io::stdout().as_raw_fd()) != 0 }
    }

    #[cfg(not(unix))]
    {
        true
    }
}

/// Check if a path is a mount point.
fn is_mount_point(path: &std::path::Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let path_meta = std::fs::metadata(path)?;
        let parent = path.parent().unwrap_or(std::path::Path::new("/"));
        let parent_meta = std::fs::metadata(parent)?;

        // Different device numbers indicate a mount point
        Ok(path_meta.dev() != parent_meta.dev())
    }

    #[cfg(not(unix))]
    {
        // On non-Unix, just check if it's a directory
        Ok(path.is_dir())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_parsing() {
        assert_eq!("quick".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Quick);
        assert_eq!("read".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Read);
        assert_eq!("write".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Write);
        assert_eq!("synthetic".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Synthetic);
        assert_eq!("metadata".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Metadata);
        assert_eq!("meta".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Metadata);
        assert_eq!("SYNTHETIC".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Synthetic);
        // "full" is kept as alias for backward compatibility
        assert_eq!("full".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Synthetic);
        assert!("invalid".parse::<BenchmarkSuite>().is_err());
    }
}
