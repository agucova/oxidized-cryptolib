//! Command-line interface for the benchmark harness.

use crate::config::{BenchmarkConfig, BenchmarkSuite, Implementation};
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;

/// Cross-implementation filesystem benchmark harness for Cryptomator vaults.
///
/// Compares performance between oxidized-fuse, oxidized-fskit (macOS 15.4+),
/// and the official Cryptomator application.
#[derive(Parser, Debug)]
#[command(name = "oxbench")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to the Cryptomator vault.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,

    /// Implementations to benchmark.
    ///
    /// Valid values: fuse, fskit, cryptomator
    /// If not specified, auto-detects available implementations.
    #[arg(value_name = "IMPL")]
    pub implementations: Vec<String>,

    /// Mount point prefix for auto-generated mount points.
    #[arg(short = 'm', long, default_value = "/tmp/oxbench")]
    pub mount_prefix: PathBuf,

    /// Path to already-mounted Cryptomator vault.
    ///
    /// Required when benchmarking the official Cryptomator app.
    #[arg(short = 'c', long)]
    pub cryptomator: Option<PathBuf>,

    /// Vault password.
    ///
    /// Can also be set via OXBENCH_PASSWORD environment variable.
    #[arg(short = 'p', long, env = "OXBENCH_PASSWORD")]
    pub password: Option<String>,

    /// Benchmark suite to run.
    ///
    /// Valid values: quick, read, write, full (default: full)
    #[arg(short = 's', long, default_value = "full")]
    pub suite: String,

    /// Number of iterations per benchmark.
    #[arg(long, default_value = "10")]
    pub iterations: usize,

    /// Disable warmup iterations.
    #[arg(long)]
    pub no_warmup: bool,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,

    /// Verbose output.
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

impl Cli {
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

        // Check color support
        let color = !self.no_color && supports_color();

        // Clone values we need before moving self
        let cryptomator_path = self.cryptomator.clone();
        let vault = self.vault.clone();
        let mount_prefix = self.mount_prefix.clone();

        let mut config = BenchmarkConfig::new(vault, password);
        config.mount_prefix = mount_prefix;
        config.cryptomator_path = cryptomator_path;
        config.implementations = implementations;
        config.suite = suite;
        config.iterations = self.iterations;
        config.warmup_iterations = if self.no_warmup { 0 } else { 3 };
        config.color = color;
        config.verbose = self.verbose;

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
                "cryptomator" | "official" => Implementation::OfficialCryptomator,
                _ => bail!("Unknown implementation: {s}. Valid options: fuse, fskit, cryptomator"),
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

        // Only include Cryptomator if path is provided
        if self.cryptomator.is_some() {
            impls.push(Implementation::OfficialCryptomator);
        }

        impls
    }

    /// Validate the configuration.
    fn validate_config(&self, config: &BenchmarkConfig) -> Result<()> {
        // Check Cryptomator path if that implementation is requested
        if config.implementations.contains(&Implementation::OfficialCryptomator) {
            match &config.cryptomator_path {
                Some(path) => {
                    if !path.exists() {
                        bail!("Cryptomator mount path does not exist: {}", path.display());
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
                        "Cryptomator implementation requested but no mount path provided. \
                         Use --cryptomator <PATH> to specify the mounted vault path."
                    );
                }
            }
        }

        // Validate iterations
        if config.iterations == 0 {
            bail!("Iterations must be at least 1");
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
        assert_eq!("full".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Full);
        assert_eq!("FULL".parse::<BenchmarkSuite>().unwrap(), BenchmarkSuite::Full);
        assert!("invalid".parse::<BenchmarkSuite>().is_err());
    }
}
