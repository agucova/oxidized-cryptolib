//! External mount validation (for official Cryptomator app).

use anyhow::{Context, Result};
use std::path::Path;

/// Validates that an external mount exists and is readable.
///
/// This is used for benchmarking the official Cryptomator app, which the user
/// must mount themselves. We just validate the mount is accessible.
pub struct ExternalMount;

impl ExternalMount {
    /// Validate that an external mount exists and is readable.
    pub fn validate(path: &Path) -> Result<()> {
        // Check path exists
        if !path.exists() {
            anyhow::bail!("Mount path does not exist: {}", path.display());
        }

        // Check it's a directory
        if !path.is_dir() {
            anyhow::bail!("Mount path is not a directory: {}", path.display());
        }

        // Try to read the directory to verify access
        std::fs::read_dir(path)
            .with_context(|| format!("Cannot read mount directory: {}", path.display()))?;

        // Optionally check if it's actually a mount point
        if let Ok(is_mount) = super::is_mount_point(path) {
            if !is_mount {
                tracing::warn!(
                    "Path {} may not be a mount point (same device as parent)",
                    path.display()
                );
            }
        }

        Ok(())
    }
}
