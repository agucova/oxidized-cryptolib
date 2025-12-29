//! Export command - bulk decryption of files from a vault.
//!
//! This command exports files from an encrypted vault to the local filesystem
//! without requiring a mount. Useful for bulk decryption operations.
//!
//! # Examples
//!
//! ```bash
//! # Export a single file
//! oxcrypt ~/vault export /documents/report.pdf ~/Downloads/
//!
//! # Export directory recursively
//! oxcrypt ~/vault export /backup/photos/ ~/restored-photos/ -r
//!
//! # Export entire vault
//! oxcrypt ~/vault export / ~/vault-export/ -r
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use oxcrypt_core::vault::operations::VaultOperations;
use oxcrypt_core::vault::path::{DirId, EntryType};

use super::normalize_path;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Source path(s) in the vault
    #[arg(required = true)]
    pub sources: Vec<String>,

    /// Destination path on local filesystem
    #[arg(required = true)]
    pub dest: PathBuf,

    /// Export directories recursively
    #[arg(short, long)]
    pub recursive: bool,

    /// Overwrite existing files on local filesystem
    #[arg(short, long)]
    pub force: bool,

    /// Show progress during export
    #[arg(long)]
    pub progress: bool,
}

/// Statistics for export operation
#[derive(Default)]
struct ExportStats {
    files_exported: usize,
    directories_created: usize,
    bytes_exported: u64,
    files_skipped: usize,
    errors: Vec<String>,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let mut stats = ExportStats::default();

    // Validate destination
    if args.dest.exists() && !args.dest.is_dir() && args.sources.len() > 1 {
        anyhow::bail!(
            "Destination '{}' is not a directory, but multiple sources were specified",
            args.dest.display()
        );
    }

    // Validate sources exist in vault
    for source in &args.sources {
        let source_path = normalize_path(source);
        let entry_type = vault_ops.entry_type(&source_path);

        match entry_type {
            None => {
                anyhow::bail!("Source path does not exist in vault: {}", source_path);
            }
            Some(EntryType::Directory) if !args.recursive => {
                anyhow::bail!(
                    "Source '{}' is a directory. Use -r/--recursive to export directories.",
                    source_path
                );
            }
            _ => {}
        }
    }

    // Determine if destination should be treated as a directory
    let dest_is_dir = args.dest.is_dir() || args.sources.len() > 1 || args.dest.to_string_lossy().ends_with('/');

    // Create destination directory if it doesn't exist
    if dest_is_dir && !args.dest.exists() {
        fs::create_dir_all(&args.dest)
            .with_context(|| format!("Failed to create destination directory: {}", args.dest.display()))?;
    }

    // Export each source
    for source in &args.sources {
        let source_path = normalize_path(source);

        let target_path = if dest_is_dir {
            // Append source filename to destination directory
            let file_name = source_path
                .rsplit('/')
                .next()
                .unwrap_or(&source_path);
            args.dest.join(file_name)
        } else {
            args.dest.clone()
        };

        match vault_ops.entry_type(&source_path) {
            Some(EntryType::File) => {
                export_file(vault_ops, &source_path, &target_path, &args, &mut stats)?;
            }
            Some(EntryType::Directory) => {
                export_directory(vault_ops, &source_path, &target_path, &args, &mut stats)?;
            }
            Some(EntryType::Symlink) => {
                export_symlink(vault_ops, &source_path, &target_path, &args, &mut stats)?;
            }
            None => {
                // Already validated above, shouldn't happen
                anyhow::bail!("Source path does not exist: {}", source_path);
            }
        }
    }

    // Print summary
    if !stats.errors.is_empty() {
        eprintln!();
        eprintln!("Errors:");
        for error in &stats.errors {
            eprintln!("  - {}", error);
        }
    }

    eprintln!();
    eprintln!(
        "Exported {} file(s) ({} bytes), created {} director{}, skipped {}",
        stats.files_exported,
        format_bytes(stats.bytes_exported),
        stats.directories_created,
        if stats.directories_created == 1 { "y" } else { "ies" },
        stats.files_skipped
    );

    if !stats.errors.is_empty() {
        anyhow::bail!("{} error(s) occurred during export", stats.errors.len());
    }

    Ok(())
}

/// Export a single file from the vault
fn export_file(
    vault_ops: &VaultOperations,
    source: &str,
    dest: &Path,
    args: &Args,
    stats: &mut ExportStats,
) -> Result<()> {
    // Check if destination already exists
    if dest.exists() && !args.force {
        if args.progress {
            eprintln!("Skipping (exists): {} -> {}", source, dest.display());
        }
        stats.files_skipped += 1;
        return Ok(());
    }

    // Ensure parent directory exists
    if let Some(parent) = dest.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;
        }
    }

    // Read from vault
    let file_info = vault_ops
        .read_by_path(source)
        .with_context(|| format!("Failed to read from vault: {}", source))?;

    let size = file_info.content.len() as u64;

    // Write to local filesystem
    fs::write(dest, &file_info.content)
        .with_context(|| format!("Failed to write to: {}", dest.display()))?;

    if args.progress {
        eprintln!("Exported: {} -> {} ({})", source, dest.display(), format_bytes(size));
    }

    stats.files_exported += 1;
    stats.bytes_exported += size;

    Ok(())
}

/// Export a directory recursively from the vault
fn export_directory(
    vault_ops: &VaultOperations,
    source: &str,
    dest: &Path,
    args: &Args,
    stats: &mut ExportStats,
) -> Result<()> {
    // Create destination directory
    if !dest.exists() {
        fs::create_dir_all(dest)
            .with_context(|| format!("Failed to create directory: {}", dest.display()))?;
        stats.directories_created += 1;

        if args.progress {
            eprintln!("Created directory: {}", dest.display());
        }
    }

    // Resolve the path to a directory ID
    let dir_id = if source == "/" || source.is_empty() {
        DirId::root()
    } else {
        let (id, is_dir) = vault_ops.resolve_path(source)?;
        if !is_dir {
            anyhow::bail!("Not a directory: {}", source);
        }
        id
    };

    // List directory contents using VaultOperations API
    let files = vault_ops.list_files(&dir_id)?;
    let dirs = vault_ops.list_directories(&dir_id)?;
    let symlinks = vault_ops.list_symlinks(&dir_id)?;

    // Export files
    for file in files {
        let entry_path = if source == "/" {
            format!("/{}", file.name)
        } else {
            format!("{}/{}", source, file.name)
        };
        let target_path = dest.join(&file.name);

        match export_file(vault_ops, &entry_path, &target_path, args, stats) {
            Ok(()) => {}
            Err(e) => {
                stats.errors.push(format!("{}: {}", entry_path, e));
            }
        }
    }

    // Export subdirectories
    for dir in dirs {
        let entry_path = if source == "/" {
            format!("/{}", dir.name)
        } else {
            format!("{}/{}", source, dir.name)
        };
        let target_path = dest.join(&dir.name);

        match export_directory(vault_ops, &entry_path, &target_path, args, stats) {
            Ok(()) => {}
            Err(e) => {
                stats.errors.push(format!("{}: {}", entry_path, e));
            }
        }
    }

    // Export symlinks
    for symlink in symlinks {
        let entry_path = if source == "/" {
            format!("/{}", symlink.name)
        } else {
            format!("{}/{}", source, symlink.name)
        };
        let target_path = dest.join(&symlink.name);

        match export_symlink_direct(&symlink.target, &target_path, args, stats) {
            Ok(()) => {}
            Err(e) => {
                stats.errors.push(format!("{}: {}", entry_path, e));
            }
        }
    }

    Ok(())
}

/// Export a symlink from the vault by reading its target
fn export_symlink(
    vault_ops: &VaultOperations,
    source: &str,
    dest: &Path,
    args: &Args,
    stats: &mut ExportStats,
) -> Result<()> {
    // Check if destination already exists
    if dest.exists() || dest.symlink_metadata().is_ok() {
        if !args.force {
            if args.progress {
                eprintln!("Skipping (exists): {} -> {}", source, dest.display());
            }
            stats.files_skipped += 1;
            return Ok(());
        }
        // Remove existing for overwrite
        let _ = fs::remove_file(dest);
    }

    // Read symlink target from vault
    let target = vault_ops
        .read_symlink_by_path(source)
        .with_context(|| format!("Failed to read symlink: {}", source))?;

    // Create symlink on local filesystem
    create_symlink(&target, dest)?;

    if args.progress {
        eprintln!("Created symlink: {} -> {} (target: {})", source, dest.display(), target);
    }

    stats.files_exported += 1;

    Ok(())
}

/// Create a symlink when we already know the target
fn export_symlink_direct(
    target: &str,
    dest: &Path,
    args: &Args,
    stats: &mut ExportStats,
) -> Result<()> {
    // Check if destination already exists
    if dest.exists() || dest.symlink_metadata().is_ok() {
        if !args.force {
            if args.progress {
                eprintln!("Skipping (exists): {}", dest.display());
            }
            stats.files_skipped += 1;
            return Ok(());
        }
        // Remove existing for overwrite
        let _ = fs::remove_file(dest);
    }

    // Create symlink on local filesystem
    create_symlink(target, dest)?;

    if args.progress {
        eprintln!("Created symlink: {} -> {}", dest.display(), target);
    }

    stats.files_exported += 1;

    Ok(())
}

/// Platform-specific symlink creation
fn create_symlink(target: &str, dest: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest)
            .with_context(|| format!("Failed to create symlink: {}", dest.display()))?;
    }

    #[cfg(windows)]
    {
        // Windows requires knowing if target is file or directory
        // For simplicity, try file first, then directory
        if std::os::windows::fs::symlink_file(target, dest).is_err() {
            std::os::windows::fs::symlink_dir(target, dest)
                .with_context(|| format!("Failed to create symlink: {}", dest.display()))?;
        }
    }

    Ok(())
}

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
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
        format!("{} B", bytes)
    }
}
