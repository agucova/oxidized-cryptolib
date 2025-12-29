//! Import command - bulk encryption of files into a vault.
//!
//! This command imports files from the local filesystem into an encrypted vault
//! without requiring a mount. Useful for bulk encryption operations.
//!
//! # Examples
//!
//! ```bash
//! # Import a single file
//! oxcrypt ~/vault import ~/document.pdf /documents/
//!
//! # Import directory recursively
//! oxcrypt ~/vault import ~/photos/ /backup/photos/ -r
//!
//! # Import and delete source
//! oxcrypt ~/vault import ~/sensitive/ /encrypted/ -r --delete
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use oxcrypt_core::vault::operations::VaultOperations;
use oxcrypt_core::vault::path::EntryType;

use super::normalize_path;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Source path(s) on local filesystem
    #[arg(required = true)]
    pub sources: Vec<PathBuf>,

    /// Destination path in the vault
    #[arg(required = true)]
    pub dest: String,

    /// Import directories recursively
    #[arg(short, long)]
    pub recursive: bool,

    /// Delete source files after successful import
    #[arg(long)]
    pub delete: bool,

    /// Overwrite existing files in vault
    #[arg(short, long)]
    pub force: bool,

    /// Show progress during import
    #[arg(long)]
    pub progress: bool,
}

/// Statistics for import operation
#[derive(Default)]
struct ImportStats {
    files_imported: usize,
    directories_created: usize,
    bytes_imported: u64,
    files_skipped: usize,
    errors: Vec<String>,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let dest = normalize_path(&args.dest);
    let mut stats = ImportStats::default();

    // Validate sources exist
    for source in &args.sources {
        if !source.exists() {
            anyhow::bail!("Source path does not exist: {}", source.display());
        }
        if source.is_dir() && !args.recursive {
            anyhow::bail!(
                "Source '{}' is a directory. Use -r/--recursive to import directories.",
                source.display()
            );
        }
    }

    // Determine if destination is a directory (ends with / or multiple sources)
    let dest_is_dir = dest.ends_with('/') || args.sources.len() > 1;

    // Ensure destination directory exists if needed
    if dest_is_dir {
        ensure_directory_exists(vault_ops, &dest)?;
    }

    // Import each source
    for source in &args.sources {
        let target_path = if dest_is_dir {
            // Append source filename to destination directory
            let file_name = source
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Invalid source path: {}", source.display()))?
                .to_string_lossy();
            format!("{}{}", dest.trim_end_matches('/'), format!("/{}", file_name))
        } else {
            dest.clone()
        };

        if source.is_file() {
            import_file(vault_ops, source, &target_path, &args, &mut stats)?;
        } else if source.is_dir() {
            import_directory(vault_ops, source, &target_path, &args, &mut stats)?;
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
        "Imported {} file(s) ({} bytes), created {} director{}, skipped {}",
        stats.files_imported,
        format_bytes(stats.bytes_imported),
        stats.directories_created,
        if stats.directories_created == 1 { "y" } else { "ies" },
        stats.files_skipped
    );

    if !stats.errors.is_empty() {
        anyhow::bail!("{} error(s) occurred during import", stats.errors.len());
    }

    Ok(())
}

/// Import a single file into the vault
fn import_file(
    vault_ops: &VaultOperations,
    source: &Path,
    dest: &str,
    args: &Args,
    stats: &mut ImportStats,
) -> Result<()> {
    // Check if destination already exists
    if vault_ops.entry_type(dest).is_some() && !args.force {
        if args.progress {
            eprintln!("Skipping (exists): {} -> {}", source.display(), dest);
        }
        stats.files_skipped += 1;
        return Ok(());
    }

    // Read source file
    let content = fs::read(source)
        .with_context(|| format!("Failed to read source file: {}", source.display()))?;

    let size = content.len() as u64;

    // Write to vault
    vault_ops
        .write_by_path(dest, &content)
        .with_context(|| format!("Failed to write to vault: {}", dest))?;

    if args.progress {
        eprintln!("Imported: {} -> {} ({})", source.display(), dest, format_bytes(size));
    }

    stats.files_imported += 1;
    stats.bytes_imported += size;

    // Delete source if requested
    if args.delete {
        fs::remove_file(source)
            .with_context(|| format!("Failed to delete source: {}", source.display()))?;
    }

    Ok(())
}

/// Import a directory recursively into the vault
fn import_directory(
    vault_ops: &VaultOperations,
    source: &Path,
    dest: &str,
    args: &Args,
    stats: &mut ImportStats,
) -> Result<()> {
    // Create destination directory
    ensure_directory_exists(vault_ops, dest)?;
    stats.directories_created += 1;

    if args.progress {
        eprintln!("Created directory: {}", dest);
    }

    // Read directory contents
    let entries = fs::read_dir(source)
        .with_context(|| format!("Failed to read directory: {}", source.display()))?;

    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path();
        let entry_name = entry
            .file_name()
            .to_string_lossy()
            .to_string();

        let target_path = format!("{}/{}", dest.trim_end_matches('/'), entry_name);

        if entry_path.is_file() {
            match import_file(vault_ops, &entry_path, &target_path, args, stats) {
                Ok(()) => {}
                Err(e) => {
                    stats.errors.push(format!("{}: {}", entry_path.display(), e));
                }
            }
        } else if entry_path.is_dir() {
            match import_directory(vault_ops, &entry_path, &target_path, args, stats) {
                Ok(()) => {}
                Err(e) => {
                    stats.errors.push(format!("{}: {}", entry_path.display(), e));
                }
            }
        } else if entry_path.is_symlink() {
            // Read symlink target and create in vault
            match fs::read_link(&entry_path) {
                Ok(link_target) => {
                    let target_str = link_target.to_string_lossy().to_string();
                    match vault_ops.create_symlink_by_path(&target_path, &target_str) {
                        Ok(_) => {
                            stats.files_imported += 1;
                            if args.progress {
                                eprintln!("Created symlink: {} -> {}", target_path, target_str);
                            }
                        }
                        Err(e) => {
                            stats.errors.push(format!("{}: {}", entry_path.display(), e));
                        }
                    }
                }
                Err(e) => {
                    stats.errors.push(format!("Failed to read symlink {}: {}", entry_path.display(), e));
                }
            }
        }
    }

    // Delete source directory if requested and successful
    if args.delete && stats.errors.is_empty() {
        fs::remove_dir_all(source)
            .with_context(|| format!("Failed to delete source directory: {}", source.display()))?;
    }

    Ok(())
}

/// Ensure a directory exists in the vault, creating parent directories as needed
fn ensure_directory_exists(vault_ops: &VaultOperations, path: &str) -> Result<()> {
    // Split path and create each component
    let components: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    let mut current_path = String::new();
    for component in components {
        current_path.push('/');
        current_path.push_str(component);

        match vault_ops.entry_type(&current_path) {
            Some(EntryType::Directory) => {
                // Already exists as directory, continue
            }
            Some(EntryType::File) => {
                anyhow::bail!("Cannot create directory '{}': path exists as a file", current_path);
            }
            Some(EntryType::Symlink) => {
                anyhow::bail!("Cannot create directory '{}': path exists as a symlink", current_path);
            }
            None => {
                // Create directory
                vault_ops.create_directory_by_path(&current_path)?;
            }
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
