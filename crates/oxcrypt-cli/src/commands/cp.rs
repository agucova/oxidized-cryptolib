//! Copy command - copy files or directories within a vault.
//!
//! # Examples
//!
//! ```bash
//! # Copy a single file
//! oxcrypt ~/vault cp /documents/report.pdf /backup/report.pdf
//!
//! # Copy multiple files to a directory
//! oxcrypt ~/vault cp /file1.txt /file2.txt /backup/
//!
//! # Copy directory recursively
//! oxcrypt ~/vault cp -r /photos/ /backup/photos/
//! ```

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use tracing::instrument;

use oxcrypt_core::vault::operations::VaultOperations;
use oxcrypt_core::vault::path::{DirId, EntryType};

use super::normalize_path;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Source path(s) in the vault
    #[arg(required = true)]
    pub sources: Vec<String>,

    /// Destination path in the vault
    #[arg(required = true)]
    pub dest: String,

    /// Copy directories recursively
    #[arg(short, long)]
    pub recursive: bool,

    /// Show progress during copy
    #[arg(long)]
    pub verbose: bool,
}

/// Statistics for copy operation
#[derive(Default)]
struct CopyStats {
    files_copied: usize,
    directories_created: usize,
    symlinks_copied: usize,
    errors: Vec<String>,
}

#[instrument(level = "info", name = "cmd::cp", skip_all, fields(dest = %args.dest, recursive = args.recursive))]
pub fn execute(vault_ops: &VaultOperations, args: &Args) -> Result<()> {
    let dest = normalize_path(&args.dest);
    let mut stats = CopyStats::default();

    // Validate sources exist
    for source in &args.sources {
        let source_path = normalize_path(source);
        let entry_type = vault_ops.entry_type(&source_path);

        match entry_type {
            None => {
                anyhow::bail!("Source path does not exist: {source_path}");
            }
            Some(EntryType::Directory) if !args.recursive => {
                anyhow::bail!(
                    "Source '{source_path}' is a directory. Use -r/--recursive to copy directories."
                );
            }
            _ => {}
        }
    }

    // Determine if destination is a directory
    let dest_is_dir = dest.ends_with('/')
        || args.sources.len() > 1
        || matches!(vault_ops.entry_type(&dest), Some(EntryType::Directory));

    // Ensure destination directory exists if needed
    if dest_is_dir && vault_ops.entry_type(&dest).is_none() {
        ensure_directory_exists(vault_ops, &dest)?;
        stats.directories_created += 1;
    }

    // Copy each source
    for source in &args.sources {
        let source_path = normalize_path(source);

        let target_path = if dest_is_dir {
            // Append source filename to destination directory
            let file_name = source_path
                .rsplit('/')
                .next()
                .unwrap_or(&source_path);
            format!("{}/{}", dest.trim_end_matches('/'), file_name)
        } else {
            dest.clone()
        };

        match vault_ops.entry_type(&source_path) {
            Some(EntryType::File) => {
                copy_file(vault_ops, &source_path, &target_path, args, &mut stats)?;
            }
            Some(EntryType::Directory) => {
                copy_directory(vault_ops, &source_path, &target_path, args, &mut stats)?;
            }
            Some(EntryType::Symlink) => {
                copy_symlink(vault_ops, &source_path, &target_path, args, &mut stats)?;
            }
            None => {
                // Already validated above
                anyhow::bail!("Source path does not exist: {source_path}");
            }
        }
    }

    // Print summary if verbose or if there were errors
    if args.verbose || !stats.errors.is_empty() {
        if !stats.errors.is_empty() {
            eprintln!();
            eprintln!("Errors:");
            for error in &stats.errors {
                eprintln!("  - {error}");
            }
        }

        eprintln!(
            "Copied {} file(s), {} director{}, {} symlink(s)",
            stats.files_copied,
            stats.directories_created,
            if stats.directories_created == 1 { "y" } else { "ies" },
            stats.symlinks_copied
        );
    }

    if !stats.errors.is_empty() {
        anyhow::bail!("{} error(s) occurred during copy", stats.errors.len());
    }

    Ok(())
}

/// Copy a single file within the vault
fn copy_file(
    vault_ops: &VaultOperations,
    source: &str,
    dest: &str,
    args: &Args,
    stats: &mut CopyStats,
) -> Result<()> {
    // Read source file
    let content = vault_ops
        .read_by_path(source)
        .with_context(|| format!("Failed to read source: {source}"))?;

    // Ensure parent directory exists
    if let Some(parent) = dest.rsplit_once('/').map(|(p, _)| p)
        && !parent.is_empty() && vault_ops.entry_type(parent).is_none() {
            ensure_directory_exists(vault_ops, parent)?;
        }

    // Write to destination
    vault_ops
        .write_by_path(dest, &content.content)
        .with_context(|| format!("Failed to write to: {dest}"))?;

    if args.verbose {
        eprintln!("Copied: {source} -> {dest}");
    }

    stats.files_copied += 1;
    Ok(())
}

/// Copy a directory recursively within the vault
fn copy_directory(
    vault_ops: &VaultOperations,
    source: &str,
    dest: &str,
    args: &Args,
    stats: &mut CopyStats,
) -> Result<()> {
    // Create destination directory
    if vault_ops.entry_type(dest).is_none() {
        ensure_directory_exists(vault_ops, dest)?;
        stats.directories_created += 1;

        if args.verbose {
            eprintln!("Created directory: {dest}");
        }
    }

    // Resolve the source path to a directory ID
    let dir_id = if source == "/" || source.is_empty() {
        DirId::root()
    } else {
        let (id, is_dir) = vault_ops.resolve_path(source)?;
        if !is_dir {
            anyhow::bail!("Not a directory: {source}");
        }
        id
    };

    // List directory contents
    let files = vault_ops.list_files(&dir_id)?;
    let dirs = vault_ops.list_directories(&dir_id)?;
    let symlinks = vault_ops.list_symlinks(&dir_id)?;

    // Copy files
    for file in files {
        let entry_source = if source == "/" {
            format!("/{}", file.name)
        } else {
            format!("{}/{}", source, file.name)
        };
        let entry_dest = format!("{}/{}", dest.trim_end_matches('/'), file.name);

        match copy_file(vault_ops, &entry_source, &entry_dest, args, stats) {
            Ok(()) => {}
            Err(e) => {
                stats.errors.push(format!("{entry_source}: {e}"));
            }
        }
    }

    // Copy subdirectories
    for dir in dirs {
        let entry_source = if source == "/" {
            format!("/{}", dir.name)
        } else {
            format!("{}/{}", source, dir.name)
        };
        let entry_dest = format!("{}/{}", dest.trim_end_matches('/'), dir.name);

        match copy_directory(vault_ops, &entry_source, &entry_dest, args, stats) {
            Ok(()) => {}
            Err(e) => {
                stats.errors.push(format!("{entry_source}: {e}"));
            }
        }
    }

    // Copy symlinks
    for symlink in symlinks {
        let entry_source = if source == "/" {
            format!("/{}", symlink.name)
        } else {
            format!("{}/{}", source, symlink.name)
        };
        let entry_dest = format!("{}/{}", dest.trim_end_matches('/'), symlink.name);

        match copy_symlink(vault_ops, &entry_source, &entry_dest, args, stats) {
            Ok(()) => {}
            Err(e) => {
                stats.errors.push(format!("{entry_source}: {e}"));
            }
        }
    }

    Ok(())
}

/// Copy a symlink within the vault
fn copy_symlink(
    vault_ops: &VaultOperations,
    source: &str,
    dest: &str,
    args: &Args,
    stats: &mut CopyStats,
) -> Result<()> {
    // Read symlink target
    let target = vault_ops
        .read_symlink_by_path(source)
        .with_context(|| format!("Failed to read symlink: {source}"))?;

    // Ensure parent directory exists
    if let Some(parent) = dest.rsplit_once('/').map(|(p, _)| p)
        && !parent.is_empty() && vault_ops.entry_type(parent).is_none() {
            ensure_directory_exists(vault_ops, parent)?;
        }

    // Create symlink at destination
    vault_ops
        .create_symlink_by_path(dest, &target)
        .with_context(|| format!("Failed to create symlink: {dest}"))?;

    if args.verbose {
        eprintln!("Copied symlink: {source} -> {dest} (target: {target})");
    }

    stats.symlinks_copied += 1;
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
                anyhow::bail!("Cannot create directory '{current_path}': path exists as a file");
            }
            Some(EntryType::Symlink) => {
                anyhow::bail!("Cannot create directory '{current_path}': path exists as a symlink");
            }
            None => {
                // Create directory
                vault_ops.create_directory_by_path(&current_path)?;
            }
        }
    }

    Ok(())
}
