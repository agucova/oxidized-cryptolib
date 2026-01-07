//! List command - list directory contents in a vault.
//!
//! # Examples
//!
//! ```bash
//! # List root directory
//! oxcrypt ~/vault ls
//!
//! # List with details
//! oxcrypt ~/vault ls -l /documents
//!
//! # Output as JSON for scripting
//! oxcrypt ~/vault ls --json / | jq '.entries[].name'
//! ```

use anyhow::{bail, Result};
use clap::Args as ClapArgs;
use serde::Serialize;
use tracing::instrument;

use oxcrypt_core::fs::encrypted_to_plaintext_size_or_zero;
use oxcrypt_core::vault::operations::VaultOperations;
use oxcrypt_core::vault::path::DirId;

use super::normalize_path;
use crate::output::{create_table, format_entry_type, format_size};

#[allow(clippy::struct_excessive_bools)] // Command-line args naturally have multiple boolean flags
#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Path within the vault (default: root)
    #[arg(default_value = "/")]
    pub path: String,

    /// Show detailed information
    #[arg(short, long)]
    pub long: bool,

    /// Show all files including hidden
    #[arg(short, long)]
    pub all: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// One entry per line (script-friendly)
    #[arg(short = '1')]
    pub one_per_line: bool,
}

/// JSON output format for ls command
#[derive(Serialize)]
struct LsOutput {
    path: String,
    entries: Vec<EntryInfo>,
}

#[derive(Serialize)]
struct EntryInfo {
    name: String,
    #[serde(rename = "type")]
    entry_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
}

#[instrument(level = "info", name = "cmd::ls", skip_all, fields(path = %args.path))]
pub fn execute(vault_ops: &VaultOperations, args: &Args) -> Result<()> {
    let normalized = normalize_path(&args.path);
    let path = if normalized == "/" { "" } else { &normalized };

    // Resolve the path to a directory ID
    let dir_id = if path.is_empty() {
        DirId::root()
    } else {
        let (id, is_dir) = vault_ops.resolve_path(path)?;
        if !is_dir {
            bail!("Not a directory: {}", args.path);
        }
        id
    };

    // Get directory contents
    let files = vault_ops.list_files(&dir_id)?;
    let dirs = vault_ops.list_directories(&dir_id)?;
    let symlinks = vault_ops.list_symlinks(&dir_id)?;

    if args.json {
        print_json(&normalized, &files, &dirs, &symlinks, args.all)?;
    } else if args.long {
        print_long_format(&files, &dirs, &symlinks, args.all);
    } else {
        print_short_format(&files, &dirs, &symlinks, args.all, args.one_per_line);
    }

    Ok(())
}

fn print_json(
    path: &str,
    files: &[oxcrypt_core::vault::operations::VaultFileInfo],
    dirs: &[oxcrypt_core::vault::operations::VaultDirectoryInfo],
    symlinks: &[oxcrypt_core::vault::operations::VaultSymlinkInfo],
    show_hidden: bool,
) -> Result<()> {
    let mut entries = Vec::new();

    // Directories
    for dir in dirs {
        if !show_hidden && dir.name.starts_with('.') {
            continue;
        }
        entries.push(EntryInfo {
            name: dir.name.clone(),
            entry_type: "directory".to_string(),
            size: None,
            target: None,
        });
    }

    // Files
    for file in files {
        if !show_hidden && file.name.starts_with('.') {
            continue;
        }
        entries.push(EntryInfo {
            name: file.name.clone(),
            entry_type: "file".to_string(),
            size: Some(encrypted_to_plaintext_size_or_zero(file.encrypted_size)),
            target: None,
        });
    }

    // Symlinks
    for symlink in symlinks {
        if !show_hidden && symlink.name.starts_with('.') {
            continue;
        }
        entries.push(EntryInfo {
            name: symlink.name.clone(),
            entry_type: "symlink".to_string(),
            size: None,
            target: Some(symlink.target.clone()),
        });
    }

    let output = LsOutput {
        path: path.to_string(),
        entries,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_long_format(
    files: &[oxcrypt_core::vault::operations::VaultFileInfo],
    dirs: &[oxcrypt_core::vault::operations::VaultDirectoryInfo],
    symlinks: &[oxcrypt_core::vault::operations::VaultSymlinkInfo],
    show_hidden: bool,
) {
    let mut table = create_table();
    table.set_header(vec!["Type", "Size", "Name"]);

    // Directories first
    for dir in dirs {
        if !show_hidden && dir.name.starts_with('.') {
            continue;
        }
        table.add_row(vec![
            format_entry_type(true, false).to_string(),
            "-".to_string(),
            format!("{}/", dir.name),
        ]);
    }

    // Then files
    for file in files {
        if !show_hidden && file.name.starts_with('.') {
            continue;
        }
        table.add_row(vec![
            format_entry_type(false, false).to_string(),
            format_size(encrypted_to_plaintext_size_or_zero(file.encrypted_size)),
            file.name.clone(),
        ]);
    }

    // Then symlinks
    for symlink in symlinks {
        if !show_hidden && symlink.name.starts_with('.') {
            continue;
        }
        table.add_row(vec![
            format_entry_type(false, true).to_string(),
            "-".to_string(),
            format!("{} -> {}", symlink.name, symlink.target),
        ]);
    }

    println!("{table}");
}

fn print_short_format(
    files: &[oxcrypt_core::vault::operations::VaultFileInfo],
    dirs: &[oxcrypt_core::vault::operations::VaultDirectoryInfo],
    symlinks: &[oxcrypt_core::vault::operations::VaultSymlinkInfo],
    show_hidden: bool,
    one_per_line: bool,
) {
    let mut entries: Vec<String> = Vec::new();

    for dir in dirs {
        if !show_hidden && dir.name.starts_with('.') {
            continue;
        }
        entries.push(format!("{}/", dir.name));
    }

    for file in files {
        if !show_hidden && file.name.starts_with('.') {
            continue;
        }
        entries.push(file.name.clone());
    }

    for symlink in symlinks {
        if !show_hidden && symlink.name.starts_with('.') {
            continue;
        }
        entries.push(format!("{}@", symlink.name));
    }

    if one_per_line || entries.len() > 10 {
        // One per line for many entries or when requested
        for entry in entries {
            println!("{entry}");
        }
    } else {
        // Space-separated for few entries
        println!("{}", entries.join("  "));
    }
}
