use anyhow::{bail, Result};
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;
use oxidized_cryptolib::vault::path::DirId;

use super::normalize_path;
use crate::output::{create_table, format_entry_type, format_size};

#[derive(ClapArgs)]
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
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
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

    if args.long {
        print_long_format(&files, &dirs, &symlinks, args.all);
    } else {
        print_short_format(&files, &dirs, &symlinks, args.all);
    }

    Ok(())
}

fn print_long_format(
    files: &[oxidized_cryptolib::vault::operations::VaultFileInfo],
    dirs: &[oxidized_cryptolib::vault::operations::VaultDirectoryInfo],
    symlinks: &[oxidized_cryptolib::vault::operations::VaultSymlinkInfo],
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
            format_size(file.encrypted_size),
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
    files: &[oxidized_cryptolib::vault::operations::VaultFileInfo],
    dirs: &[oxidized_cryptolib::vault::operations::VaultDirectoryInfo],
    symlinks: &[oxidized_cryptolib::vault::operations::VaultSymlinkInfo],
    show_hidden: bool,
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

    for entry in entries {
        println!("{entry}");
    }
}
