use anyhow::{bail, Result};
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;
use oxidized_cryptolib::vault::path::DirId;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Starting path (default: root)
    #[arg(default_value = "/")]
    pub path: String,

    /// Maximum depth to display
    #[arg(short = 'd', long)]
    pub max_depth: Option<usize>,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let normalized = normalize_path(&args.path);
    let path = if normalized == "/" { "" } else { &normalized };

    let dir_id = if path.is_empty() {
        DirId::root()
    } else {
        let (id, is_dir) = vault_ops.resolve_path(path)?;
        if !is_dir {
            bail!("Not a directory: {}", args.path);
        }
        id
    };

    let name = if args.path == "/" { "." } else { &args.path };
    println!("{name}");
    print_tree_recursive(vault_ops, &dir_id, "", 0, args.max_depth)?;

    Ok(())
}

fn print_tree_recursive(
    vault_ops: &VaultOperations,
    dir_id: &DirId,
    prefix: &str,
    depth: usize,
    max_depth: Option<usize>,
) -> Result<()> {
    if let Some(max) = max_depth {
        if depth >= max {
            return Ok(());
        }
    }

    let dirs = vault_ops.list_directories(dir_id)?;
    let files = vault_ops.list_files(dir_id)?;
    let symlinks = vault_ops.list_symlinks(dir_id)?;

    let total = dirs.len() + files.len() + symlinks.len();
    let mut current = 0;

    // Print directories
    for dir in &dirs {
        current += 1;
        let is_last = current == total;
        let connector = if is_last { "└── " } else { "├── " };
        println!("{prefix}{connector}{}/", dir.name);

        let new_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };
        print_tree_recursive(vault_ops, &dir.directory_id, &new_prefix, depth + 1, max_depth)?;
    }

    // Print files
    for file in &files {
        current += 1;
        let is_last = current == total;
        let connector = if is_last { "└── " } else { "├── " };
        println!("{prefix}{connector}{}", file.name);
    }

    // Print symlinks
    for symlink in &symlinks {
        current += 1;
        let is_last = current == total;
        let connector = if is_last { "└── " } else { "├── " };
        println!("{prefix}{connector}{} -> {}", symlink.name, symlink.target);
    }

    Ok(())
}
