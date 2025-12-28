use anyhow::{bail, Result};
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Path to remove
    pub path: String,

    /// Remove directories and their contents recursively
    #[arg(short, long)]
    pub recursive: bool,

    /// Force removal without confirmation (ignore nonexistent files)
    #[arg(short, long)]
    pub force: bool,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let path = normalize_path(&args.path);
    let exists = vault_ops.exists_by_path(&path);

    match exists {
        Some(true) => {
            // It's a directory
            if args.recursive {
                let stats = vault_ops.delete_directory_recursive_by_path(&path)?;
                eprintln!(
                    "Deleted {} files and {} directories",
                    stats.files_deleted, stats.directories_deleted
                );
            } else {
                vault_ops.delete_directory_by_path(&path)?;
            }
        }
        Some(false) => {
            // It's a file
            vault_ops.delete_by_path(&path)?;
        }
        None => {
            if !args.force {
                bail!("Path not found: {}", path);
            }
        }
    }

    Ok(())
}
