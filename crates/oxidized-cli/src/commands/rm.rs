use anyhow::{bail, Result};
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::path::EntryType;
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

    match vault_ops.entry_type(&path) {
        Some(EntryType::Directory) => {
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
        Some(EntryType::File) => {
            vault_ops.delete_by_path(&path)?;
        }
        Some(EntryType::Symlink) => {
            vault_ops.delete_symlink_by_path(&path)?;
        }
        None => {
            if !args.force {
                bail!("Path not found: {}", path);
            }
        }
    }

    Ok(())
}
