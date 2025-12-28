use anyhow::Result;
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Path to the file to create
    pub path: String,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let path = normalize_path(&args.path);

    // Check if file already exists (Some(true) = dir, Some(false) = file, None = doesn't exist)
    if vault_ops.exists_by_path(&path).is_some() {
        // Path exists, nothing to do (real touch would update mtime, but we can't)
        return Ok(());
    }

    // Create empty file
    vault_ops.write_by_path(&path, b"")?;
    Ok(())
}
