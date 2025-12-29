use anyhow::Result;
use clap::Args as ClapArgs;

use oxcrypt_core::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Source path
    pub source: String,

    /// Destination path
    pub dest: String,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let source = normalize_path(&args.source);
    let dest = normalize_path(&args.dest);
    vault_ops.move_file_by_path(&source, &dest)?;
    Ok(())
}
