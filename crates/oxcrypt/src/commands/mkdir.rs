use anyhow::Result;
use clap::Args as ClapArgs;

use oxcrypt_core::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Directory path to create
    pub path: String,

    /// Create parent directories as needed
    #[arg(short, long)]
    pub parents: bool,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let path = normalize_path(&args.path);

    if args.parents {
        // Use create_directory_all for mkdir -p behavior
        vault_ops.create_directory_all(&path)?;
    } else {
        vault_ops.create_directory_by_path(&path)?;
    }
    Ok(())
}
