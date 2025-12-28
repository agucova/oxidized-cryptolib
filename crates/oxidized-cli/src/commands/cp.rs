use anyhow::Result;
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Source file path
    pub source: String,

    /// Destination path
    pub dest: String,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let source = normalize_path(&args.source);
    let dest = normalize_path(&args.dest);

    // Read source file
    let content = vault_ops.read_by_path(&source)?;

    // Write to destination
    vault_ops.write_by_path(&dest, &content.content)?;

    Ok(())
}
