use anyhow::Result;
use clap::Args as ClapArgs;
use std::io::{self, Write};

use oxidized_cryptolib::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// File path within the vault
    pub file: String,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let path = normalize_path(&args.file);
    let decrypted = vault_ops.read_by_path(&path)?;
    io::stdout().write_all(&decrypted.content)?;
    Ok(())
}
