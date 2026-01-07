use anyhow::Result;
use clap::Args as ClapArgs;
use std::io::{self, Write};
use tracing::instrument;

use oxcrypt_core::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// File path within the vault
    pub file: String,
}

#[instrument(level = "info", name = "cmd::cat", skip_all, fields(file = %args.file))]
pub fn execute(vault_ops: &VaultOperations, args: &Args) -> Result<()> {
    let path = normalize_path(&args.file);
    let decrypted = vault_ops.read_by_path(&path)?;
    io::stdout().write_all(&decrypted.content)?;
    Ok(())
}
