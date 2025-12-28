use std::io::{self, Read};

use anyhow::Result;
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;

use super::normalize_path;

#[derive(ClapArgs)]
pub struct Args {
    /// Destination path in the vault
    pub path: String,

    /// Append to file instead of overwriting
    #[arg(short, long)]
    pub append: bool,
}

pub fn execute(vault_ops: &VaultOperations, args: Args) -> Result<()> {
    let path = normalize_path(&args.path);

    // Read all content from stdin
    let mut content = Vec::new();
    io::stdin().read_to_end(&mut content)?;

    // Check if path exists (Some(false) = file, Some(true) = dir, None = doesn't exist)
    let file_exists = vault_ops.exists_by_path(&path) == Some(false);

    if args.append && file_exists {
        // Read existing content and append
        let existing = vault_ops.read_by_path(&path)?;
        let mut combined = existing.content;
        combined.extend(content);
        vault_ops.write_by_path(&path, &combined)?;
    } else {
        // Write new file (or overwrite)
        vault_ops.write_by_path(&path, &content)?;
    }

    Ok(())
}
