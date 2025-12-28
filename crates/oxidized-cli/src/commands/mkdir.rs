use anyhow::Result;
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::operations::VaultOperations;

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
        create_with_parents(vault_ops, &path)?;
    } else {
        vault_ops.create_directory_by_path(&path)?;
    }
    Ok(())
}

fn create_with_parents(vault_ops: &VaultOperations, path: &str) -> Result<()> {
    let path = path.trim_start_matches('/');
    let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let mut current_path = String::new();
    for component in components {
        if !current_path.is_empty() {
            current_path.push('/');
        }
        current_path.push_str(component);

        // Check if path exists
        match vault_ops.exists_by_path(&current_path) {
            Some(true) => {
                // Directory exists, continue
            }
            Some(false) => {
                // It's a file, can't create directory
                anyhow::bail!("Path component is a file: {}", current_path);
            }
            None => {
                // Doesn't exist, create it
                vault_ops.create_directory_by_path(&current_path)?;
            }
        }
    }

    Ok(())
}
