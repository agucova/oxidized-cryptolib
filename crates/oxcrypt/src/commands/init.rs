use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::Path;

use oxcrypt_core::vault::VaultCreator;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Path where the vault will be created
    pub path: String,

    /// Passphrase for the new vault
    #[arg(long, env = "OXCRYPT_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

pub fn execute(args: Args) -> Result<()> {
    let path = Path::new(&args.path);

    // Get password from flag, env, or prompt
    let password = match args.password {
        Some(p) => p,
        None => {
            eprint!("New vault passphrase: ");
            std::io::Write::flush(&mut std::io::stderr())?;
            let pass1 = rpassword::read_password()?;

            eprint!("Confirm passphrase: ");
            std::io::Write::flush(&mut std::io::stderr())?;
            let pass2 = rpassword::read_password()?;

            if pass1 != pass2 {
                anyhow::bail!("Passphrases do not match");
            }
            if pass1.is_empty() {
                anyhow::bail!("Passphrase cannot be empty");
            }
            pass1
        }
    };

    VaultCreator::new(path, &password)
        .create()
        .context("Failed to create vault")?;

    println!("Created new vault at: {}", path.display());
    Ok(())
}
