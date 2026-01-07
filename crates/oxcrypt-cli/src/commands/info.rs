//! Info command - show vault information and configuration.
//!
//! # Examples
//!
//! ```bash
//! # Show vault info in table format
//! oxcrypt ~/vault info
//!
//! # Output as JSON for scripting
//! oxcrypt ~/vault info --json
//! ```

use std::path::Path;

use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Serialize;
use tracing::instrument;

use oxcrypt_core::vault::config::VaultConfigurationClaims;

use crate::output::create_table;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Show raw JWT token details
    #[arg(long)]
    pub raw: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// JSON output format for info command
#[derive(Serialize)]
struct VaultInfo {
    vault_path: String,
    format: i32,
    cipher: String,
    shortening_threshold: usize,
}

#[instrument(level = "info", name = "cmd::info", skip_all, fields(vault = %vault_path.display()))]
pub fn execute(vault_path: &Path, claims: &VaultConfigurationClaims, args: &Args) -> Result<()> {
    let cipher_str = claims
        .cipher_combo()
        .map_or("Unknown", |c| c.as_str());

    if args.json {
        let info = VaultInfo {
            vault_path: vault_path.display().to_string(),
            format: claims.format(),
            cipher: cipher_str.to_string(),
            shortening_threshold: claims.shortening_threshold(),
        };
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        let mut table = create_table();
        table.set_header(vec!["Property", "Value"]);
        table.add_row(vec!["Vault Path", &vault_path.display().to_string()]);
        table.add_row(vec!["Format", &claims.format().to_string()]);
        table.add_row(vec!["Cipher", cipher_str]);
        table.add_row(vec![
            "Shortening Threshold",
            &claims.shortening_threshold().to_string(),
        ]);
        println!("{table}");
    }

    Ok(())
}
