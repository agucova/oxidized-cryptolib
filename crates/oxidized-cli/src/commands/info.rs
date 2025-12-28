use std::path::Path;

use anyhow::Result;
use clap::Args as ClapArgs;

use oxidized_cryptolib::vault::config::VaultConfigurationClaims;

use crate::output::create_table;

#[derive(ClapArgs)]
pub struct Args {
    /// Show raw JWT token details
    #[arg(long)]
    pub raw: bool,
}

pub fn execute(vault_path: &Path, claims: &VaultConfigurationClaims, _args: Args) -> Result<()> {
    let mut table = create_table();
    table.set_header(vec!["Property", "Value"]);
    table.add_row(vec!["Vault Path", &vault_path.display().to_string()]);
    table.add_row(vec!["Format", &claims.format().to_string()]);
    let cipher_str = claims
        .cipher_combo()
        .map(|c| c.as_str())
        .unwrap_or("Unknown");
    table.add_row(vec!["Cipher", cipher_str]);
    table.add_row(vec![
        "Shortening Threshold",
        &claims.shortening_threshold().to_string(),
    ]);
    println!("{table}");
    Ok(())
}
