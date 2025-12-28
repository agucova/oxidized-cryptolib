use anyhow::{bail, Result};
use rpassword::read_password;
use std::io::{self, Write};

/// Prompt the user for the vault passphrase securely.
/// Input is hidden and not echoed to the terminal.
///
/// For non-interactive use, pass `--password` or set `OXCRYPT_PASSWORD`.
pub fn prompt_passphrase() -> Result<String> {
    eprint!("Vault passphrase: ");
    io::stderr().flush()?;

    let passphrase = read_password()?;

    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty");
    }

    Ok(passphrase)
}
