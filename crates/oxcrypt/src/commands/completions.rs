//! Shell completion generation for oxcrypt CLI.
//!
//! Generates shell completions for bash, zsh, fish, and PowerShell.
//!
//! # Examples
//!
//! ```bash
//! # Bash (add to ~/.bashrc)
//! eval "$(oxcrypt completions bash)"
//!
//! # Zsh (add to ~/.zshrc)
//! eval "$(oxcrypt completions zsh)"
//!
//! # Fish (save to completions directory)
//! oxcrypt completions fish > ~/.config/fish/completions/oxcrypt.fish
//!
//! # PowerShell (add to profile)
//! oxcrypt completions powershell >> $PROFILE
//! ```

use std::io;

use anyhow::Result;
use clap::{Args as ClapArgs, CommandFactory, ValueEnum};
use clap_complete::{generate, Shell};

use crate::Cli;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: ShellType,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ShellType {
    /// Bourne Again SHell
    Bash,
    /// Z shell
    Zsh,
    /// Friendly Interactive SHell
    Fish,
    /// PowerShell
    Powershell,
    /// Elvish
    Elvish,
}

impl From<ShellType> for Shell {
    fn from(shell: ShellType) -> Self {
        match shell {
            ShellType::Bash => Shell::Bash,
            ShellType::Zsh => Shell::Zsh,
            ShellType::Fish => Shell::Fish,
            ShellType::Powershell => Shell::PowerShell,
            ShellType::Elvish => Shell::Elvish,
        }
    }
}

pub fn execute(args: Args) -> Result<()> {
    let mut cmd = Cli::command();
    let shell: Shell = args.shell.into();

    generate(shell, &mut cmd, "oxcrypt", &mut io::stdout());

    Ok(())
}
