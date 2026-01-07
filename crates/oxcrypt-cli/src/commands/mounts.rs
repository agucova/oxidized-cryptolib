//! Mounts command - list currently active oxcrypt mounts.

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Args as ClapArgs;
use tracing::instrument;
use comfy_table::{Cell, Color, Table};

use crate::state::{MountEntry, MountStateManager};

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Include stale (dead process) entries
    #[arg(long)]
    pub include_stale: bool,

    /// Don't clean up stale entries automatically
    #[arg(long)]
    pub no_cleanup: bool,
}

#[instrument(level = "info", name = "cmd::mounts", skip_all)]
pub fn execute(args: &Args) -> Result<()> {
    let manager = MountStateManager::new()?;
    let (active, stale) = manager.validate_entries()?;

    // Clean up stale entries unless --no-cleanup or --include-stale
    if !args.no_cleanup && !args.include_stale && !stale.is_empty() {
        let removed = manager.cleanup_stale()?;
        if !removed.is_empty() {
            eprintln!("Cleaned up {} stale mount entries", removed.len());
        }
    }

    if args.json {
        output_json(&active, if args.include_stale { Some(&stale) } else { None })?;
    } else {
        if active.is_empty() && stale.is_empty() {
            eprintln!("No active mounts.");
            eprintln!("Use 'oxcrypt mount --daemon' to start a background mount.");
            return Ok(());
        }

        if !active.is_empty() {
            output_table(&active, "Active Mounts");
        }

        if args.include_stale && !stale.is_empty() {
            eprintln!();
            output_table(&stale, "Stale Mounts (process dead or unmounted)");
        }

        // Summary
        eprintln!();
        eprintln!(
            "{} active mount(s){}",
            active.len(),
            if !stale.is_empty() && args.include_stale {
                format!(", {} stale", stale.len())
            } else {
                String::new()
            }
        );
    }

    Ok(())
}

fn output_table(entries: &[MountEntry], title: &str) {
    let mut table = Table::new();
    table.set_header(vec!["Vault", "Mountpoint", "Backend", "PID", "Started"]);

    for entry in entries {
        let vault_display = entry
            .vault_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| entry.vault_path.to_str().unwrap_or("?"));

        let mountpoint_display = entry.mountpoint.display().to_string();

        let backend_cell = Cell::new(&entry.backend).fg(match entry.backend.as_str() {
            "fuse" | "FUSE" => Color::Blue,
            "fskit" | "FSKit" => Color::Green,
            "webdav" | "WebDAV" => Color::Yellow,
            "nfs" | "NFS" => Color::Magenta,
            _ => Color::White,
        });

        let started = format_relative_time(entry.started_at);

        table.add_row(vec![
            Cell::new(vault_display),
            Cell::new(&mountpoint_display),
            backend_cell,
            Cell::new(entry.pid.to_string()),
            Cell::new(started),
        ]);
    }

    eprintln!("{title}");
    println!("{table}");
}

fn output_json(active: &[MountEntry], stale: Option<&[MountEntry]>) -> Result<()> {
    let output = if let Some(stale) = stale {
        serde_json::json!({
            "active": active.iter().map(entry_to_json).collect::<Vec<_>>(),
            "stale": stale.iter().map(entry_to_json).collect::<Vec<_>>(),
        })
    } else {
        serde_json::json!({
            "active": active.iter().map(entry_to_json).collect::<Vec<_>>(),
        })
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn entry_to_json(entry: &MountEntry) -> serde_json::Value {
    serde_json::json!({
        "id": entry.id,
        "vault_path": entry.vault_path,
        "mountpoint": entry.mountpoint,
        "backend": entry.backend,
        "pid": entry.pid,
        "started_at": entry.started_at.to_rfc3339(),
        "is_daemon": entry.is_daemon,
    })
}

fn format_relative_time(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(dt);

    if duration.num_seconds() < 60 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        let mins = duration.num_minutes();
        format!("{} min{} ago", mins, if mins == 1 { "" } else { "s" })
    } else if duration.num_hours() < 24 {
        let hours = duration.num_hours();
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else {
        let days = duration.num_days();
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    }
}
