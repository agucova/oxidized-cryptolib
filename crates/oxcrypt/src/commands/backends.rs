//! Backends command - list available mount backends and their status.

use anyhow::Result;
use clap::Args as ClapArgs;
use comfy_table::{Cell, Color, Table};
use oxcrypt_mount::BackendInfo;

use super::mount::list_backends;

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn execute(args: Args) -> Result<()> {
    let backends = list_backends();

    if backends.is_empty() {
        eprintln!("No mount backends are enabled.");
        eprintln!("Rebuild with --features fuse or --features fskit to enable backends.");
        return Ok(());
    }

    if args.json {
        output_json(&backends)?;
    } else {
        output_table(&backends);
    }

    Ok(())
}

fn output_table(backends: &[BackendInfo]) {
    let mut table = Table::new();
    table.set_header(vec!["Backend", "Status", "Notes"]);

    for backend in backends {
        let status = if backend.available {
            Cell::new("Available").fg(Color::Green)
        } else {
            Cell::new("Unavailable").fg(Color::Red)
        };

        let default_notes = match backend.id.as_str() {
            "fuse" => "Cross-platform (macOS, Linux)",
            "fskit" => "Native macOS integration (15.4+)",
            "webdav" => "Cross-platform (Windows, macOS, Linux)",
            "nfs" => "NFSv3 server (macOS, Linux, no extensions)",
            _ => "",
        };
        let notes = backend.unavailable_reason.as_deref().unwrap_or(default_notes);

        table.add_row(vec![
            Cell::new(&backend.name),
            status,
            Cell::new(notes),
        ]);
    }

    println!("{table}");

    // Print summary
    let available_count = backends.iter().filter(|b| b.available).count();
    if available_count == 0 {
        eprintln!("\nNo backends are available on this system.");
        #[cfg(target_os = "macos")]
        eprintln!("Install macFUSE (https://osxfuse.github.io/) or upgrade to macOS 15.4+.");
        #[cfg(target_os = "linux")]
        eprintln!("Ensure the FUSE kernel module is loaded (modprobe fuse).");
        #[cfg(target_os = "windows")]
        eprintln!("Rebuild with --features webdav to enable WebDAV mounting.");
    } else {
        eprintln!("\n{} backend(s) available for mounting.", available_count);
    }
}

fn output_json(backends: &[BackendInfo]) -> Result<()> {
    let json_backends: Vec<_> = backends
        .iter()
        .map(|b| serde_json::json!({
            "id": b.id,
            "name": b.name,
            "available": b.available,
            "unavailable_reason": b.unavailable_reason,
        }))
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_backends)?);
    Ok(())
}
