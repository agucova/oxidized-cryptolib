//! Settings dialog with tabbed interface
//!
//! Provides application-wide settings for mount backends, default paths,
//! and debugging options.

use dioxus::prelude::*;

use crate::state::{use_app_state, BackendType};

/// Active tab in the settings dialog
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsTab {
    #[default]
    General,
    About,
}

/// Props for the settings dialog
#[derive(Props, Clone, PartialEq)]
pub struct SettingsDialogProps {
    /// Called when the dialog is closed
    pub on_close: EventHandler<()>,
}

/// Settings dialog component
#[component]
pub fn SettingsDialog(props: SettingsDialogProps) -> Element {
    let mut active_tab = use_signal(|| SettingsTab::General);

    rsx! {
        // Backdrop
        div {
            style: "
                position: fixed;
                inset: 0;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000;
            ",
            onclick: move |_| props.on_close.call(()),

            // Dialog
            div {
                style: "
                    background: white;
                    border-radius: 12px;
                    width: 500px;
                    max-width: 90vw;
                    max-height: 80vh;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
                    display: flex;
                    flex-direction: column;
                    overflow: hidden;
                ",
                onclick: move |e| e.stop_propagation(),

                // Header with tabs
                div {
                    style: "
                        border-bottom: 1px solid #e0e0e0;
                        padding: 16px 24px 0 24px;
                    ",

                    // Title
                    h2 {
                        style: "margin: 0 0 16px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                        "Settings"
                    }

                    // Tab bar
                    div {
                        style: "display: flex; gap: 0;",

                        TabButton {
                            label: "General",
                            icon: "⚙️",
                            is_active: active_tab() == SettingsTab::General,
                            on_click: move |_| active_tab.set(SettingsTab::General),
                        }
                        TabButton {
                            label: "About",
                            icon: "ℹ️",
                            is_active: active_tab() == SettingsTab::About,
                            on_click: move |_| active_tab.set(SettingsTab::About),
                        }
                    }
                }

                // Content area
                div {
                    style: "
                        flex: 1;
                        padding: 24px;
                        overflow-y: auto;
                    ",

                    match active_tab() {
                        SettingsTab::General => rsx! { GeneralTab {} },
                        SettingsTab::About => rsx! { AboutTab {} },
                    }
                }

                // Footer with close button
                div {
                    style: "
                        padding: 16px 24px;
                        border-top: 1px solid #e0e0e0;
                        display: flex;
                        justify-content: flex-end;
                    ",

                    button {
                        style: "
                            padding: 10px 24px;
                            background: #2196f3;
                            color: white;
                            border: none;
                            border-radius: 6px;
                            font-size: 14px;
                            font-weight: 500;
                            cursor: pointer;
                        ",
                        onclick: move |_| props.on_close.call(()),
                        "Done"
                    }
                }
            }
        }
    }
}

// ============================================================================
// Tab Button Component
// ============================================================================

#[derive(Props, Clone, PartialEq)]
struct TabButtonProps {
    label: &'static str,
    icon: &'static str,
    is_active: bool,
    on_click: EventHandler<()>,
}

#[component]
fn TabButton(props: TabButtonProps) -> Element {
    let base_style = "
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 10px 16px;
        border: none;
        background: transparent;
        font-size: 14px;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        margin-bottom: -1px;
        transition: all 0.15s ease;
    ";

    let active_style = if props.is_active {
        "color: #2196f3; border-bottom-color: #2196f3; font-weight: 500;"
    } else {
        "color: #666;"
    };

    rsx! {
        button {
            style: "{base_style} {active_style}",
            onclick: move |_| props.on_click.call(()),
            span { "{props.icon}" }
            span { "{props.label}" }
        }
    }
}

// ============================================================================
// General Tab
// ============================================================================

#[component]
fn GeneralTab() -> Element {
    let mut app_state = use_app_state();
    let config = app_state.read().config.clone();

    // Handle backend change
    let handle_backend_change = move |e: Event<FormData>| {
        let value = e.value();
        let backend = match value.as_str() {
            "Fuse" => BackendType::Fuse,
            "FSKit" => BackendType::FSKit,
            "WebDav" => BackendType::WebDav,
            "Nfs" => BackendType::Nfs,
            _ => return,
        };
        app_state.write().config.default_backend = backend;
        if let Err(e) = app_state.read().save() {
            tracing::error!("Failed to save config: {}", e);
        }
    };

    // Handle mount prefix browse
    let handle_browse_mount_prefix = move |_| {
        spawn(async move {
            let folder = rfd::AsyncFileDialog::new()
                .set_title("Select Default Mount Location")
                .pick_folder()
                .await;

            if let Some(folder) = folder {
                let path = folder.path().to_path_buf();
                app_state.write().config.default_mount_prefix = Some(path);
                if let Err(e) = app_state.read().save() {
                    tracing::error!("Failed to save config: {}", e);
                }
            }
        });
    };

    // Handle clear mount prefix
    let handle_clear_mount_prefix = move |_| {
        app_state.write().config.default_mount_prefix = None;
        if let Err(e) = app_state.read().save() {
            tracing::error!("Failed to save config: {}", e);
        }
    };

    // Handle debug logging toggle
    let handle_debug_toggle = move |_| {
        let new_value = !app_state.read().config.debug_logging;
        app_state.write().config.debug_logging = new_value;

        // Update tracing level at runtime
        if new_value {
            tracing::info!("Debug logging enabled");
        } else {
            tracing::info!("Debug logging disabled");
        }

        if let Err(e) = app_state.read().save() {
            tracing::error!("Failed to save config: {}", e);
        }
    };

    rsx! {
        // Default Backend Section
        div {
            style: "margin-bottom: 24px;",

            h3 {
                style: "margin: 0 0 8px 0; font-size: 14px; font-weight: 600; color: #333;",
                "Default Mount Backend"
            }
            p {
                style: "margin: 0 0 12px 0; font-size: 13px; color: #666;",
                "Choose the filesystem backend used when mounting new vaults."
            }

            select {
                style: "
                    width: 100%;
                    padding: 10px 12px;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    font-size: 14px;
                    background: white;
                    cursor: pointer;
                    outline: none;
                ",
                value: "{config.default_backend:?}",
                onchange: handle_backend_change,

                for backend in BackendType::all() {
                    option {
                        value: "{backend:?}",
                        selected: config.default_backend == *backend,
                        "{backend.display_name()} - {backend.description()}"
                    }
                }
            }
        }

        // Default Mount Location Section
        div {
            style: "margin-bottom: 24px;",

            h3 {
                style: "margin: 0 0 8px 0; font-size: 14px; font-weight: 600; color: #333;",
                "Default Mount Location"
            }
            p {
                style: "margin: 0 0 12px 0; font-size: 13px; color: #666;",
                "Choose where vaults are mounted by default. Leave empty for system default."
            }

            div {
                style: "display: flex; gap: 8px;",

                // Path display
                {
                    let text_color = if config.default_mount_prefix.is_some() { "#333" } else { "#999" };
                    let display_text = config.default_mount_prefix
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "System default".to_string());
                    rsx! {
                        div {
                            style: "
                                flex: 1;
                                padding: 10px 12px;
                                border: 1px solid #ddd;
                                border-radius: 6px;
                                font-size: 14px;
                                color: {text_color};
                                background: #f9f9f9;
                                overflow: hidden;
                                text-overflow: ellipsis;
                                white-space: nowrap;
                            ",
                            "{display_text}"
                        }
                    }
                }

                // Browse button
                button {
                    style: "
                        padding: 10px 16px;
                        background: #f5f5f5;
                        color: #333;
                        border: 1px solid #ddd;
                        border-radius: 6px;
                        font-size: 14px;
                        cursor: pointer;
                    ",
                    onclick: handle_browse_mount_prefix,
                    "Browse"
                }

                // Clear button (only show if set)
                if config.default_mount_prefix.is_some() {
                    button {
                        style: "
                            padding: 10px 12px;
                            background: transparent;
                            color: #666;
                            border: 1px solid #ddd;
                            border-radius: 6px;
                            font-size: 14px;
                            cursor: pointer;
                        ",
                        onclick: handle_clear_mount_prefix,
                        title: "Reset to system default",
                        "×"
                    }
                }
            }
        }

        // Debug Logging Section
        div {
            style: "margin-bottom: 24px;",

            h3 {
                style: "margin: 0 0 8px 0; font-size: 14px; font-weight: 600; color: #333;",
                "Debug Logging"
            }

            label {
                style: "
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    cursor: pointer;
                    font-size: 14px;
                    color: #333;
                ",

                input {
                    r#type: "checkbox",
                    style: "
                        width: 18px;
                        height: 18px;
                        cursor: pointer;
                    ",
                    checked: config.debug_logging,
                    onchange: handle_debug_toggle,
                }

                span { "Enable verbose debug logging" }
            }

            p {
                style: "margin: 8px 0 0 28px; font-size: 12px; color: #999;",
                "Useful for troubleshooting issues. Increases log output significantly."
            }
        }
    }
}

// ============================================================================
// About Tab
// ============================================================================

#[component]
fn AboutTab() -> Element {
    let version = env!("CARGO_PKG_VERSION");
    let repo_url = "https://github.com/agucova/oxidized-cryptolib";
    let docs_url = "https://github.com/agucova/oxidized-cryptolib#readme";

    rsx! {
        div {
            style: "text-align: center;",

            // App icon/logo placeholder
            div {
                style: "font-size: 64px; margin-bottom: 16px;",
                "🔐"
            }

            // App name
            h2 {
                style: "margin: 0 0 4px 0; font-size: 24px; font-weight: 600; color: #1a1a1a;",
                "Oxidized Vault"
            }

            // Version
            p {
                style: "margin: 0 0 24px 0; font-size: 14px; color: #666;",
                "Version {version}"
            }

            // Description
            p {
                style: "margin: 0 0 24px 0; font-size: 14px; color: #555; line-height: 1.6;",
                "A fast, secure Cryptomator vault manager written in Rust. "
                "Open source under the MIT license."
            }

            // Links
            div {
                style: "display: flex; flex-direction: column; gap: 12px; align-items: center;",

                LinkButton {
                    label: "View on GitHub",
                    url: repo_url,
                }

                LinkButton {
                    label: "Documentation",
                    url: docs_url,
                }
            }

            // Copyright
            p {
                style: "margin: 32px 0 0 0; font-size: 12px; color: #999;",
                "MIT License"
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct LinkButtonProps {
    label: &'static str,
    url: &'static str,
}

#[component]
fn LinkButton(props: LinkButtonProps) -> Element {
    let url = props.url;

    rsx! {
        button {
            style: "
                padding: 10px 24px;
                background: transparent;
                color: #2196f3;
                border: 1px solid #2196f3;
                border-radius: 6px;
                font-size: 14px;
                cursor: pointer;
                min-width: 180px;
            ",
            onclick: move |_| {
                let _ = open::that(url);
            },
            "{props.label}"
        }
    }
}
