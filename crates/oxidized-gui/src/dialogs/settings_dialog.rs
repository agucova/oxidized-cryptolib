//! Settings dialog with tabbed interface
//!
//! Provides application-wide settings for mount backends, default paths,
//! and debugging options.

use dioxus::prelude::*;

use crate::state::{use_app_state, BackendType, ThemePreference};

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
            class: "dialog-backdrop",
            onclick: move |_| props.on_close.call(()),

            // Dialog
            div {
                class: "dialog w-[500px] max-h-[80vh] flex flex-col",
                onclick: move |e| e.stop_propagation(),

                // Header with tabs
                div {
                    class: "border-b border-gray-200 dark:border-neutral-700 pt-4 px-6 pb-0",

                    // Title
                    h2 {
                        class: "mb-4 text-xl font-semibold text-gray-900 dark:text-gray-100",
                        "Settings"
                    }

                    // Tab bar
                    div {
                        class: "tabs",

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
                    class: "flex-1 p-6 overflow-y-auto",

                    match active_tab() {
                        SettingsTab::General => rsx! { GeneralTab {} },
                        SettingsTab::About => rsx! { AboutTab {} },
                    }
                }

                // Footer with close button
                div {
                    class: "dialog-footer",

                    button {
                        class: "btn-primary",
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
    let tab_class = if props.is_active { "tab active" } else { "tab" };

    rsx! {
        button {
            class: tab_class,
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
        // Theme Section
        div {
            class: "mb-6",

            h3 {
                class: "mb-2 text-sm font-semibold text-gray-900 dark:text-gray-100",
                "Appearance"
            }
            p {
                class: "mb-3 text-sm text-gray-600 dark:text-gray-400",
                "Choose how the application looks."
            }

            // Theme toggle buttons
            div {
                class: "flex gap-2",

                for theme in ThemePreference::all() {
                    {
                        let is_selected = config.theme == *theme;
                        let button_class = if is_selected {
                            "flex-1 px-3 py-2.5 border-2 border-blue-500 bg-blue-50 dark:bg-blue-900/30 rounded-lg text-sm cursor-pointer text-blue-700 dark:text-blue-300 font-medium transition-colors"
                        } else {
                            "flex-1 px-3 py-2.5 border border-gray-300 dark:border-neutral-600 bg-white dark:bg-neutral-800 rounded-lg text-sm cursor-pointer text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-neutral-700 transition-colors"
                        };
                        let theme_value = format!("{:?}", theme);
                        rsx! {
                            button {
                                key: "{theme_value}",
                                class: "{button_class}",
                                onclick: move |_| {
                                    app_state.write().config.theme = *theme;
                                    if let Err(e) = app_state.read().save() {
                                        tracing::error!("Failed to save config: {}", e);
                                    }
                                },

                                div {
                                    class: "flex flex-col items-center gap-1",
                                    span {
                                        class: "text-lg",
                                        match theme {
                                            ThemePreference::System => "💻",
                                            ThemePreference::Light => "☀️",
                                            ThemePreference::Dark => "🌙",
                                        }
                                    }
                                    span { "{theme.display_name()}" }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Default Backend Section
        BackendSelector {
            current_backend: config.default_backend,
            on_change: move |backend| {
                app_state.write().config.default_backend = backend;
                if let Err(e) = app_state.read().save() {
                    tracing::error!("Failed to save config: {}", e);
                }
            },
        }

        // Default Mount Location Section
        div {
            class: "mb-6",

            h3 {
                class: "mb-2 text-sm font-semibold text-gray-900 dark:text-gray-100",
                "Default Mount Location"
            }
            p {
                class: "mb-3 text-sm text-gray-600 dark:text-gray-400",
                "Choose where vaults are mounted by default. Leave empty for system default."
            }

            div {
                class: "flex gap-2",

                // Path display
                {
                    let text_class = if config.default_mount_prefix.is_some() {
                        "flex-1 px-3 py-2.5 border border-gray-300 dark:border-neutral-600 rounded-lg text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-neutral-700 overflow-hidden text-ellipsis whitespace-nowrap"
                    } else {
                        "flex-1 px-3 py-2.5 border border-gray-300 dark:border-neutral-600 rounded-lg text-sm text-gray-500 bg-gray-50 dark:bg-neutral-700 overflow-hidden text-ellipsis whitespace-nowrap"
                    };
                    let display_text = config.default_mount_prefix
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "System default".to_string());
                    rsx! {
                        div {
                            class: "{text_class}",
                            "{display_text}"
                        }
                    }
                }

                // Browse button
                button {
                    class: "btn-secondary",
                    onclick: handle_browse_mount_prefix,
                    "Browse"
                }

                // Clear button (only show if set)
                if config.default_mount_prefix.is_some() {
                    button {
                        class: "px-3 py-2.5 bg-transparent text-gray-600 dark:text-gray-400 border border-gray-300 dark:border-neutral-600 rounded-lg text-sm cursor-pointer hover:bg-gray-100 dark:hover:bg-neutral-700",
                        onclick: handle_clear_mount_prefix,
                        title: "Reset to system default",
                        "×"
                    }
                }
            }
        }

        // Debug Logging Section
        div {
            class: "mb-6",

            h3 {
                class: "mb-2 text-sm font-semibold text-gray-900 dark:text-gray-100",
                "Debug Logging"
            }

            label {
                class: "flex items-center gap-2.5 cursor-pointer text-sm text-gray-900 dark:text-gray-100",

                input {
                    r#type: "checkbox",
                    class: "w-4 h-4 cursor-pointer accent-blue-500",
                    checked: config.debug_logging,
                    onchange: handle_debug_toggle,
                }

                span { "Enable verbose debug logging" }
            }

            p {
                class: "mt-2 ml-7 text-xs text-gray-500",
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
            class: "text-center",

            // App icon/logo placeholder
            div {
                class: "text-6xl mb-4",
                "🔐"
            }

            // App name
            h2 {
                class: "mb-1 text-2xl font-semibold text-gray-900 dark:text-gray-100",
                "Oxidized Vault"
            }

            // Version
            p {
                class: "mb-6 text-sm text-gray-600 dark:text-gray-400",
                "Version {version}"
            }

            // Description
            p {
                class: "mb-6 text-sm text-gray-700 dark:text-gray-300 leading-relaxed",
                "A fast, secure Cryptomator vault manager written in Rust. "
                "Open source under the MIT license."
            }

            // Links
            div {
                class: "flex flex-col gap-3 items-center",

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
                class: "mt-8 text-xs text-gray-500",
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
            class: "px-6 py-2.5 bg-transparent text-blue-500 dark:text-blue-400 border border-blue-500 dark:border-blue-400 rounded-lg text-sm cursor-pointer min-w-[180px] hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors",
            onclick: move |_| {
                let _ = open::that(url);
            },
            "{props.label}"
        }
    }
}

// ============================================================================
// Backend Selector Component
// ============================================================================

#[derive(Props, Clone, PartialEq)]
struct BackendSelectorProps {
    current_backend: BackendType,
    on_change: EventHandler<BackendType>,
}

/// Custom styled dropdown for selecting mount backend
#[component]
fn BackendSelector(props: BackendSelectorProps) -> Element {
    let mut is_open = use_signal(|| false);

    rsx! {
        div {
            class: "mb-6",

            h3 {
                class: "mb-2 text-sm font-semibold text-gray-900 dark:text-gray-100",
                "Default Mount Backend"
            }
            p {
                class: "mb-3 text-sm text-gray-600 dark:text-gray-400",
                "Choose the filesystem backend used when mounting new vaults."
            }

            // Custom dropdown
            div {
                class: "relative",

                // Dropdown button
                button {
                    class: "w-full px-3 py-2.5 border border-gray-300 dark:border-neutral-600 rounded-lg text-sm text-left text-gray-900 dark:text-gray-100 bg-white dark:bg-neutral-800 cursor-pointer outline-none hover:border-gray-400 dark:hover:border-neutral-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors flex items-center justify-between",
                    onclick: move |_| is_open.set(!is_open()),

                    span {
                        class: "flex-1",
                        "{props.current_backend.display_name()}"
                    }
                    span {
                        class: "text-gray-400 dark:text-gray-500 ml-2 transition-transform",
                        style: if is_open() { "transform: rotate(180deg)" } else { "" },
                        "▼"
                    }
                }

                // Dropdown menu
                if is_open() {
                    // Click-away overlay
                    div {
                        class: "fixed inset-0 z-40",
                        onclick: move |_| is_open.set(false),
                    }

                    // Options list
                    div {
                        class: "absolute z-50 mt-1 w-full bg-white dark:bg-neutral-800 border border-gray-200 dark:border-neutral-600 rounded-lg shadow-lg overflow-hidden",

                        for backend in BackendType::all() {
                            {
                                let is_selected = props.current_backend == *backend;
                                let item_class = if is_selected {
                                    "w-full px-3 py-2.5 text-left text-sm cursor-pointer bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-none"
                                } else {
                                    "w-full px-3 py-2.5 text-left text-sm cursor-pointer bg-transparent text-gray-900 dark:text-gray-100 hover:bg-gray-50 dark:hover:bg-neutral-700 border-none"
                                };
                                rsx! {
                                    button {
                                        key: "{backend:?}",
                                        class: "{item_class}",
                                        onclick: move |_| {
                                            props.on_change.call(*backend);
                                            is_open.set(false);
                                        },

                                        div {
                                            class: "font-medium",
                                            "{backend.display_name()}"
                                        }
                                        div {
                                            class: "text-xs text-gray-500 dark:text-gray-400 mt-0.5",
                                            "{backend.description()}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
