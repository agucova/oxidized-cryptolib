//! Standalone Settings Window
//!
//! This is a separate window component that runs in its own VirtualDom.
//! It loads configuration from disk and saves changes directly.

use dioxus::prelude::*;

use crate::backend::{mount_manager, BackendInfo};
use crate::state::{AppConfig, BackendType, ThemePreference};

/// Active tab in the settings window
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsTab {
    #[default]
    General,
    About,
}

/// Standalone settings window component
///
/// This component manages its own state and persists changes to disk.
/// It's designed to run in a separate VirtualDom via `window.open_window()`.
#[component]
pub fn SettingsWindow() -> Element {
    // Load config from disk (this is a standalone window)
    let config = use_signal(AppConfig::load);
    let mut active_tab = use_signal(|| SettingsTab::General);

    // Get theme class for styling
    let theme_class = config.read().theme.css_class().unwrap_or("");
    let platform_class = crate::current_platform().css_class();

    rsx! {
        // Include Tailwind CSS
        document::Link { rel: "stylesheet", href: asset!("/assets/tailwind.css") }

        div {
            class: "settings-window {theme_class} {platform_class}",

            // Header with tabs
            div {
                class: "settings-header",

                // Title bar area (for window dragging on macOS)
                div {
                    class: "settings-titlebar",
                    h1 {
                        class: "text-lg font-semibold text-gray-900 dark:text-gray-100",
                        "Settings"
                    }
                }

                // Tab bar
                div {
                    class: "settings-tabs",

                    TabButton {
                        label: "General",
                        icon: "⚙️",
                        is_active: active_tab() == SettingsTab::General,
                        on_click: move |()| active_tab.set(SettingsTab::General),
                    }
                    TabButton {
                        label: "About",
                        icon: "ℹ️",
                        is_active: active_tab() == SettingsTab::About,
                        on_click: move |()| active_tab.set(SettingsTab::About),
                    }
                }
            }

            // Content area
            div {
                class: "settings-content",

                match active_tab() {
                    SettingsTab::General => rsx! {
                        GeneralTab { config }
                    },
                    SettingsTab::About => rsx! { AboutTab {} },
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
    let tab_class = if props.is_active {
        "settings-tab active"
    } else {
        "settings-tab"
    };

    rsx! {
        button {
            class: tab_class,
            onclick: move |_| { props.on_click.call(()) },
            span { class: "mr-1.5", "{props.icon}" }
            span { "{props.label}" }
        }
    }
}

// ============================================================================
// General Tab
// ============================================================================

#[derive(Props, Clone, PartialEq)]
struct GeneralTabProps {
    config: Signal<AppConfig>,
}

#[component]
fn GeneralTab(props: GeneralTabProps) -> Element {
    let mut config = props.config;

    // Save helper
    let save_config = move || {
        if let Err(e) = config.read().save() {
            tracing::error!("Failed to save config: {}", e);
        }
    };

    // Handle mount prefix browse
    let handle_browse_mount_prefix = move |_| {
        let mut config = config;
        spawn(async move {
            let folder = rfd::AsyncFileDialog::new()
                .set_title("Select Default Mount Location")
                .pick_folder()
                .await;

            if let Some(folder) = folder {
                let path = folder.path().to_path_buf();
                config.write().default_mount_prefix = Some(path);
                if let Err(e) = config.read().save() {
                    tracing::error!("Failed to save config: {}", e);
                }
            }
        });
    };

    // Handle clear mount prefix
    let handle_clear_mount_prefix = {
        let save = save_config;
        move |_| {
            config.write().default_mount_prefix = None;
            save();
        }
    };

    let current_config = config.read().clone();

    rsx! {
        // Theme Section
        div {
            class: "settings-section",

            h3 {
                class: "settings-section-title",
                "Appearance"
            }
            p {
                class: "settings-section-description",
                "Choose how the application looks."
            }

            // Theme toggle buttons
            div {
                class: "flex gap-2",

                for theme in ThemePreference::all() {
                    {
                        let is_selected = current_config.theme == *theme;
                        let button_class = if is_selected {
                            "settings-theme-btn selected"
                        } else {
                            "settings-theme-btn"
                        };
                        let theme_value = *theme;
                        let save = save_config;
                        rsx! {
                            button {
                                key: "{theme:?}",
                                class: "{button_class}",
                                onclick: move |_| {
                                    config.write().theme = theme_value;
                                    save();
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
        div {
            class: "settings-section",

            h3 {
                class: "settings-section-title",
                "Default Mount Backend"
            }
            p {
                class: "settings-section-description",
                "Choose the filesystem backend used when mounting new vaults."
            }

            BackendSelector {
                current_backend: current_config.default_backend,
                on_change: {
                    let save = save_config;
                    move |backend| {
                        config.write().default_backend = backend;
                        save();
                    }
                },
            }
        }

        // Default Mount Location Section
        div {
            class: "settings-section",

            h3 {
                class: "settings-section-title",
                "Default Mount Location"
            }
            p {
                class: "settings-section-description",
                "Choose where vaults are mounted by default. Leave empty for system default."
            }

            div {
                class: "flex gap-2",

                // Path display
                {
                    let text_class = if current_config.default_mount_prefix.is_some() {
                        "settings-path-display"
                    } else {
                        "settings-path-display placeholder"
                    };
                    let display_text = current_config.default_mount_prefix
                        .as_ref().map_or_else(|| "System default".to_string(), |p: &std::path::PathBuf| p.display().to_string());
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
                if current_config.default_mount_prefix.is_some() {
                    button {
                        class: "settings-clear-btn",
                        onclick: handle_clear_mount_prefix,
                        title: "Reset to system default",
                        "×"
                    }
                }
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
    let repo_url = "https://github.com/agucova/oxcrypt-core";
    let docs_url = "https://github.com/agucova/oxcrypt-core#readme";

    rsx! {
        div {
            class: "settings-about",

            // App name
            h2 {
                class: "text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-1",
                "Oxcrypt"
            }

            // Version
            p {
                class: "text-sm text-gray-600 dark:text-gray-400 mb-6",
                "Version {version}"
            }

            // Description
            p {
                class: "text-sm text-gray-700 dark:text-gray-300 leading-relaxed mb-6 max-w-xs",
                "A fast, secure Cryptomator vault manager written in Rust. "
                "Open source under the MPL-2.0 license."
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
            class: "settings-link-btn",
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

    // Get registered backends from mount manager (shows availability status)
    let manager = mount_manager();
    let backends: Vec<BackendInfo> = manager.backend_info();

    // Find the display name for current backend
    let current_display = backends
        .iter()
        .find(|b| b.backend_type == props.current_backend).map_or_else(|| props.current_backend.display_name(), |b| b.name.as_str());

    rsx! {
        div {
            class: "relative",

            // Dropdown button
            button {
                class: "settings-dropdown-btn",
                onclick: move |_| { is_open.set(!is_open())},

                span {
                    class: "flex-1",
                    "{current_display}"
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
                    onclick: move |_| { is_open.set(false) },
                }

                // Options list
                div {
                    class: "settings-dropdown-menu",

                    for backend in backends.iter() {
                        {
                            let is_selected = props.current_backend == backend.backend_type;
                            let is_available = backend.available;
                            let backend_type = backend.backend_type;

                            let item_class = if !is_available {
                                "settings-dropdown-item disabled"
                            } else if is_selected {
                                "settings-dropdown-item selected"
                            } else {
                                "settings-dropdown-item"
                            };

                            rsx! {
                                button {
                                    key: "{backend.id}",
                                    class: "{item_class}",
                                    disabled: !is_available,
                                    onclick: move |_| {
                                        if is_available {
                                            props.on_change.call(backend_type);
                                            is_open.set(false);
                                        }
                                    },

                                    div {
                                        class: "flex items-center justify-between",

                                        div {
                                            class: "font-medium",
                                            "{backend.name}"
                                        }

                                        // Availability badge
                                        if !is_available {
                                            span {
                                                class: "text-xs px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400",
                                                "Unavailable"
                                            }
                                        }
                                    }

                                    div {
                                        class: "text-xs text-gray-500 dark:text-gray-400 mt-0.5",
                                        "{backend.description}"
                                    }

                                    // Show reason if unavailable
                                    if let Some(reason) = &backend.unavailable_reason {
                                        if !is_available {
                                            div {
                                                class: "text-xs text-amber-600 dark:text-amber-400 mt-0.5 italic",
                                                "{reason}"
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
}
