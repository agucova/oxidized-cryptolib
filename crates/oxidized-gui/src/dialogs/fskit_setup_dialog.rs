//! FSKitBridge setup wizard dialog
//!
//! This dialog guides users through installing and configuring FSKitBridge.app
//! for FSKit-based vault mounting on macOS 15.4+.

use dioxus::prelude::*;
use std::time::Duration;

#[cfg(all(target_os = "macos", feature = "fskit"))]
use oxidized_fskit::setup::{
    self, BridgeStatus, DownloadProgress, RELEASES_URL,
};

/// Wizard step in the setup process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    /// Introduction explaining what FSKitBridge is
    Introduction,
    /// Downloading FSKitBridge from GitHub
    Downloading,
    /// Installing to ~/Applications
    Installing,
    /// Prompting user to remove quarantine (if needed)
    RemoveQuarantine,
    /// Prompting user to enable extension in System Settings
    EnableExtension,
    /// Verifying the bridge is responding
    Verifying,
    /// Setup complete
    Complete,
    /// An error occurred
    Error,
}

/// Props for the FSKit setup dialog
#[derive(Props, Clone, PartialEq)]
pub struct FSKitSetupDialogProps {
    /// Initial status from startup check
    #[props(default)]
    pub initial_status: Option<String>,
    /// Called when setup completes successfully
    pub on_complete: EventHandler<()>,
    /// Called when dialog is dismissed
    pub on_dismiss: EventHandler<()>,
}

/// FSKit setup wizard dialog
#[component]
pub fn FSKitSetupDialog(props: FSKitSetupDialogProps) -> Element {
    let mut step = use_signal(|| SetupStep::Introduction);
    let progress = use_signal(|| 0.0f32);
    let mut error_msg = use_signal(|| None::<String>);

    // Determine initial step based on status
    #[cfg(all(target_os = "macos", feature = "fskit"))]
    use_effect(move || {
        spawn(async move {
            let status = setup::get_status().await;
            let initial_step = match status {
                BridgeStatus::Ready => SetupStep::Complete,
                BridgeStatus::NotInstalled => SetupStep::Introduction,
                BridgeStatus::Quarantined => SetupStep::RemoveQuarantine,
                BridgeStatus::ExtensionDisabled => SetupStep::EnableExtension,
                BridgeStatus::UnsupportedPlatform => {
                    error_msg.set(Some("FSKit requires macOS 15.4 or later".to_string()));
                    SetupStep::Error
                }
            };
            step.set(initial_step);
        });
    });

    // Render based on current step
    rsx! {
        // Backdrop
        div {
            class: "dialog-backdrop",
            onclick: move |_| props.on_dismiss.call(()),

            // Dialog
            div {
                class: "dialog w-[500px] max-w-[90vw] p-8",
                onclick: move |e| e.stop_propagation(),

                match step() {
                    SetupStep::Introduction => rsx! {
                        StepIntroduction {
                            on_start: move |_| {
                                step.set(SetupStep::Downloading);
                                #[cfg(all(target_os = "macos", feature = "fskit"))]
                                spawn(async move {
                                    start_download(step, progress, error_msg).await;
                                });
                            },
                            on_manual: move |_| {
                                let _ = open::that(RELEASES_URL);
                            },
                            on_dismiss: move |_| props.on_dismiss.call(()),
                        }
                    },
                    SetupStep::Downloading => rsx! {
                        StepDownloading {}
                    },
                    SetupStep::Installing => rsx! {
                        StepInstalling {}
                    },
                    SetupStep::RemoveQuarantine => rsx! {
                        StepRemoveQuarantine {
                            on_remove: move |_| {
                                #[cfg(all(target_os = "macos", feature = "fskit"))]
                                {
                                    if let Some(path) = setup::find_installation() {
                                        let _ = setup::remove_quarantine(&path);
                                    }
                                    step.set(SetupStep::EnableExtension);
                                }
                            },
                            on_skip: move |_| step.set(SetupStep::EnableExtension),
                        }
                    },
                    SetupStep::EnableExtension => rsx! {
                        StepEnableExtension {
                            on_open_settings: move |_| {
                                #[cfg(all(target_os = "macos", feature = "fskit"))]
                                {
                                    let _ = setup::open_system_settings_extensions();
                                }
                            },
                            on_verify: move |_| {
                                step.set(SetupStep::Verifying);
                                #[cfg(all(target_os = "macos", feature = "fskit"))]
                                spawn(async move {
                                    verify_connection(step, error_msg, props.on_complete.clone()).await;
                                });
                            },
                        }
                    },
                    SetupStep::Verifying => rsx! {
                        StepVerifying {}
                    },
                    SetupStep::Complete => rsx! {
                        StepComplete {
                            on_close: move |_| props.on_complete.call(()),
                        }
                    },
                    SetupStep::Error => rsx! {
                        StepError {
                            message: error_msg().unwrap_or_else(|| "Unknown error".to_string()),
                            on_retry: move |_| step.set(SetupStep::Introduction),
                            on_dismiss: move |_| props.on_dismiss.call(()),
                        }
                    },
                }
            }
        }
    }
}

// ============================================================================
// Step Components
// ============================================================================

#[derive(Props, Clone, PartialEq)]
struct StepIntroductionProps {
    on_start: EventHandler<()>,
    on_manual: EventHandler<()>,
    on_dismiss: EventHandler<()>,
}

#[component]
fn StepIntroduction(props: StepIntroductionProps) -> Element {
    rsx! {
        // Header
        div {
            class: "text-center mb-6",
            div {
                class: "text-5xl mb-4",
                "🔧"
            }
            h2 {
                class: "mb-2 text-2xl font-semibold text-gray-900 dark:text-gray-100",
                "FSKit Setup Required"
            }
            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "FSKitBridge is needed for native vault mounting on macOS 15.4+"
            }
        }

        // Benefits list
        div {
            class: "bg-gray-50 dark:bg-neutral-800 rounded-lg p-4 mb-6",
            h3 {
                class: "mb-3 text-sm font-semibold text-gray-900 dark:text-gray-100",
                "Why FSKit?"
            }
            ul {
                class: "pl-5 text-sm text-gray-600 dark:text-gray-400 leading-relaxed list-disc",
                li { "No kernel extensions required (unlike macFUSE)" }
                li { "Better system integration and stability" }
                li { "Survives sleep/wake cycles reliably" }
                li { "Native Apple framework" }
            }
        }

        // Buttons
        div {
            class: "flex flex-col gap-3",

            button {
                class: "btn-primary w-full py-3.5 text-base",
                onclick: move |_| props.on_start.call(()),
                "Install FSKitBridge Automatically"
            }

            button {
                class: "w-full py-3 px-6 bg-transparent text-blue-500 dark:text-blue-400 border border-blue-500 dark:border-blue-400 rounded-lg text-sm cursor-pointer hover:bg-blue-50 dark:hover:bg-blue-900/20",
                onclick: move |_| props.on_manual.call(()),
                "Download Manually from GitHub"
            }

            button {
                class: "btn-ghost w-full",
                onclick: move |_| props.on_dismiss.call(()),
                "Skip for Now"
            }
        }
    }
}

#[component]
fn StepDownloading() -> Element {
    rsx! {
        div {
            class: "text-center",

            // Spinner
            div {
                class: "w-16 h-16 mx-auto mb-6 border-4 border-gray-200 dark:border-neutral-600 border-t-blue-500 rounded-full animate-spin",
            }

            h2 {
                class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                "Downloading FSKitBridge..."
            }

            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "Please wait while we download from GitHub..."
            }
        }
    }
}

#[component]
fn StepInstalling() -> Element {
    rsx! {
        div {
            class: "text-center",

            div {
                class: "w-16 h-16 mx-auto mb-6 border-4 border-gray-200 dark:border-neutral-600 border-t-blue-500 rounded-full animate-spin",
            }

            h2 {
                class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                "Installing..."
            }

            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "Copying FSKitBridge.app to ~/Applications"
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct StepRemoveQuarantineProps {
    on_remove: EventHandler<()>,
    on_skip: EventHandler<()>,
}

#[component]
fn StepRemoveQuarantine(props: StepRemoveQuarantineProps) -> Element {
    rsx! {
        div {
            class: "text-center mb-6",
            div {
                class: "text-5xl mb-4",
                "🛡️"
            }
            h2 {
                class: "mb-2 text-2xl font-semibold text-gray-900 dark:text-gray-100",
                "Security Approval Needed"
            }
            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "FSKitBridge was downloaded from the internet and needs approval"
            }
        }

        div {
            class: "alert-warning mb-6",
            "macOS quarantines downloaded apps for security. We need to remove this to allow FSKitBridge to run."
        }

        div {
            class: "flex gap-3",

            button {
                class: "btn-secondary flex-1",
                onclick: move |_| props.on_skip.call(()),
                "Skip"
            }

            button {
                class: "btn-primary flex-1",
                onclick: move |_| props.on_remove.call(()),
                "Remove Quarantine"
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct StepEnableExtensionProps {
    on_open_settings: EventHandler<()>,
    on_verify: EventHandler<()>,
}

#[component]
fn StepEnableExtension(props: StepEnableExtensionProps) -> Element {
    rsx! {
        div {
            class: "text-center mb-6",
            div {
                class: "text-5xl mb-4",
                "⚙️"
            }
            h2 {
                class: "mb-2 text-2xl font-semibold text-gray-900 dark:text-gray-100",
                "Enable FSKit Extension"
            }
            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "One more step - enable the extension in System Settings"
            }
        }

        // Instructions
        div {
            class: "bg-gray-50 dark:bg-neutral-800 rounded-lg p-4 mb-6",
            ol {
                class: "pl-5 text-sm text-gray-600 dark:text-gray-400 leading-loose list-decimal",
                li { "Open " strong { class: "text-gray-900 dark:text-gray-100", "System Settings" } }
                li { "Go to " strong { class: "text-gray-900 dark:text-gray-100", "General" } " → " strong { class: "text-gray-900 dark:text-gray-100", "Login Items & Extensions" } }
                li { "Scroll to " strong { class: "text-gray-900 dark:text-gray-100", "File System Extensions" } }
                li { "Enable " strong { class: "text-gray-900 dark:text-gray-100", "FSKitBridge" } }
            }
        }

        div {
            class: "flex flex-col gap-3",

            button {
                class: "btn-primary w-full py-3.5 text-base",
                onclick: move |_| props.on_open_settings.call(()),
                "Open System Settings"
            }

            button {
                class: "btn-success w-full",
                onclick: move |_| props.on_verify.call(()),
                "I've Enabled It - Verify"
            }
        }
    }
}

#[component]
fn StepVerifying() -> Element {
    rsx! {
        div {
            class: "text-center",

            div {
                class: "w-16 h-16 mx-auto mb-6 border-4 border-gray-200 dark:border-neutral-600 border-t-green-500 rounded-full animate-spin",
            }

            h2 {
                class: "mb-2 text-xl font-semibold text-gray-900 dark:text-gray-100",
                "Verifying..."
            }

            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "Checking if FSKitBridge is responding"
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct StepCompleteProps {
    on_close: EventHandler<()>,
}

#[component]
fn StepComplete(props: StepCompleteProps) -> Element {
    rsx! {
        div {
            class: "text-center mb-6",
            div {
                class: "text-6xl mb-4",
                "✅"
            }
            h2 {
                class: "mb-2 text-2xl font-semibold text-green-600 dark:text-green-400",
                "FSKit Ready!"
            }
            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "FSKitBridge is installed and working. You can now mount vaults using FSKit."
            }
        }

        button {
            class: "btn-success w-full py-3.5 text-base",
            onclick: move |_| props.on_close.call(()),
            "Done"
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct StepErrorProps {
    message: String,
    on_retry: EventHandler<()>,
    on_dismiss: EventHandler<()>,
}

#[component]
fn StepError(props: StepErrorProps) -> Element {
    rsx! {
        div {
            class: "text-center mb-6",
            div {
                class: "text-6xl mb-4",
                "❌"
            }
            h2 {
                class: "mb-2 text-2xl font-semibold text-red-600 dark:text-red-400",
                "Setup Failed"
            }
            p {
                class: "text-sm text-gray-600 dark:text-gray-400",
                "{props.message}"
            }
        }

        div {
            class: "flex gap-3",

            button {
                class: "btn-secondary flex-1",
                onclick: move |_| props.on_dismiss.call(()),
                "Dismiss"
            }

            button {
                class: "btn-primary flex-1",
                onclick: move |_| props.on_retry.call(()),
                "Try Again"
            }
        }
    }
}

// ============================================================================
// Async Handlers
// ============================================================================

#[cfg(all(target_os = "macos", feature = "fskit"))]
async fn start_download(
    mut step: Signal<SetupStep>,
    _progress: Signal<f32>,
    mut error_msg: Signal<Option<String>>,
) {
    // Note: We don't use real-time progress updates because Dioxus signals
    // aren't thread-safe and download_latest requires a Send closure.
    // Instead we show an indeterminate spinner.
    match setup::download_latest(|_p: DownloadProgress| {
        // Progress updates happen on a different thread, can't update signal here
    }).await {
        Ok(app_path) => {
            step.set(SetupStep::Installing);

            // Install to ~/Applications
            if let Some(apps_dir) = dirs::home_dir().map(|h| h.join("Applications")) {
                match setup::install_to(&app_path, &apps_dir).await {
                    Ok(installed_path) => {
                        // Check if quarantined
                        if setup::is_quarantined(&installed_path) {
                            step.set(SetupStep::RemoveQuarantine);
                        } else {
                            // Launch the app to register the extension
                            let _ = setup::launch_bridge();
                            step.set(SetupStep::EnableExtension);
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Installation failed: {}", e)));
                        step.set(SetupStep::Error);
                    }
                }
            } else {
                error_msg.set(Some("Could not find home directory".to_string()));
                step.set(SetupStep::Error);
            }
        }
        Err(e) => {
            error_msg.set(Some(format!("Download failed: {}", e)));
            step.set(SetupStep::Error);
        }
    }
}

#[cfg(all(target_os = "macos", feature = "fskit"))]
async fn verify_connection(
    mut step: Signal<SetupStep>,
    mut error_msg: Signal<Option<String>>,
    on_complete: EventHandler<()>,
) {
    // Launch bridge if not already running
    let _ = setup::launch_bridge();

    // Try connecting with retries
    for i in 0..15 {
        tokio::time::sleep(Duration::from_secs(1)).await;

        if setup::check_bridge_connection().await {
            step.set(SetupStep::Complete);
            return;
        }

        // After 5 seconds, suggest re-checking settings
        if i == 5 {
            tracing::info!("FSKitBridge not responding after 5s, still waiting...");
        }
    }

    error_msg.set(Some(
        "FSKitBridge is not responding. Make sure the extension is enabled in System Settings.".to_string()
    ));
    step.set(SetupStep::Error);
}

// Fallback for non-macOS
#[cfg(not(all(target_os = "macos", feature = "fskit")))]
const RELEASES_URL: &str = "https://github.com/debox-network/FSKitBridge/releases";
