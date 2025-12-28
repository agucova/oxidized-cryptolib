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
            style: "
                position: fixed;
                inset: 0;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000;
            ",
            onclick: move |_| props.on_dismiss.call(()),

            // Dialog
            div {
                style: "
                    background: white;
                    border-radius: 16px;
                    padding: 32px;
                    width: 500px;
                    max-width: 90vw;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
                ",
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

        // CSS animations
        style { "
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.5; }}
            }}
        " }
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
            style: "text-align: center; margin-bottom: 24px;",
            div {
                style: "font-size: 48px; margin-bottom: 16px;",
                "🔧"
            }
            h2 {
                style: "margin: 0 0 8px 0; font-size: 24px; font-weight: 600; color: #1a1a1a;",
                "FSKit Setup Required"
            }
            p {
                style: "margin: 0; font-size: 14px; color: #666;",
                "FSKitBridge is needed for native vault mounting on macOS 15.4+"
            }
        }

        // Benefits list
        div {
            style: "
                background: #f8f9fa;
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 24px;
            ",
            h3 {
                style: "margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: #333;",
                "Why FSKit?"
            }
            ul {
                style: "margin: 0; padding-left: 20px; font-size: 13px; color: #555; line-height: 1.8;",
                li { "No kernel extensions required (unlike macFUSE)" }
                li { "Better system integration and stability" }
                li { "Survives sleep/wake cycles reliably" }
                li { "Native Apple framework" }
            }
        }

        // Buttons
        div {
            style: "display: flex; flex-direction: column; gap: 12px;",

            button {
                style: "
                    width: 100%;
                    padding: 14px 24px;
                    background: #007aff;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 500;
                    cursor: pointer;
                ",
                onclick: move |_| props.on_start.call(()),
                "Install FSKitBridge Automatically"
            }

            button {
                style: "
                    width: 100%;
                    padding: 12px 24px;
                    background: transparent;
                    color: #007aff;
                    border: 1px solid #007aff;
                    border-radius: 8px;
                    font-size: 14px;
                    cursor: pointer;
                ",
                onclick: move |_| props.on_manual.call(()),
                "Download Manually from GitHub"
            }

            button {
                style: "
                    width: 100%;
                    padding: 12px 24px;
                    background: transparent;
                    color: #666;
                    border: none;
                    font-size: 14px;
                    cursor: pointer;
                ",
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
            style: "text-align: center;",

            // Spinner
            div {
                style: "
                    width: 64px;
                    height: 64px;
                    margin: 0 auto 24px;
                    border: 4px solid #e0e0e0;
                    border-top-color: #007aff;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                ",
            }

            h2 {
                style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                "Downloading FSKitBridge..."
            }

            p {
                style: "margin: 0; font-size: 14px; color: #666;",
                "Please wait while we download from GitHub..."
            }
        }
    }
}

#[component]
fn StepInstalling() -> Element {
    rsx! {
        div {
            style: "text-align: center;",

            div {
                style: "
                    width: 64px;
                    height: 64px;
                    margin: 0 auto 24px;
                    border: 4px solid #e0e0e0;
                    border-top-color: #007aff;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                ",
            }

            h2 {
                style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                "Installing..."
            }

            p {
                style: "margin: 0; font-size: 14px; color: #666;",
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
            style: "text-align: center; margin-bottom: 24px;",
            div {
                style: "font-size: 48px; margin-bottom: 16px;",
                "🛡️"
            }
            h2 {
                style: "margin: 0 0 8px 0; font-size: 24px; font-weight: 600; color: #1a1a1a;",
                "Security Approval Needed"
            }
            p {
                style: "margin: 0; font-size: 14px; color: #666;",
                "FSKitBridge was downloaded from the internet and needs approval"
            }
        }

        div {
            style: "
                background: #fff3cd;
                border: 1px solid #ffc107;
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 24px;
                font-size: 13px;
                color: #856404;
            ",
            "macOS quarantines downloaded apps for security. We need to remove this to allow FSKitBridge to run."
        }

        div {
            style: "display: flex; gap: 12px;",

            button {
                style: "
                    flex: 1;
                    padding: 12px 24px;
                    background: #f5f5f5;
                    color: #333;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    cursor: pointer;
                ",
                onclick: move |_| props.on_skip.call(()),
                "Skip"
            }

            button {
                style: "
                    flex: 1;
                    padding: 12px 24px;
                    background: #007aff;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                ",
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
            style: "text-align: center; margin-bottom: 24px;",
            div {
                style: "font-size: 48px; margin-bottom: 16px;",
                "⚙️"
            }
            h2 {
                style: "margin: 0 0 8px 0; font-size: 24px; font-weight: 600; color: #1a1a1a;",
                "Enable FSKit Extension"
            }
            p {
                style: "margin: 0; font-size: 14px; color: #666;",
                "One more step - enable the extension in System Settings"
            }
        }

        // Instructions
        div {
            style: "
                background: #f8f9fa;
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 24px;
            ",
            ol {
                style: "margin: 0; padding-left: 20px; font-size: 13px; color: #555; line-height: 2;",
                li { "Open " strong { "System Settings" } }
                li { "Go to " strong { "General" } " → " strong { "Login Items & Extensions" } }
                li { "Scroll to " strong { "File System Extensions" } }
                li { "Enable " strong { "FSKitBridge" } }
            }
        }

        div {
            style: "display: flex; flex-direction: column; gap: 12px;",

            button {
                style: "
                    width: 100%;
                    padding: 14px 24px;
                    background: #007aff;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 500;
                    cursor: pointer;
                ",
                onclick: move |_| props.on_open_settings.call(()),
                "Open System Settings"
            }

            button {
                style: "
                    width: 100%;
                    padding: 12px 24px;
                    background: #28a745;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    cursor: pointer;
                ",
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
            style: "text-align: center;",

            div {
                style: "
                    width: 64px;
                    height: 64px;
                    margin: 0 auto 24px;
                    border: 4px solid #e0e0e0;
                    border-top-color: #28a745;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                ",
            }

            h2 {
                style: "margin: 0 0 8px 0; font-size: 20px; font-weight: 600; color: #1a1a1a;",
                "Verifying..."
            }

            p {
                style: "margin: 0; font-size: 14px; color: #666;",
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
            style: "text-align: center; margin-bottom: 24px;",
            div {
                style: "font-size: 64px; margin-bottom: 16px;",
                "✅"
            }
            h2 {
                style: "margin: 0 0 8px 0; font-size: 24px; font-weight: 600; color: #28a745;",
                "FSKit Ready!"
            }
            p {
                style: "margin: 0; font-size: 14px; color: #666;",
                "FSKitBridge is installed and working. You can now mount vaults using FSKit."
            }
        }

        button {
            style: "
                width: 100%;
                padding: 14px 24px;
                background: #28a745;
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 500;
                cursor: pointer;
            ",
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
            style: "text-align: center; margin-bottom: 24px;",
            div {
                style: "font-size: 64px; margin-bottom: 16px;",
                "❌"
            }
            h2 {
                style: "margin: 0 0 8px 0; font-size: 24px; font-weight: 600; color: #dc3545;",
                "Setup Failed"
            }
            p {
                style: "margin: 0; font-size: 14px; color: #666;",
                "{props.message}"
            }
        }

        div {
            style: "display: flex; gap: 12px;",

            button {
                style: "
                    flex: 1;
                    padding: 12px 24px;
                    background: #f5f5f5;
                    color: #333;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    cursor: pointer;
                ",
                onclick: move |_| props.on_dismiss.call(()),
                "Dismiss"
            }

            button {
                style: "
                    flex: 1;
                    padding: 12px 24px;
                    background: #007aff;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                ",
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
