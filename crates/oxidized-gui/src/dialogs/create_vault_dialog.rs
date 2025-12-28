//! Create new vault wizard dialog

use dioxus::prelude::*;
use std::path::PathBuf;

/// Wizard steps for creating a new vault
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    /// Step 1: Choose parent directory
    ChooseLocation,
    /// Step 2: Enter vault name
    EnterName,
    /// Step 3: Enter and confirm password
    CreatePassword,
    /// Step 4: Creating vault (progress)
    Creating,
}

/// State during vault creation
#[derive(Debug, Clone, PartialEq)]
pub enum CreationState {
    /// Waiting for user input
    Idle,
    /// Creating vault (show spinner)
    Creating,
    /// Vault created successfully
    Success(PathBuf),
    /// Creation failed
    Error(String),
}

/// Dialog for creating a new Cryptomator vault
#[component]
pub fn CreateVaultDialog(
    on_complete: EventHandler<PathBuf>,
    on_cancel: EventHandler<()>,
) -> Element {
    let mut current_step = use_signal(|| WizardStep::ChooseLocation);
    let mut parent_path = use_signal(|| Option::<PathBuf>::None);
    let mut vault_name = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut confirm_password = use_signal(String::new);
    let mut creation_state = use_signal(|| CreationState::Idle);
    let mut validation_error = use_signal(|| Option::<String>::None);

    // Computed vault path preview
    let vault_path_preview = {
        let parent = parent_path();
        let name = vault_name();
        if let Some(parent) = parent {
            if !name.is_empty() {
                Some(parent.join(&name))
            } else {
                None
            }
        } else {
            None
        }
    };

    // Password validation
    let password_error = {
        let pw = password();
        let confirm = confirm_password();

        if pw.is_empty() {
            None
        } else if pw.len() < 8 {
            Some("Password must be at least 8 characters".to_string())
        } else if !confirm.is_empty() && pw != confirm {
            Some("Passwords do not match".to_string())
        } else {
            None
        }
    };

    let can_proceed = match current_step() {
        WizardStep::ChooseLocation => parent_path().is_some(),
        WizardStep::EnterName => {
            let name = vault_name();
            !name.is_empty() && !name.contains('/') && !name.contains('\\')
        }
        WizardStep::CreatePassword => {
            let pw = password();
            let confirm = confirm_password();
            pw.len() >= 8 && pw == confirm
        }
        WizardStep::Creating => false,
    };

    // Handle folder picker
    let open_folder_picker = move |_| {
        spawn(async move {
            if let Some(folder) = rfd::AsyncFileDialog::new()
                .set_title("Choose location for new vault")
                .pick_folder()
                .await
            {
                parent_path.set(Some(folder.path().to_path_buf()));
            }
        });
    };

    // Handle next step
    let next_step = {
        let vault_path_preview = vault_path_preview.clone();
        move |_| {
            validation_error.set(None);

            match current_step() {
                WizardStep::ChooseLocation => {
                    current_step.set(WizardStep::EnterName);
                }
                WizardStep::EnterName => {
                    // Validate vault name
                    let name = vault_name();
                    if name.is_empty() {
                        validation_error.set(Some("Vault name cannot be empty".to_string()));
                        return;
                    }
                    if name.contains('/') || name.contains('\\') {
                        validation_error.set(Some("Vault name cannot contain path separators".to_string()));
                        return;
                    }
                    // Check if vault already exists
                    if let Some(ref parent) = parent_path() {
                        let full_path = parent.join(&name);
                        if full_path.exists() {
                            validation_error.set(Some(format!(
                                "A folder named '{}' already exists at this location",
                                name
                            )));
                            return;
                        }
                    }
                    current_step.set(WizardStep::CreatePassword);
                }
                WizardStep::CreatePassword => {
                    // Start vault creation
                    current_step.set(WizardStep::Creating);
                    creation_state.set(CreationState::Creating);

                    let vault_path = vault_path_preview.clone().unwrap();
                    let pw = password();
                    let vault_path_for_success = vault_path.clone();

                    spawn(async move {
                        // Create vault in blocking task (involves scrypt)
                        let result = tokio::task::spawn_blocking(move || {
                            oxidized_cryptolib::vault::VaultCreator::new(&vault_path, &pw).create()
                        })
                        .await;

                        match result {
                            Ok(Ok(_ops)) => {
                                creation_state.set(CreationState::Success(vault_path_for_success.clone()));
                                on_complete.call(vault_path_for_success);
                            }
                            Ok(Err(e)) => {
                                tracing::error!("Failed to create vault: {}", e);
                                creation_state.set(CreationState::Error(format!(
                                    "Failed to create vault: {}",
                                    e
                                )));
                            }
                            Err(e) => {
                                tracing::error!("Vault creation task panicked: {}", e);
                                creation_state.set(CreationState::Error(
                                    "Internal error occurred".to_string(),
                                ));
                            }
                        }
                    });
                }
                WizardStep::Creating => {}
            }
        }
    };

    // Handle back step
    let mut prev_step = move |_| {
        validation_error.set(None);
        match current_step() {
            WizardStep::ChooseLocation => {}
            WizardStep::EnterName => current_step.set(WizardStep::ChooseLocation),
            WizardStep::CreatePassword => current_step.set(WizardStep::EnterName),
            WizardStep::Creating => {} // Can't go back during creation
        }
    };

    let step_title = match current_step() {
        WizardStep::ChooseLocation => "Choose Location",
        WizardStep::EnterName => "Vault Name",
        WizardStep::CreatePassword => "Create Password",
        WizardStep::Creating => "Creating Vault",
    };

    let step_number = match current_step() {
        WizardStep::ChooseLocation => 1,
        WizardStep::EnterName => 2,
        WizardStep::CreatePassword => 3,
        WizardStep::Creating => 4,
    };

    let is_location_step = matches!(current_step(), WizardStep::ChooseLocation);
    let is_name_step = matches!(current_step(), WizardStep::EnterName);
    let is_password_step = matches!(current_step(), WizardStep::CreatePassword);
    let is_creating_step = matches!(current_step(), WizardStep::Creating);
    let is_success = matches!(creation_state(), CreationState::Success(_));
    let is_error = matches!(creation_state(), CreationState::Error(_));

    rsx! {
        // Modal overlay
        div {
            style: "
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 1000;
            ",
            onclick: move |e| e.stop_propagation(),

            // Dialog
            div {
                style: "
                    background: #fff;
                    border-radius: 12px;
                    width: 480px;
                    max-height: 90vh;
                    overflow: hidden;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                ",
                onclick: move |e| e.stop_propagation(),

                // Header with progress
                div {
                    style: "padding: 20px 24px; border-bottom: 1px solid #eee;",

                    // Step indicator
                    StepIndicator { current_step: step_number }

                    h2 {
                        style: "margin: 0; font-size: 18px; font-weight: 600; color: #1a1a1a;",
                        "{step_title}"
                    }
                }

                // Content
                div {
                    style: "padding: 24px;",

                    // Step 1: Choose Location
                    if is_location_step {
                        LocationStep {
                            parent_path: parent_path(),
                            on_browse: open_folder_picker,
                        }
                    }

                    // Step 2: Enter Name
                    if is_name_step {
                        NameStep {
                            vault_name: vault_name(),
                            on_name_change: move |name: String| vault_name.set(name),
                            vault_path_preview: vault_path_preview.clone(),
                            validation_error: validation_error(),
                        }
                    }

                    // Step 3: Create Password
                    if is_password_step {
                        PasswordStep {
                            password: password(),
                            confirm_password: confirm_password(),
                            on_password_change: move |pw: String| password.set(pw),
                            on_confirm_change: move |pw: String| confirm_password.set(pw),
                            password_error: password_error,
                        }
                    }

                    // Step 4: Creating
                    if is_creating_step {
                        CreatingStep {
                            state: creation_state(),
                            on_retry: move |_| {
                                current_step.set(WizardStep::CreatePassword);
                                creation_state.set(CreationState::Idle);
                            },
                        }
                    }
                }

                // Footer with buttons
                div {
                    style: "
                        padding: 16px 24px;
                        border-top: 1px solid #eee;
                        display: flex;
                        justify-content: space-between;
                    ",

                    // Back/Cancel button
                    {
                        let show_close = is_location_step || is_success;
                        let disabled = is_creating_step && !is_success && !is_error;
                        rsx! {
                            button {
                                style: "
                                    padding: 10px 20px;
                                    background: transparent;
                                    border: 1px solid #ddd;
                                    border-radius: 6px;
                                    font-size: 14px;
                                    cursor: pointer;
                                ",
                                onclick: move |_| {
                                    if is_location_step || is_success {
                                        on_cancel.call(());
                                    } else if !is_creating_step {
                                        prev_step(());
                                    }
                                },
                                disabled: disabled,

                                if show_close { "Close" } else { "Back" }
                            }
                        }
                    }

                    // Next/Create button
                    {
                        let show_next = !is_creating_step || is_error;
                        let btn_bg = if can_proceed { "#2196f3" } else { "#ccc" };
                        let btn_cursor = if can_proceed { "pointer" } else { "not-allowed" };
                        let btn_text = if is_password_step { "Create Vault" } else { "Next" };
                        if show_next {
                            rsx! {
                                button {
                                    style: "
                                        padding: 10px 20px;
                                        background: {btn_bg};
                                        color: #fff;
                                        border: none;
                                        border-radius: 6px;
                                        font-size: 14px;
                                        cursor: {btn_cursor};
                                    ",
                                    onclick: next_step,
                                    disabled: !can_proceed,
                                    "{btn_text}"
                                }
                            }
                        } else {
                            rsx! {}
                        }
                    }
                }
            }
        }
    }
}

/// Step indicator showing progress through wizard
#[component]
fn StepIndicator(current_step: i32) -> Element {
    let line1_bg = if 1 < current_step { "#4caf50" } else { "#ddd" };
    let line2_bg = if 2 < current_step { "#4caf50" } else { "#ddd" };
    let line3_bg = if 3 < current_step { "#4caf50" } else { "#ddd" };

    rsx! {
        div {
            style: "display: flex; align-items: center; gap: 8px; margin-bottom: 8px;",

            StepDot { step: 1, current: current_step }
            span {
                style: "flex: 1; height: 2px; background: {line1_bg};",
            }
            StepDot { step: 2, current: current_step }
            span {
                style: "flex: 1; height: 2px; background: {line2_bg};",
            }
            StepDot { step: 3, current: current_step }
            span {
                style: "flex: 1; height: 2px; background: {line3_bg};",
            }
            StepDot { step: 4, current: current_step }
        }
    }
}

/// Individual step dot in the indicator
#[component]
fn StepDot(step: i32, current: i32) -> Element {
    let is_current = step == current;
    let is_completed = step < current;
    let bg = if is_current {
        "#2196f3"
    } else if is_completed {
        "#4caf50"
    } else {
        "#ddd"
    };
    let color = if is_current || is_completed { "#fff" } else { "#666" };

    rsx! {
        span {
            style: "
                width: 24px;
                height: 24px;
                border-radius: 50%;
                background: {bg};
                color: {color};
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
                font-weight: 600;
            ",
            "{step}"
        }
    }
}

/// Step 1: Choose location content
#[component]
fn LocationStep(
    parent_path: Option<PathBuf>,
    on_browse: EventHandler<()>,
) -> Element {
    rsx! {
        p {
            style: "margin: 0 0 16px 0; color: #666; font-size: 14px;",
            "Choose the folder where your new vault will be created."
        }

        div {
            style: "
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 12px;
                background: #f9f9f9;
                border-radius: 6px;
                border: 1px dashed #ccc;
            ",

            span {
                style: "font-size: 24px;",
                ""
            }

            div {
                style: "flex: 1;",

                if let Some(path) = parent_path {
                    span {
                        style: "font-size: 13px; color: #333; word-break: break-all;",
                        "{path.display()}"
                    }
                } else {
                    span {
                        style: "font-size: 13px; color: #999;",
                        "No folder selected"
                    }
                }
            }

            button {
                style: "
                    padding: 8px 16px;
                    background: #2196f3;
                    color: #fff;
                    border: none;
                    border-radius: 4px;
                    font-size: 13px;
                    cursor: pointer;
                ",
                onclick: move |_| on_browse.call(()),
                "Browse..."
            }
        }
    }
}

/// Step 2: Enter vault name content
#[component]
fn NameStep(
    vault_name: String,
    on_name_change: EventHandler<String>,
    vault_path_preview: Option<PathBuf>,
    validation_error: Option<String>,
) -> Element {
    rsx! {
        p {
            style: "margin: 0 0 16px 0; color: #666; font-size: 14px;",
            "Enter a name for your new vault."
        }

        input {
            r#type: "text",
            placeholder: "My Vault",
            value: "{vault_name}",
            oninput: move |e| on_name_change.call(e.value().clone()),
            style: "
                width: 100%;
                padding: 12px;
                font-size: 16px;
                border: 1px solid #ddd;
                border-radius: 6px;
                box-sizing: border-box;
            ",
        }

        if let Some(preview) = vault_path_preview {
            div {
                style: "margin-top: 12px; padding: 8px 12px; background: #f5f5f5; border-radius: 4px;",
                p {
                    style: "margin: 0 0 4px 0; font-size: 12px; color: #666;",
                    "Vault will be created at:"
                }
                p {
                    style: "margin: 0; font-size: 13px; color: #333; word-break: break-all;",
                    "{preview.display()}"
                }
            }
        }

        if let Some(error) = validation_error {
            p {
                style: "margin: 12px 0 0 0; color: #f44336; font-size: 13px;",
                "{error}"
            }
        }
    }
}

/// Step 3: Create password content
#[component]
fn PasswordStep(
    password: String,
    confirm_password: String,
    on_password_change: EventHandler<String>,
    on_confirm_change: EventHandler<String>,
    password_error: Option<String>,
) -> Element {
    rsx! {
        p {
            style: "margin: 0 0 16px 0; color: #666; font-size: 14px;",
            "Create a strong password to protect your vault. This password cannot be recovered."
        }

        div {
            style: "margin-bottom: 12px;",

            label {
                style: "display: block; font-size: 13px; color: #666; margin-bottom: 4px;",
                "Password"
            }
            input {
                r#type: "password",
                placeholder: "Enter password",
                value: "{password}",
                oninput: move |e| on_password_change.call(e.value().clone()),
                style: "
                    width: 100%;
                    padding: 12px;
                    font-size: 14px;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    box-sizing: border-box;
                ",
            }
        }

        div {
            label {
                style: "display: block; font-size: 13px; color: #666; margin-bottom: 4px;",
                "Confirm Password"
            }
            input {
                r#type: "password",
                placeholder: "Confirm password",
                value: "{confirm_password}",
                oninput: move |e| on_confirm_change.call(e.value().clone()),
                style: "
                    width: 100%;
                    padding: 12px;
                    font-size: 14px;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    box-sizing: border-box;
                ",
            }
        }

        if let Some(error) = password_error {
            p {
                style: "margin: 12px 0 0 0; color: #f44336; font-size: 13px;",
                "{error}"
            }
        }

        // Password requirements hint
        div {
            style: "margin-top: 12px; padding: 8px 12px; background: #fff8e1; border-radius: 4px;",
            p {
                style: "margin: 0; font-size: 12px; color: #f57c00;",
                "Minimum 8 characters required. Choose a strong, unique password."
            }
        }
    }
}

/// Step 4: Creating vault progress content
#[component]
fn CreatingStep(
    state: CreationState,
    on_retry: EventHandler<()>,
) -> Element {
    let is_creating = matches!(state, CreationState::Creating | CreationState::Idle);
    let success_path = match &state {
        CreationState::Success(p) => Some(p.display().to_string()),
        _ => None,
    };
    let error_msg = match &state {
        CreationState::Error(m) => Some(m.clone()),
        _ => None,
    };

    rsx! {
        div {
            style: "text-align: center; padding: 24px 0;",

            if is_creating {
                div {
                    style: "font-size: 48px; margin-bottom: 16px;",
                    ""
                }
                p {
                    style: "margin: 0; color: #666; font-size: 14px;",
                    "Creating your vault..."
                }
                p {
                    style: "margin: 8px 0 0 0; color: #999; font-size: 12px;",
                    "This may take a few seconds"
                }
            }

            if let Some(path) = success_path {
                div {
                    style: "font-size: 48px; margin-bottom: 16px;",
                    ""
                }
                p {
                    style: "margin: 0; color: #4caf50; font-size: 16px; font-weight: 500;",
                    "Vault Created Successfully!"
                }
                p {
                    style: "margin: 8px 0 0 0; color: #666; font-size: 13px; word-break: break-all;",
                    "{path}"
                }
            }

            if let Some(msg) = error_msg {
                div {
                    style: "font-size: 48px; margin-bottom: 16px;",
                    ""
                }
                p {
                    style: "margin: 0; color: #f44336; font-size: 16px; font-weight: 500;",
                    "Failed to Create Vault"
                }
                p {
                    style: "margin: 8px 0 0 0; color: #666; font-size: 13px;",
                    "{msg}"
                }
                button {
                    style: "
                        margin-top: 16px;
                        padding: 8px 16px;
                        background: #f5f5f5;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    ",
                    onclick: move |_| on_retry.call(()),
                    "Try Again"
                }
            }
        }
    }
}
