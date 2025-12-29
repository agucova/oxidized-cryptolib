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
            class: "dialog-backdrop",
            onclick: move |e| e.stop_propagation(),

            // Dialog
            div {
                class: "dialog w-[480px] max-h-[90vh] overflow-hidden",
                onclick: move |e| e.stop_propagation(),

                // Header with progress
                div {
                    class: "px-6 py-5 border-b border-gray-200 dark:border-neutral-700",

                    // Step indicator
                    StepIndicator { current_step: step_number }

                    h2 {
                        class: "m-0 text-lg font-semibold text-gray-900 dark:text-gray-100",
                        "{step_title}"
                    }
                }

                // Content
                div {
                    class: "p-6",

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
                    class: "dialog-footer justify-between",

                    // Back/Cancel button
                    {
                        let show_close = is_location_step || is_success;
                        let disabled = is_creating_step && !is_success && !is_error;
                        rsx! {
                            button {
                                class: "btn-secondary",
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
                        let btn_text = if is_password_step { "Create Vault" } else { "Next" };
                        if show_next {
                            rsx! {
                                button {
                                    class: "btn-primary",
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
    let line1_class = if 1 < current_step { "flex-1 h-0.5 bg-green-500" } else { "flex-1 h-0.5 bg-gray-300 dark:bg-neutral-600" };
    let line2_class = if 2 < current_step { "flex-1 h-0.5 bg-green-500" } else { "flex-1 h-0.5 bg-gray-300 dark:bg-neutral-600" };
    let line3_class = if 3 < current_step { "flex-1 h-0.5 bg-green-500" } else { "flex-1 h-0.5 bg-gray-300 dark:bg-neutral-600" };

    rsx! {
        div {
            class: "flex items-center gap-2 mb-2",

            StepDot { step: 1, current: current_step }
            span { class: line1_class }
            StepDot { step: 2, current: current_step }
            span { class: line2_class }
            StepDot { step: 3, current: current_step }
            span { class: line3_class }
            StepDot { step: 4, current: current_step }
        }
    }
}

/// Individual step dot in the indicator
#[component]
fn StepDot(step: i32, current: i32) -> Element {
    let is_current = step == current;
    let is_completed = step < current;

    let class = if is_current {
        "w-6 h-6 rounded-full bg-blue-500 text-white flex items-center justify-center text-xs font-semibold"
    } else if is_completed {
        "w-6 h-6 rounded-full bg-green-500 text-white flex items-center justify-center text-xs font-semibold"
    } else {
        "w-6 h-6 rounded-full bg-gray-300 dark:bg-neutral-600 text-gray-600 dark:text-gray-400 flex items-center justify-center text-xs font-semibold"
    };

    rsx! {
        span {
            class: class,
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
            class: "mb-4 text-sm text-gray-600 dark:text-gray-400",
            "Choose the folder where your new vault will be created."
        }

        div {
            class: "flex items-center gap-3 p-3 bg-gray-50 dark:bg-neutral-800 rounded-lg border border-dashed border-gray-300 dark:border-neutral-600",

            span {
                class: "text-2xl",
                ""
            }

            div {
                class: "flex-1",

                if let Some(path) = parent_path {
                    span {
                        class: "text-sm text-gray-900 dark:text-gray-100 break-all",
                        "{path.display()}"
                    }
                } else {
                    span {
                        class: "text-sm text-gray-500 dark:text-gray-500",
                        "No folder selected"
                    }
                }
            }

            button {
                class: "btn-primary btn-sm",
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
            class: "mb-4 text-sm text-gray-600 dark:text-gray-400",
            "Enter a name for your new vault."
        }

        input {
            r#type: "text",
            class: "input text-base",
            placeholder: "My Vault",
            value: "{vault_name}",
            oninput: move |e| on_name_change.call(e.value().clone()),
        }

        if let Some(preview) = vault_path_preview {
            div {
                class: "mt-3 p-2 px-3 bg-gray-100 dark:bg-neutral-700 rounded",
                p {
                    class: "mb-1 text-xs text-gray-600 dark:text-gray-400",
                    "Vault will be created at:"
                }
                p {
                    class: "text-sm text-gray-900 dark:text-gray-100 break-all",
                    "{preview.display()}"
                }
            }
        }

        if let Some(error) = validation_error {
            p {
                class: "mt-3 text-sm text-red-600 dark:text-red-400",
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
            class: "mb-4 text-sm text-gray-600 dark:text-gray-400",
            "Create a strong password to protect your vault. This password cannot be recovered."
        }

        div {
            class: "mb-3",

            label {
                class: "label",
                "Password"
            }
            input {
                r#type: "password",
                class: "input",
                placeholder: "Enter password",
                value: "{password}",
                oninput: move |e| on_password_change.call(e.value().clone()),
            }
        }

        div {
            label {
                class: "label",
                "Confirm Password"
            }
            input {
                r#type: "password",
                class: "input",
                placeholder: "Confirm password",
                value: "{confirm_password}",
                oninput: move |e| on_confirm_change.call(e.value().clone()),
            }
        }

        if let Some(error) = password_error {
            p {
                class: "mt-3 text-sm text-red-600 dark:text-red-400",
                "{error}"
            }
        }

        // Password requirements hint
        div {
            class: "alert-warning mt-3",
            "Minimum 8 characters required. Choose a strong, unique password."
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
            class: "text-center py-6",

            if is_creating {
                div {
                    class: "text-5xl mb-4",
                    ""
                }
                p {
                    class: "text-sm text-gray-600 dark:text-gray-400",
                    "Creating your vault..."
                }
                p {
                    class: "mt-2 text-xs text-gray-500 dark:text-gray-500",
                    "This may take a few seconds"
                }
            }

            if let Some(path) = success_path {
                div {
                    class: "text-5xl mb-4",
                    ""
                }
                p {
                    class: "text-base font-medium text-green-600 dark:text-green-400",
                    "Vault Created Successfully!"
                }
                p {
                    class: "mt-2 text-sm text-gray-600 dark:text-gray-400 break-all",
                    "{path}"
                }
            }

            if let Some(msg) = error_msg {
                div {
                    class: "text-5xl mb-4",
                    ""
                }
                p {
                    class: "text-base font-medium text-red-600 dark:text-red-400",
                    "Failed to Create Vault"
                }
                p {
                    class: "mt-2 text-sm text-gray-600 dark:text-gray-400",
                    "{msg}"
                }
                button {
                    class: "btn-secondary mt-4",
                    onclick: move |_| on_retry.call(()),
                    "Try Again"
                }
            }
        }
    }
}
