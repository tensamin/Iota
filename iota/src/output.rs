use super::*;

/// The IPC payload is the versioned, tagged schema used by headless clients.
/// Text remains an operator-oriented presentation; JSON and YAML must never
/// require consumers to parse it.
pub(super) fn render_structured(
    payload: &ResponsePayload,
    output: OutputFormat,
) -> Result<(), StartupError> {
    if matches!(
        payload,
        ResponsePayload::UserCredentialExport { .. }
            | ResponsePayload::TAuthAppCreated { .. }
            | ResponsePayload::TAuthAppCredentialExport { .. }
    ) {
        return Err(StartupError::Other(
            "Refusing to encode credential material as ordinary output.".into(),
        ));
    }
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(payload).map_err(|error| StartupError::Other(format!(
                "Cannot encode JSON output: {error}"
            )))?
        ),
        OutputFormat::Yaml => print!(
            "{}",
            serde_yaml::to_string(payload).map_err(|error| StartupError::Other(format!(
                "Cannot encode YAML output: {error}"
            )))?
        ),
        OutputFormat::Table => render_table(payload),
        OutputFormat::Text => unreachable!(),
    }
    Ok(())
}

pub(super) fn render_table(payload: &ResponsePayload) {
    match payload {
        ResponsePayload::InvitationCreated(invitation) => {
            println!("{:<15} {}", "Invitation ID", invitation.invitation_id);
            println!(
                "{:<15} {}",
                "Authority",
                format_args!("{:?}", invitation.authority)
            );
            println!("{:<15} {}", "Token", invitation.raw_token.0);
            println!("{:<15} {}", "Expires", invitation.expires_at);
            if let Some(url) = &invitation.short_url {
                println!("{:<15} {}", "Link", url);
            }
        }
        ResponsePayload::Invitations(invitations) => {
            println!("{:<16} {:<10} {:<14} LABEL", "ID", "AUTHORITY", "STATE");
            for invitation in invitations {
                println!(
                    "{:<16} {:<10} {:<14} {}",
                    invitation.invitation_id,
                    format!("{:?}", invitation.authority),
                    format!("{:?}", invitation.state),
                    invitation.label.as_deref().unwrap_or("-")
                );
            }
        }
        ResponsePayload::InvitationUpdated(invitation) => {
            println!("{:<15} {}", "Invitation ID", invitation.invitation_id);
            println!("{:<15} {:?}", "State", invitation.state);
        }
        ResponsePayload::Users(users) => {
            if users.is_empty() {
                println!("No users.");
                return;
            }
            println!(
                "{:<12} {:<18} {:<10} {:<9} {:<12} PENDING",
                "ID", "USERNAME", "STATE", "DATA", "CREDENTIAL"
            );
            for user in users {
                println!(
                    "{:<12} {:<18} {:<10} {:<9} {:<12} {}",
                    user.user_id,
                    user.username,
                    match user.state {
                        iota_ipc::LocalUserState::Managed => "managed",
                        iota_ipc::LocalUserState::Released => "released",
                    },
                    if user.data_present {
                        "present"
                    } else {
                        "empty"
                    },
                    match user.credential_status {
                        iota_ipc::CredentialStatus::LocalPresent => "local",
                        iota_ipc::CredentialStatus::External => "external",
                        iota_ipc::CredentialStatus::Missing => "missing",
                        iota_ipc::CredentialStatus::None => "none",
                    },
                    user.pending_operation
                        .as_ref()
                        .map(format_pending_operation)
                        .unwrap_or_else(|| "-".into())
                );
            }
        }
        ResponsePayload::TAuthApps(apps) => {
            if apps.is_empty() {
                println!("No TAuth apps.");
                return;
            }
            println!("{:<66} {:<28} MODE", "APP ID", "DOMAIN");
            for app in apps {
                println!(
                    "{:<66} {:<28} {}",
                    app.app_id, app.domain, app.connection_mode
                );
            }
        }
        ResponsePayload::TAuthApp(app) => {
            println!("{:<18} {}", "App ID", app.app_id);
            println!("{:<18} {}", "Domain", app.domain);
            println!("{:<18} {}", "Owner user", app.owner_user_id);
            println!("{:<18} {}", "Public key", app.public_key);
            println!("{:<18} {}", "Mode", app.connection_mode);
            println!("{:<18} {}", "Endpoint", app.endpoint_url);
        }
        ResponsePayload::TAuthAppCreated { .. }
        | ResponsePayload::TAuthAppCredentialExport { .. } => {
            println!("TAuth credential material withheld.");
        }
        ResponsePayload::Tasks(tasks) => {
            if tasks.is_empty() {
                println!("No active tasks.");
                return;
            }
            println!("NAME");
            println!("--------");
            for task in tasks {
                println!("{}", task.name);
            }
        }
        ResponsePayload::Components(components) => {
            if components.is_empty() {
                println!("No component health data available.");
                return;
            }
            println!("{:<20} {:<10} MESSAGE", "COMPONENT", "STATUS");
            println!("{:<20} {:<10} --------", "--------", "--------");
            for comp in components {
                let status_str = match comp.status {
                    iota_ipc::HealthStatus::Healthy => "healthy",
                    iota_ipc::HealthStatus::Degraded => "degraded",
                    iota_ipc::HealthStatus::Failed => "failed",
                };
                let message = comp.message.as_deref().unwrap_or("-");
                println!(
                    "{:<20} {:<10} {}",
                    format!("{:?}", comp.id),
                    status_str,
                    message
                );
            }
        }
        ResponsePayload::Communities(communities) => {
            if communities.is_empty() {
                println!("No communities.");
                return;
            }
            println!("{:<20} TITLE", "NAME");
            println!("{:<20} --------", "--------");
            for c in communities {
                println!("{:<20} {}", c.name, c.title);
            }
        }
        ResponsePayload::LogEntries(logs) => {
            if logs.entries.is_empty() {
                println!("No log entries.");
                return;
            }
            println!(
                "{:<20} {:<6} {:<12} MESSAGE",
                "TIMESTAMP", "LEVEL", "SENDER"
            );
            println!(
                "{:<20} {:<6} {:<12} --------",
                "--------", "--------", "--------"
            );
            for entry in &logs.entries {
                let level = if entry.is_error { "ERR" } else { "INF" };
                println!(
                    "{:<20} {:<6} {:<12} {}",
                    entry.timestamp_ms, level, entry.sender, entry.message
                );
            }
        }
        ResponsePayload::Status(status) => {
            println!("{:<15} Value", "Field");
            println!("{:<15} --------", "--------");
            println!("{:<15} {}", "Phase", status.phase);
            if !status.tasks.is_empty() {
                println!("{:<15} {}", "Tasks", status.tasks.join(", "));
            }
            if let Some(reason) = &status.degraded_reason {
                println!("{:<15} {}", "Degraded", reason);
            }
        }
        ResponsePayload::DaemonStatus(status) => {
            println!("{}", status.formatted);
        }
        ResponsePayload::Config(config) => {
            println!("{}", config.yaml);
        }
        ResponsePayload::OmikronStatus(status) => {
            println!("{:<15} Value", "Field");
            println!("{:<15} --------", "--------");
            println!("{:<15} {}", "Connected", status.connected);
            if let Some(id) = &status.iota_id {
                println!("{:<15} {}", "Iota ID", id);
            }
        }
        ResponsePayload::UpdateStatus(status) => {
            println!("{:<15} Value", "Field");
            println!("{:<15} --------", "--------");
            println!("{:<15} {}", "Available", status.available);
        }
        ResponsePayload::UserCreated { user_id, username } => {
            println!("Created user {} ({})", username, user_id);
        }
        ResponsePayload::TuCredentialPreview(preview) => {
            println!("{:<15} {}", "Username", preview.username);
            println!("{:<15} {}", "User ID", preview.user_id);
            println!(
                "{:<15} {}",
                "Current Iota",
                preview
                    .assigned_iota_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "Unassigned".into())
            );
        }
        ResponsePayload::UserReconciled(result) => {
            println!("{:<15} {}", "User ID", result.user_id);
            println!("{:<15} {:?}", "Action", result.action);
        }
        ResponsePayload::UserDiagnostics(diagnostics) => {
            println!("{:<15} {}", "Username", diagnostics.username);
            println!("{:<15} {}", "User ID", diagnostics.user_id);
            println!("{:<15} {:?}", "Local state", diagnostics.local_state);
            println!("{:<15} {}", "Hosted data", diagnostics.data_present);
            println!("{:<15} {:?}", "Credential", diagnostics.credential_status);
            println!("{:<15} {}", "TAuth grants", diagnostics.tauth_grant_count);
        }
        ResponsePayload::UserCredentialExport { .. } => {
            println!("Credential export payload withheld.");
        }
        ResponsePayload::UserRemoved { user_id } => {
            println!("Removed user {}", user_id);
        }
        ResponsePayload::UserDataPurged { user_id } => {
            println!("Purged hosted data for {}", user_id);
        }
        ResponsePayload::Acknowledged { message } => {
            println!("{}", message);
        }
        ResponsePayload::UserDetail(user) => {
            println!("{:<15} Value", "Field");
            println!("{:<15} --------", "--------");
            println!("{:<15} {}", "Username", user.username);
            println!("{:<15} {}", "User ID", user.user_id);
            if let Some(ref name) = user.display_name {
                println!("{:<15} {}", "Display Name", name);
            }
            println!("{:<15} {}", "Created At", user.created_at);
            if !user.tauth_grants.is_empty() {
                println!("{:<15} {}", "TAuth grants", user.tauth_grants.join(", "));
            }
        }
    }
}

pub(super) fn format_pending_operation(operation: &iota_ipc::UserOperationSummary) -> String {
    let kind = match operation.operation {
        iota_ipc::UserOperationKind::Create => "create",
        iota_ipc::UserOperationKind::Attach => "attach",
        iota_ipc::UserOperationKind::Release => "release",
        iota_ipc::UserOperationKind::Purge => "purge",
    };
    format!("{kind}/{}", operation.phase)
}
