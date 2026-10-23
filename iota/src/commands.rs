use super::*;

pub(super) async fn run_command(
    ipc: Arc<IpcClient>,
    command: Command,
    output: OutputFormat,
) -> Result<(), StartupError> {
    let color = ColorConfig::new();
    let mut credential_output = None;
    let mut tauth_credential_output = None;
    let mut tauth_manifest_output = None;
    let request = match command {
        Command::Status => LocalRequest::GetStatus,
        Command::Tasks => LocalRequest::ListTasks,
        Command::UsersList => LocalRequest::ListUsers,
        Command::UsersShow { user_id } => LocalRequest::GetUser { user_id },
        Command::UsersAdd {
            username: Some(username),
            tu: None,
        } => LocalRequest::CreateUser { username },
        Command::UsersAdd {
            username: None,
            tu: Some(path),
        } => {
            let contents = std::fs::read_to_string(&path).map_err(|error| {
                StartupError::InvalidCommand(format!("Cannot read {}: {error}", path.display()))
            })?;
            iota_util::tu::TuCredential::parse(&contents).map_err(|error| {
                StartupError::InvalidCommand(format!(
                    "Invalid credential {}: {error}",
                    path.display()
                ))
            })?;
            LocalRequest::AttachUserFromTu {
                credential: iota_ipc::SecretString(contents),
            }
        }
        Command::UsersAdd { .. } => {
            return Err(StartupError::InvalidCommand(
                "users add requires exactly one of <username> or --tu <PATH>".into(),
            ));
        }
        Command::UsersRelease {
            user_id,
            confirmed: true,
        } => LocalRequest::ReleaseUser { user_id },
        Command::UsersPurgeData {
            user_id,
            confirmed: true,
        } => LocalRequest::PurgeUserData { user_id },
        Command::UsersCompleteDelete {
            user_id,
            tu,
            confirmed: true,
        } => {
            let credential = match tu {
                Some(path) => {
                    let contents = std::fs::read_to_string(&path).map_err(|error| {
                        StartupError::InvalidCommand(format!(
                            "Cannot read {}: {error}",
                            path.display()
                        ))
                    })?;
                    let parsed =
                        iota_util::tu::TuCredential::parse(&contents).map_err(|error| {
                            StartupError::InvalidCommand(format!(
                                "Invalid credential {}: {error}",
                                path.display()
                            ))
                        })?;
                    if parsed.user_id != user_id {
                        return Err(StartupError::InvalidCommand(
                            "credential user ID does not match complete-delete target".into(),
                        ));
                    }
                    Some(iota_ipc::SecretString(contents))
                }
                None => None,
            };
            LocalRequest::CompleteDeleteUser {
                user_id,
                credential,
            }
        }
        Command::UsersReconcile { user_id } => LocalRequest::ReconcileUser { user_id },
        Command::UsersDiagnostics { user_id } => LocalRequest::GetUserDiagnostics { user_id },
        Command::UsersForceDetach {
            user_id,
            confirmed: true,
        } => LocalRequest::ForceDetachUser { user_id },
        Command::UsersForget {
            user_id,
            confirmed: true,
        } => LocalRequest::ForgetReleasedUser { user_id },
        Command::UsersRevokeApp {
            user_id,
            app_id,
            confirmed: true,
        } => LocalRequest::RevokeTAuthGrant { user_id, app_id },
        Command::UsersRevokeAllApps {
            user_id,
            confirmed: true,
        } => LocalRequest::RevokeAllTAuthGrants { user_id },
        Command::UsersExportCredential { user_id, output } => {
            let daemon_status = ipc.daemon_status();
            if !daemon_status
                .borrow()
                .capabilities
                .iter()
                .any(|capability| capability == "credential_export_v1")
            {
                return Err(StartupError::InvalidCommand(
                    "The connected daemon does not support credential export.".into(),
                ));
            }
            credential_output = Some(output);
            LocalRequest::ExportUserCredential { user_id }
        }
        Command::AppsList => LocalRequest::ListTAuthApps,
        Command::AppsShow { app_id } => LocalRequest::GetTAuthApp { app_id },
        Command::AppsCreate {
            owner_user_id,
            domain,
            name,
            redirects,
            connection,
            output,
            manifest_output,
        } => {
            if output == manifest_output {
                return Err(StartupError::InvalidCommand(
                    ".ta and manifest outputs must use different paths.".into(),
                ));
            }
            for path in [&output, &manifest_output] {
                if path.exists() {
                    return Err(StartupError::InvalidCommand(format!(
                        "Refusing to overwrite {}.",
                        path.display()
                    )));
                }
            }
            tauth_credential_output = Some(output);
            tauth_manifest_output = Some(manifest_output);
            LocalRequest::CreateTAuthApp {
                owner_user_id,
                domain,
                name,
                redirects,
                connection,
            }
        }
        Command::AppsExport { app_id, output } => {
            if output.exists() {
                return Err(StartupError::InvalidCommand(format!(
                    "Refusing to overwrite {}.",
                    output.display()
                )));
            }
            tauth_credential_output = Some(output);
            LocalRequest::ExportTAuthApp { app_id }
        }
        Command::AppsDelete {
            app_id,
            confirmed: true,
        } => LocalRequest::DeleteTAuthApp { app_id },
        Command::OmikronReconnect => LocalRequest::ReconnectOmikron,
        Command::IdentityRotate { confirmed: true } => LocalRequest::RotateIotaIdentity,
        Command::RegenerateKeys { confirmed: true } => LocalRequest::RotateIotaIdentity,
        Command::DaemonRestart { confirmed: true } => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Restart,
        },
        Command::DaemonStop { confirmed: true } => LocalRequest::RequestProcessExit {
            intent: iota_ipc::ExitIntent::Stop,
        },
        Command::DaemonDaemonStatus => LocalRequest::GetDaemonStatus,
        Command::OmikronStatus => LocalRequest::GetOmikronStatus,
        Command::ConfigGet => LocalRequest::GetConfig,
        Command::ConfigSet { key, value } => LocalRequest::SetConfig { key, value },
        Command::ConfigReload => LocalRequest::ReloadConfig,
        Command::Health => LocalRequest::ListComponents,
        Command::Components => LocalRequest::ListComponents,
        Command::Logs { limit } => LocalRequest::GetLogs { limit },
        Command::UpdateCheck => LocalRequest::CheckUpdate,
        Command::UpdateApply | Command::UpdateChannel { .. } => unreachable!(),
        Command::CommunityList => LocalRequest::ListCommunities,
        Command::UsersRelease {
            confirmed: false, ..
        }
        | Command::UsersPurgeData {
            confirmed: false, ..
        }
        | Command::UsersCompleteDelete {
            confirmed: false, ..
        }
        | Command::UsersForceDetach {
            confirmed: false, ..
        }
        | Command::UsersForget {
            confirmed: false, ..
        }
        | Command::UsersRevokeApp {
            confirmed: false, ..
        }
        | Command::UsersRevokeAllApps {
            confirmed: false, ..
        }
        | Command::AppsDelete {
            confirmed: false, ..
        }
        | Command::IdentityRotate { confirmed: false }
        | Command::RegenerateKeys { confirmed: false }
        | Command::DaemonRestart { confirmed: false }
        | Command::DaemonStop { confirmed: false } => {
            return Err(StartupError::InvalidCommand(
                "Refusing destructive command without --yes.".into(),
            ));
        }
        Command::Dashboard
        | Command::Help
        | Command::Version
        | Command::Completions { .. }
        | Command::ManPage
        | Command::Install { .. }
        | Command::Bootstrap { .. }
        | Command::TermsStatus { .. }
        | Command::TermsShow { .. }
        | Command::TermsAccept { .. }
        | Command::DaemonEnable { .. }
        | Command::DaemonDisableStartup
        | Command::DaemonStartupStatus
        | Command::DaemonStart
        | Command::DaemonRestartService
        | Command::DaemonStopService => {
            return Err(StartupError::InvalidCommand(
                "Command cannot be run headlessly.".into(),
            ));
        }
    };
    match ipc
        .send_request(request)
        .await
        .map_err(|e| StartupError::Other(e.to_string()))?
    {
        ResponseResult::Ok(payload) => {
            if let ResponsePayload::UserCredentialExport {
                user_id,
                username,
                credential,
            } = &payload
            {
                let path = credential_output.as_deref().ok_or_else(|| {
                    StartupError::Other(
                        "Refusing to render a credential without an export destination.".into(),
                    )
                })?;
                iota_util::atomic_file::create_private(path, credential.0.as_bytes()).map_err(
                    |error| {
                        StartupError::Other(format!(
                            "Cannot export credential to {}: {error}",
                            path.display()
                        ))
                    },
                )?;
                println!(
                    "Exported credential for {} ({}) to {}.",
                    username,
                    user_id,
                    path.display()
                );
                return Ok(());
            }
            if let ResponsePayload::TAuthAppCreated {
                app,
                credential,
                txt_record,
                manifest_template,
            } = &payload
            {
                let credential_path = tauth_credential_output.as_deref().ok_or_else(|| {
                    StartupError::Other("Missing TAuth credential export destination.".into())
                })?;
                let manifest_path = tauth_manifest_output.as_deref().ok_or_else(|| {
                    StartupError::Other("Missing TAuth manifest export destination.".into())
                })?;
                let bytes = STANDARD.decode(&credential.0).map_err(|error| {
                    StartupError::Other(format!("Daemon returned invalid .ta data: {error}"))
                })?;
                iota_util::atomic_file::create_private(credential_path, &bytes).map_err(
                    |error| {
                        StartupError::Other(format!(
                            "Cannot export credential to {}: {error}",
                            credential_path.display()
                        ))
                    },
                )?;
                if let Err(error) = iota_util::atomic_file::create_private(
                    manifest_path,
                    manifest_template.as_bytes(),
                ) {
                    let _ = std::fs::remove_file(credential_path);
                    return Err(StartupError::Other(format!(
                        "Cannot export manifest template to {}: {error}",
                        manifest_path.display()
                    )));
                }
                println!("Created TAuth app {} for {}.", app.app_id, app.domain);
                println!(".ta: {}", credential_path.display());
                println!("TXT _tauth.{}: {}", app.domain, txt_record);
                println!("Manifest: {}", manifest_path.display());
                return Ok(());
            }
            if let ResponsePayload::TAuthAppCredentialExport { app_id, credential } = &payload {
                let path = tauth_credential_output.as_deref().ok_or_else(|| {
                    StartupError::Other("Missing TAuth credential export destination.".into())
                })?;
                let bytes = STANDARD.decode(&credential.0).map_err(|error| {
                    StartupError::Other(format!("Daemon returned invalid .ta data: {error}"))
                })?;
                iota_util::atomic_file::create_private(path, &bytes).map_err(|error| {
                    StartupError::Other(format!(
                        "Cannot export credential to {}: {error}",
                        path.display()
                    ))
                })?;
                println!("Exported TAuth app {app_id} to {}.", path.display());
                return Ok(());
            }
            if credential_output.is_some() || tauth_credential_output.is_some() {
                return Err(StartupError::Other(
                    "The daemon returned an unexpected credential export response.".into(),
                ));
            }
            if !matches!(output, OutputFormat::Text) {
                return render_structured(&payload, output);
            }
            match payload {
                ResponsePayload::Status(status) => {
                    let phase_color = if status.degraded_reason.is_some() {
                        cli_color::WARNING
                    } else {
                        cli_color::SUCCESS
                    };
                    print!(
                        "{} {}",
                        cli_color::info(&color, "Phase:"),
                        color.colorize(&status.phase, phase_color)
                    );
                    if !status.tasks.is_empty() {
                        print!(
                            ", {} {}",
                            cli_color::info(&color, "Tasks:"),
                            status.tasks.join(", ")
                        );
                    }
                    if let Some(reason) = status.degraded_reason {
                        print!(", {}: {}", cli_color::warning(&color, "Degraded"), reason);
                    }
                    println!();
                }
                ResponsePayload::Tasks(tasks) => {
                    if tasks.is_empty() {
                        println!("{}", cli_color::muted(&color, "No active tasks."));
                    } else {
                        for task in &tasks {
                            println!("{}", task.name);
                        }
                    }
                }
                ResponsePayload::Users(users) => {
                    if users.is_empty() {
                        println!("{}", cli_color::muted(&color, "No users."));
                    } else {
                        println!(
                            "{:<12} {:<18} {:<10} {:<9} {:<12} PENDING",
                            "ID", "USERNAME", "STATE", "DATA", "CREDENTIAL"
                        );
                        for user in &users {
                            println!(
                                "{:<12} {:<18} {:<10} {:<9} {:<12} {}",
                                user.user_id,
                                cli_color::heading(&color, &user.username),
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
                }
                ResponsePayload::TAuthApps(apps) => {
                    if apps.is_empty() {
                        println!("{}", cli_color::muted(&color, "No TAuth apps."));
                    } else {
                        for app in apps {
                            println!("{} {} {}", app.app_id, app.domain, app.connection_mode);
                        }
                    }
                }
                ResponsePayload::TAuthApp(app) => {
                    println!("App ID: {}", app.app_id);
                    println!("Domain: {}", app.domain);
                    println!("Owner user: {}", app.owner_user_id);
                    println!("Mode: {}", app.connection_mode);
                    println!("Endpoint: {}", app.endpoint_url);
                }
                ResponsePayload::TAuthAppCreated { .. }
                | ResponsePayload::TAuthAppCredentialExport { .. } => {
                    return Err(StartupError::Other(
                        "Refusing to display TAuth credential material.".into(),
                    ));
                }
                ResponsePayload::InvitationCreated(invitation) => {
                    println!("Invitation: {}", invitation.invitation_id);
                    println!("Token: {}", invitation.raw_token.0);
                    if let Some(url) = invitation.short_url {
                        println!("Link: {url}");
                    }
                    println!("Expires: {}", invitation.expires_at);
                    if !invitation.mirror_synced {
                        println!("Warning: local invitation metadata is still synchronizing.");
                    }
                }
                ResponsePayload::Invitations(invitations) => {
                    if invitations.is_empty() {
                        println!("No invitations.");
                    } else {
                        for invitation in invitations {
                            println!(
                                "{} ({:?}, {:?})",
                                invitation.invitation_id, invitation.authority, invitation.state
                            );
                        }
                    }
                }
                ResponsePayload::InvitationUpdated(invitation) => {
                    println!(
                        "Invitation {} is {:?}",
                        invitation.invitation_id, invitation.state
                    );
                }
                ResponsePayload::UserCreated { user_id, username } => {
                    println!(
                        "{} {} ({})",
                        cli_color::success(&color, "Created user"),
                        cli_color::heading(&color, &username),
                        user_id
                    );
                }
                ResponsePayload::UserRemoved { user_id } => {
                    println!("{} {}", cli_color::warning(&color, "Removed user"), user_id);
                }
                ResponsePayload::UserDataPurged { user_id } => {
                    println!(
                        "{} hosted data for {}. Account remains managed by this Iota.",
                        cli_color::success(&color, "Purged"),
                        user_id
                    );
                }
                ResponsePayload::Acknowledged { message } => {
                    println!("{}", message);
                }
                ResponsePayload::DaemonStatus(status) => {
                    println!("{}", status.formatted);
                }
                ResponsePayload::Config(config) => {
                    println!("{}", config.yaml);
                }
                ResponsePayload::OmikronStatus(status) => {
                    println!(
                        "{}: {}",
                        cli_color::info(&color, "Connected"),
                        status.connected
                    );
                    if let Some(id) = status.iota_id {
                        println!("{}: {}", cli_color::info(&color, "Iota ID"), id);
                    }
                }
                ResponsePayload::Components(components) => {
                    if components.is_empty() {
                        println!(
                            "{}",
                            cli_color::muted(&color, "No component health data available.")
                        );
                    } else {
                        for comp in &components {
                            let (status_str, style) = match comp.status {
                                iota_ipc::HealthStatus::Healthy => ("healthy", cli_color::SUCCESS),
                                iota_ipc::HealthStatus::Degraded => {
                                    ("degraded", cli_color::WARNING)
                                }
                                iota_ipc::HealthStatus::Failed => ("failed", cli_color::ERROR),
                            };
                            let suffix = comp
                                .message
                                .as_deref()
                                .map(|m| format!(" ({m})"))
                                .unwrap_or_default();
                            println!(
                                "{:?}: {}{}",
                                comp.id,
                                color.colorize(status_str, style),
                                suffix
                            );
                        }
                    }
                }
                ResponsePayload::UserDetail(user) => {
                    println!(
                        "{}: {} ({})",
                        cli_color::info(&color, "User"),
                        cli_color::heading(&color, &user.username),
                        user.user_id
                    );
                    if let Some(ref name) = user.display_name {
                        println!("Display Name: {name}");
                    }
                    println!("Created At: {}", user.created_at);
                    if !user.tauth_grants.is_empty() {
                        println!("TAuth grants: {}", user.tauth_grants.join(", "));
                    }
                }
                ResponsePayload::TuCredentialPreview(preview) => {
                    println!("User: {} ({})", preview.username, preview.user_id);
                    println!(
                        "Current Iota: {}",
                        preview
                            .assigned_iota_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "Unassigned".into())
                    );
                }
                ResponsePayload::UserReconciled(result) => {
                    println!("Reconciled user {}: {:?}", result.user_id, result.action);
                }
                ResponsePayload::UserDiagnostics(diagnostics) => {
                    println!("User: {} ({})", diagnostics.username, diagnostics.user_id);
                    println!("Local state: {:?}", diagnostics.local_state);
                    println!("Hosted data: {}", diagnostics.data_present);
                    println!("Credential: {:?}", diagnostics.credential_status);
                    println!("TAuth grants: {}", diagnostics.tauth_grant_count);
                    if let Some(operation) = &diagnostics.pending_operation {
                        println!("Pending operation: {operation}");
                    }
                }
                ResponsePayload::UserCredentialExport { .. } => {
                    return Err(StartupError::Other(
                        "Refusing to display credential material.".into(),
                    ));
                }
                ResponsePayload::LogEntries(logs) => {
                    for entry in &logs.entries {
                        let ts = entry.timestamp_ms;
                        let (level, style) = if entry.is_error {
                            ("ERR", cli_color::ERROR)
                        } else {
                            ("INF", cli_color::INFO)
                        };
                        println!(
                            "[{ts}] {} {}: {}",
                            color.colorize(level, style),
                            entry.sender,
                            entry.message
                        );
                    }
                }
                ResponsePayload::UpdateStatus(status) => {
                    if status.available {
                        println!("{}", cli_color::success(&color, "Update available."));
                    } else {
                        println!("{}", cli_color::info(&color, "Up to date."));
                    }
                }
                ResponsePayload::Communities(communities) => {
                    if communities.is_empty() {
                        println!("{}", cli_color::muted(&color, "No communities."));
                    } else {
                        for c in &communities {
                            println!("{} ({})", cli_color::heading(&color, &c.title), c.name);
                        }
                    }
                }
            }
            Ok(())
        }
        ResponseResult::Error(code) => Err(StartupError::Other(format!(
            "Daemon request failed: {code}"
        ))),
    }
}
