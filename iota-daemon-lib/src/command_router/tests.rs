use super::{
    InvitationAuthority, IpcRole, LocalRequest, bounded_log_entries,
    invitation_created_after_mirror,
};
use iota_ipc::{ExitIntent, LogEntry, SecretString};

#[test]
fn every_request_has_an_explicit_role_policy() {
    let requests = [
        LocalRequest::GetStatus,
        LocalRequest::ListTasks,
        LocalRequest::ListUsers,
        LocalRequest::CreateUser {
            username: "alice".into(),
        },
        LocalRequest::AttachUserFromTu {
            credential: SecretString("credential".into()),
        },
        LocalRequest::InspectTuCredential {
            credential: SecretString("credential".into()),
        },
        LocalRequest::ReconcileUser { user_id: 1 },
        LocalRequest::ForceDetachUser { user_id: 1 },
        LocalRequest::ForgetReleasedUser { user_id: 1 },
        LocalRequest::GetUserDiagnostics { user_id: 1 },
        LocalRequest::RevokeTAuthGrant {
            user_id: 1,
            app_id: "desktop".into(),
        },
        LocalRequest::RevokeAllTAuthGrants { user_id: 1 },
        LocalRequest::ExportUserCredential { user_id: 1 },
        LocalRequest::PurgeUserData { user_id: 1 },
        LocalRequest::ReleaseUser { user_id: 1 },
        LocalRequest::CompleteDeleteUser {
            user_id: 1,
            credential: None,
        },
        LocalRequest::RemoveUser { user_id: 1 },
        LocalRequest::ReconnectOmikron,
        LocalRequest::RotateIotaIdentity,
        LocalRequest::RequestProcessExit {
            intent: ExitIntent::Stop,
        },
        LocalRequest::GetDaemonStatus,
        LocalRequest::RestartDaemon,
        LocalRequest::StopDaemon,
        LocalRequest::GetConfig,
        LocalRequest::SetConfig {
            key: "port".into(),
            value: "1984".into(),
        },
        LocalRequest::ReloadConfig,
        LocalRequest::GetOmikronStatus,
        LocalRequest::ListComponents,
        LocalRequest::GetUser { user_id: 1 },
        LocalRequest::ImportUser {
            username: "alice".into(),
        },
        LocalRequest::GetLogs { limit: 10 },
        LocalRequest::CheckUpdate,
        LocalRequest::ListCommunities,
    ];

    assert_eq!(requests.len(), 33);
    for request in requests {
        let required = request.required_role();
        assert!(IpcRole::Admin.allows(required));
        assert_eq!(
            IpcRole::Operate.allows(required),
            required != IpcRole::Admin
        );
        assert_eq!(IpcRole::Read.allows(required), required == IpcRole::Read);
    }
}

#[test]
fn log_responses_drop_entries_that_cannot_fit_one_ipc_frame() {
    let entries = vec![LogEntry {
        timestamp_ms: 0,
        sender: "test".into(),
        message: "x".repeat(2 * 1024 * 1024),
        is_error: false,
    }];

    assert!(bounded_log_entries(entries).is_empty());
}

#[test]
fn omega_creation_credentials_survive_a_local_mirror_failure() {
    let created = invitation_created_after_mirror(
        1,
        InvitationAuthority::Omega,
        7,
        "raw-token".into(),
        99,
        Some("https://omega/direct/short".into()),
        Err(iota_storage::storage_error::StorageError::Other(
            "injected mirror failure".into(),
        )),
    );

    assert_eq!(created.raw_token.0, "raw-token");
    assert_eq!(
        created.short_url.as_deref(),
        Some("https://omega/direct/short")
    );
    assert!(!created.mirror_synced);
}
