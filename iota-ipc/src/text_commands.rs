use crate::LocalRequest;

pub const COMMANDS: &[&str] = &[
    "status",
    "tasks",
    "users list",
    "users show ",
    "users add ",
    "users remove ",
    "users import ",
    "omikron status",
    "reconnect",
    "identity rotate",
    "daemon status",
    "config get",
    "config set ",
    "config reload",
    "health",
    "components",
    "logs",
    "update check",
    "community list",
    "restart",
    "stop",
];

pub fn completions(prefix: &str) -> Vec<&'static str> {
    let normalized = prefix.trim_start_matches('/');
    COMMANDS
        .iter()
        .copied()
        .filter(|command| command.starts_with(normalized))
        .collect()
}

pub fn validation_error(line: &str) -> Option<String> {
    let normalized = line.trim_start_matches('/').trim();
    if normalized == "help" || parse(normalized).is_some() {
        None
    } else {
        Some(format!(
            "Unknown command `{normalized}`. Use /help or Tab completion."
        ))
    }
}

/// Parse a text command string into a typed IPC request.
///
/// Both the CLI console and the TUI command palette use this single parser.
/// Commands are case-insensitive and support an optional leading `/`.
pub fn parse(line: &str) -> Option<LocalRequest> {
    let parts: Vec<&str> = line.trim_start_matches('/').split_whitespace().collect();
    match parts.as_slice() {
        ["help"] => None,
        ["status"] => Some(LocalRequest::GetStatus),
        ["tasks"] => Some(LocalRequest::ListTasks),
        ["users"] | ["user", "list"] | ["users", "list"] => Some(LocalRequest::ListUsers),
        ["user" | "users", "show", id_str] => {
            let user_id = id_str.parse::<i64>().ok()?;
            Some(LocalRequest::GetUser { user_id })
        }
        ["user" | "users", "add", username] => Some(LocalRequest::CreateUser {
            username: username.to_string(),
        }),
        ["user" | "users", "remove", id_str] => {
            let user_id = id_str.parse::<i64>().ok()?;
            Some(LocalRequest::RemoveUser { user_id })
        }
        ["user" | "users", "import", username] => Some(LocalRequest::ImportUser {
            username: username.to_string(),
        }),
        ["reconnect"] => Some(LocalRequest::ReconnectOmikron),
        ["regenerate", "keys"] | ["identity", "rotate"] => Some(LocalRequest::RotateIotaIdentity),
        ["reload"] | ["restart"] => Some(LocalRequest::RequestProcessExit {
            intent: crate::ExitIntent::Restart,
        }),
        ["shutdown"] | ["stop"] => Some(LocalRequest::RequestProcessExit {
            intent: crate::ExitIntent::Stop,
        }),
        ["daemon", "status"] => Some(LocalRequest::GetDaemonStatus),
        ["config", "get"] => Some(LocalRequest::GetConfig),
        ["config", "set", key, value] => Some(LocalRequest::SetConfig {
            key: key.to_string(),
            value: value.to_string(),
        }),
        ["config", "reload"] => Some(LocalRequest::ReloadConfig),
        ["omikron", "status"] => Some(LocalRequest::GetOmikronStatus),
        ["health"] => Some(LocalRequest::ListComponents),
        ["components"] => Some(LocalRequest::ListComponents),
        ["logs"] => Some(LocalRequest::GetLogs { limit: 100 }),
        ["update", "check"] => Some(LocalRequest::CheckUpdate),
        ["community", "list"] | ["communities"] => Some(LocalRequest::ListCommunities),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        assert!(matches!(parse("status"), Some(LocalRequest::GetStatus)));
    }

    #[test]
    fn parses_tasks() {
        assert!(matches!(parse("tasks"), Some(LocalRequest::ListTasks)));
    }

    #[test]
    fn parses_user_list_shortcuts() {
        assert!(matches!(parse("users"), Some(LocalRequest::ListUsers)));
        assert!(matches!(parse("user list"), Some(LocalRequest::ListUsers)));
    }

    #[test]
    fn parses_user_add() {
        let req = parse("user add alice").unwrap();
        match req {
            LocalRequest::CreateUser { username } => assert_eq!(username, "alice"),
            _ => panic!("expected CreateUser"),
        }
    }

    #[test]
    fn accepts_the_headless_cli_user_vocabulary() {
        assert!(matches!(parse("users list"), Some(LocalRequest::ListUsers)));
        assert!(matches!(
            parse("users add alice"),
            Some(LocalRequest::CreateUser { .. })
        ));
        assert!(matches!(
            parse("users remove 42"),
            Some(LocalRequest::RemoveUser { user_id: 42 })
        ));
        assert!(matches!(
            parse("identity rotate"),
            Some(LocalRequest::RotateIotaIdentity)
        ));
    }

    #[test]
    fn parses_user_remove_by_id() {
        let req = parse("user remove 42").unwrap();
        match req {
            LocalRequest::RemoveUser { user_id } => assert_eq!(user_id, 42),
            _ => panic!("expected RemoveUser"),
        }
    }

    #[test]
    fn user_remove_requires_numeric_id() {
        assert!(parse("user remove alice").is_none());
    }

    #[test]
    fn parses_reconnect() {
        assert!(matches!(
            parse("reconnect"),
            Some(LocalRequest::ReconnectOmikron)
        ));
    }

    #[test]
    fn parses_regenerate_keys() {
        assert!(matches!(
            parse("regenerate keys"),
            Some(LocalRequest::RotateIotaIdentity)
        ));
    }

    #[test]
    fn parses_restart_aliases() {
        assert!(matches!(
            parse("restart"),
            Some(LocalRequest::RequestProcessExit { .. })
        ));
        assert!(matches!(
            parse("reload"),
            Some(LocalRequest::RequestProcessExit { .. })
        ));
    }

    #[test]
    fn parses_stop_aliases() {
        assert!(matches!(
            parse("stop"),
            Some(LocalRequest::RequestProcessExit { .. })
        ));
        assert!(matches!(
            parse("shutdown"),
            Some(LocalRequest::RequestProcessExit { .. })
        ));
    }

    #[test]
    fn parses_daemon_status() {
        assert!(matches!(
            parse("daemon status"),
            Some(LocalRequest::GetDaemonStatus)
        ));
    }

    #[test]
    fn parses_config_get() {
        assert!(matches!(parse("config get"), Some(LocalRequest::GetConfig)));
    }

    #[test]
    fn parses_config_reload() {
        assert!(matches!(
            parse("config reload"),
            Some(LocalRequest::ReloadConfig)
        ));
    }

    #[test]
    fn parses_omikron_status() {
        assert!(matches!(
            parse("omikron status"),
            Some(LocalRequest::GetOmikronStatus)
        ));
    }

    #[test]
    fn parses_components() {
        assert!(matches!(
            parse("components"),
            Some(LocalRequest::ListComponents)
        ));
    }

    #[test]
    fn parses_health() {
        assert!(matches!(
            parse("health"),
            Some(LocalRequest::ListComponents)
        ));
    }

    #[test]
    fn parses_users_show() {
        let req = parse("users show 42").unwrap();
        match req {
            LocalRequest::GetUser { user_id } => assert_eq!(user_id, 42),
            _ => panic!("expected GetUser"),
        }
    }

    #[test]
    fn user_show_requires_numeric_id() {
        assert!(parse("users show alice").is_none());
    }

    #[test]
    fn parses_config_set() {
        let req = parse("config set port 8080").unwrap();
        match req {
            LocalRequest::SetConfig { key, value } => {
                assert_eq!(key, "port");
                assert_eq!(value, "8080");
            }
            _ => panic!("expected SetConfig"),
        }
    }

    #[test]
    fn parses_logs() {
        assert!(matches!(parse("logs"), Some(LocalRequest::GetLogs { .. })));
    }

    #[test]
    fn parses_update_check() {
        assert!(matches!(
            parse("update check"),
            Some(LocalRequest::CheckUpdate)
        ));
    }

    #[test]
    fn parses_community_list() {
        assert!(matches!(
            parse("community list"),
            Some(LocalRequest::ListCommunities)
        ));
    }

    #[test]
    fn parses_communities_alias() {
        assert!(matches!(
            parse("communities"),
            Some(LocalRequest::ListCommunities)
        ));
    }

    #[test]
    fn parses_users_import() {
        let req = parse("users import alice").unwrap();
        match req {
            LocalRequest::ImportUser { username } => assert_eq!(username, "alice"),
            _ => panic!("expected ImportUser"),
        }
    }

    #[test]
    fn parses_with_slash_prefix() {
        assert!(matches!(parse("/status"), Some(LocalRequest::GetStatus)));
        assert!(matches!(parse("/tasks"), Some(LocalRequest::ListTasks)));
    }

    #[test]
    fn unknown_returns_none() {
        assert!(parse("nonexistent").is_none());
    }

    #[test]
    fn completion_is_prefix_based_and_deterministic() {
        assert_eq!(completions("identity r"), vec!["identity rotate"]);
        assert_eq!(completions("/users a"), vec!["users add "]);
        assert!(completions("definitely-unknown").is_empty());
    }

    #[test]
    fn validation_distinguishes_help_and_unknown_commands() {
        assert_eq!(validation_error("/help"), None);
        assert!(validation_error("status").is_none());
        assert!(
            validation_error("statuz")
                .unwrap()
                .contains("Unknown command")
        );
    }
}
