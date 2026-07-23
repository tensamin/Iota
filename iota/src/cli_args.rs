use iota_cli::theme::ThemeName;

#[derive(Debug)]
pub struct CliInvocation {
    pub theme_override: Option<ThemeName>,
    pub command: Command,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Dashboard,
    Help,
    Install {
        bundle: String,
        operator: Option<String>,
    },
    Status,
    Tasks,
    UsersList,
    DaemonRestart {
        confirmed: bool,
    },
    DaemonStop {
        confirmed: bool,
    },
    DaemonStopProcess,
    DaemonEnable {
        mode: String,
    },
    DaemonDisableStartup,
    DaemonDaemonStatus,
}
impl CliInvocation {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut theme_override = None;
        let mut command = Vec::new();
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            if argument == "--theme" {
                let value = args.next().ok_or_else(|| {
                    format!(
                        "--theme requires a value ({})",
                        ThemeName::supported_names()
                    )
                })?;
                theme_override = Some(value.parse()?);
            } else if let Some(value) = argument.strip_prefix("--theme=") {
                theme_override = Some(value.parse()?);
            } else {
                command.push(argument);
            }
        }
        let command = match command.as_slice() {
            [] => Command::Dashboard,
            [help] if help == "help" || help == "--help" => Command::Help,
            [status] if status == "status" => Command::Status,
            [tasks] if tasks == "tasks" => Command::Tasks,
            [noun, verb] if noun == "users" && verb == "list" => Command::UsersList,
            [noun, verb, flag] if noun == "daemon" && verb == "restart" => Command::DaemonRestart {
                confirmed: flag == "--yes",
            },
            [noun, verb] if noun == "daemon" && verb == "restart" => {
                Command::DaemonRestart { confirmed: false }
            }
            [noun, verb, flag] if noun == "daemon" && verb == "stop" => Command::DaemonStop {
                confirmed: flag == "--yes",
            },
            [noun, verb] if noun == "daemon" && verb == "stop" => {
                Command::DaemonStop { confirmed: false }
            }
            [noun, verb] if noun == "daemon" && verb == "stop-process" => {
                Command::DaemonStopProcess
            }
            [noun, verb] if noun == "daemon" && verb == "disable-startup" => {
                Command::DaemonDisableStartup
            }
            [noun, verb] if noun == "daemon" && verb == "status" => Command::DaemonDaemonStatus,
            [noun, verb, flag, mode]
                if noun == "daemon" && verb == "enable" && flag == "--mode" =>
            {
                Command::DaemonEnable { mode: mode.clone() }
            }
            [noun, verb, bundle_flag, bundle]
                if noun == "daemon" && verb == "install" && bundle_flag == "--bundle" =>
            {
                Command::Install {
                    bundle: bundle.clone(),
                    operator: None,
                }
            }
            [noun, verb, bundle_flag, bundle, operator_flag, operator]
                if noun == "daemon"
                    && verb == "install"
                    && bundle_flag == "--bundle"
                    && operator_flag == "--operator" =>
            {
                Command::Install {
                    bundle: bundle.clone(),
                    operator: Some(operator.clone()),
                }
            }
            _ => return Err("Unknown command. Run `iota --help`.".into()),
        };
        Ok(Self {
            theme_override,
            command,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_global_theme_option() {
        let invocation =
            CliInvocation::parse(["--theme".into(), "binary".into(), "status".into()]).unwrap();
        assert_eq!(invocation.theme_override, Some(ThemeName::Binary));
        assert_eq!(invocation.command, Command::Status);
    }

    #[test]
    fn reports_supported_names_for_invalid_theme() {
        let error = CliInvocation::parse(["--theme=ultraviolet".into()]).unwrap_err();
        assert!(error.contains(ThemeName::supported_names()));
    }

    #[test]
    fn parses_install_operator_without_raw_slice_matching() {
        let invocation = CliInvocation::parse([
            "daemon".into(),
            "install".into(),
            "--bundle".into(),
            "release.zip".into(),
            "--operator".into(),
            "alice".into(),
        ])
        .unwrap();
        assert_eq!(
            invocation.command,
            Command::Install {
                bundle: "release.zip".into(),
                operator: Some("alice".into()),
            }
        );
    }

    #[test]
    fn parses_unconfirmed_destructive_commands_explicitly() {
        let invocation = CliInvocation::parse(["daemon".into(), "stop".into()]).unwrap();
        assert_eq!(invocation.command, Command::DaemonStop { confirmed: false });
    }
}
