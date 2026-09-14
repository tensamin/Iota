use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use iota_cli::theme::{CliOutputFormat, ThemeName, UiConfig};
use iota_terms::TermsType;
use std::path::PathBuf;

#[derive(Debug)]
pub struct CliInvocation {
    pub theme_override: Option<ThemeName>,
    pub output: OutputFormat,
    pub color: CapabilityPolicy,
    pub unicode: CapabilityPolicy,
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CapabilityPolicy {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
    Table,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliTheme {
    Monospace,
    Binary,
    Ansi,
    Surface,
}
impl From<CliTheme> for ThemeName {
    fn from(value: CliTheme) -> Self {
        match value {
            CliTheme::Monospace => Self::Monospace,
            CliTheme::Binary => Self::Binary,
            CliTheme::Ansi => Self::Ansi,
            CliTheme::Surface => Self::Surface,
        }
    }
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => OutputFormat::Text,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Yaml => OutputFormat::Yaml,
            CliOutputFormat::Table => OutputFormat::Table,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "iota",
    version,
    about = "Iota operator console",
    arg_required_else_help = false
)]
struct Cli {
    #[arg(long, global = true, value_enum)]
    theme: Option<CliTheme>,
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
    #[arg(long, global = true, value_enum, default_value_t = CapabilityPolicy::Auto)]
    color: CapabilityPolicy,
    #[arg(long, global = true, value_enum, default_value_t = CapabilityPolicy::Auto)]
    unicode: CapabilityPolicy,
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    Status,
    Tasks,
    Users(UsersArgs),
    Apps(AppsArgs),
    Omikron(OmikronArgs),
    Identity(IdentityArgs),
    Daemon(DaemonArgs),
    Config(ConfigArgs),
    Terms(TermsArgs),
    RegenerateKeys {
        #[arg(long)]
        yes: bool,
    },
    Components,
    Health,
    Logs {
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    Update(UpdateArgs),
    Community(CommunityArgs),
    Completions {
        shell: String,
    },
    Man,
}
#[derive(Args, Debug)]
struct UsersArgs {
    #[command(subcommand)]
    action: UsersAction,
}

#[derive(Args, Debug)]
struct AppsArgs {
    #[command(subcommand)]
    action: AppsAction,
}

#[derive(Subcommand, Debug)]
enum AppsAction {
    List,
    Show {
        app_id: String,
    },
    Create {
        #[arg(long)]
        owner_user_id: i64,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        name: String,
        #[arg(long = "redirect", required = true)]
        redirects: Vec<String>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        manifest_output: PathBuf,
        #[command(subcommand)]
        connection: AppConnectionAction,
    },
    Export {
        app_id: String,
        #[arg(long)]
        output: PathBuf,
    },
    Delete {
        app_id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum AppConnectionAction {
    Hosted {
        #[arg(long)]
        omega_url: String,
    },
    ForcedOmikron {
        #[arg(long)]
        omikron_url: String,
        #[arg(long)]
        omikron_public_key: String,
    },
}
#[derive(Subcommand, Debug)]
enum UsersAction {
    List,
    Show {
        user_id: i64,
    },
    Add {
        #[command(subcommand)]
        action: UserAddAction,
    },
    Hosting {
        #[command(subcommand)]
        action: UserHostingAction,
    },
    Data {
        #[command(subcommand)]
        action: UserDataAction,
    },
    Account {
        #[command(subcommand)]
        action: UserAccountAction,
    },
    Repair {
        #[command(subcommand)]
        action: UserRepairAction,
    },
    Forget {
        user_id: i64,
        #[arg(long)]
        yes: bool,
    },
    Apps {
        #[command(subcommand)]
        action: UserAppsAction,
    },
    Credential {
        #[command(subcommand)]
        action: UserCredentialAction,
    },
}
#[derive(Subcommand, Debug)]
enum UserAddAction {
    Create { username: String },
    Tu { path: PathBuf },
}
#[derive(Subcommand, Debug)]
enum UserHostingAction {
    Release {
        user_id: i64,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Subcommand, Debug)]
enum UserAccountAction {
    Delete {
        user_id: i64,
        #[arg(long, value_name = "PATH")]
        tu: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Subcommand, Debug)]
enum UserRepairAction {
    Reconcile {
        user_id: i64,
    },
    Diagnostics {
        user_id: i64,
    },
    ForceDetach {
        user_id: i64,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Subcommand, Debug)]
enum UserAppsAction {
    Revoke {
        user_id: i64,
        app_id: String,
        #[arg(long)]
        yes: bool,
    },
    RevokeAll {
        user_id: i64,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Subcommand, Debug)]
enum UserCredentialAction {
    Export {
        user_id: i64,
        #[arg(
            id = "credential-destination",
            long = "destination",
            value_name = "PATH"
        )]
        output: PathBuf,
    },
}
#[derive(Subcommand, Debug)]
enum UserDataAction {
    Purge {
        user_id: i64,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Args, Debug)]
struct OmikronArgs {
    #[command(subcommand)]
    action: OmikronAction,
}
#[derive(Subcommand, Debug)]
enum OmikronAction {
    Reconnect,
    Status,
}
#[derive(Args, Debug)]
struct IdentityArgs {
    #[command(subcommand)]
    action: IdentityAction,
}
#[derive(Subcommand, Debug)]
enum IdentityAction {
    Rotate {
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Args, Debug)]
struct ConfigArgs {
    #[command(subcommand)]
    action: ConfigAction,
}
#[derive(Subcommand, Debug)]
enum ConfigAction {
    Get,
    Set { key: String, value: String },
    Reload,
}
#[derive(Args, Debug)]
struct DaemonArgs {
    #[command(subcommand)]
    action: DaemonAction,
}
#[derive(Subcommand, Debug)]
enum DaemonAction {
    Restart {
        #[arg(long)]
        yes: bool,
    },
    Stop {
        #[arg(long)]
        yes: bool,
    },
    Enable {
        #[arg(long, value_parser = ["socket", "always-on"])]
        mode: String,
    },
    DisableStartup,
    Status,
    StartupStatus,
    Start,
    RestartService,
    StopService,
    Install {
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        operator: Option<String>,
    },
    Bootstrap {
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        operator: Option<String>,
    },
}
#[derive(Args, Debug)]
struct UpdateArgs {
    #[command(subcommand)]
    action: UpdateAction,
}
#[derive(Subcommand, Debug)]
enum UpdateAction {
    Check,
}
#[derive(Args, Debug)]
struct CommunityArgs {
    #[command(subcommand)]
    action: CommunityAction,
}
#[derive(Subcommand, Debug)]
enum CommunityAction {
    List,
}
#[derive(Args, Debug)]
struct TermsArgs {
    #[command(subcommand)]
    action: TermsAction,
}
#[derive(Subcommand, Debug)]
enum TermsAction {
    Status {
        #[arg(long)]
        system: bool,
    },
    Show {
        document: TermsDocument,
    },
    Accept {
        #[arg(long)]
        system: bool,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum TermsDocument {
    Eula,
    Tos,
    Privacy,
}
impl From<TermsDocument> for TermsType {
    fn from(value: TermsDocument) -> Self {
        match value {
            TermsDocument::Eula => TermsType::EULA,
            TermsDocument::Tos => TermsType::TOS,
            TermsDocument::Privacy => TermsType::PP,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Dashboard,
    Help,
    Version,
    Completions {
        shell: String,
    },
    ManPage,
    Install {
        bundle: String,
        operator: Option<String>,
    },
    Bootstrap {
        bundle: String,
        operator: Option<String>,
    },
    Status,
    Tasks,
    UsersList,
    UsersShow {
        user_id: i64,
    },
    UsersAdd {
        username: Option<String>,
        tu: Option<PathBuf>,
    },
    UsersRelease {
        user_id: i64,
        confirmed: bool,
    },
    UsersPurgeData {
        user_id: i64,
        confirmed: bool,
    },
    UsersCompleteDelete {
        user_id: i64,
        tu: Option<PathBuf>,
        confirmed: bool,
    },
    UsersReconcile {
        user_id: i64,
    },
    UsersDiagnostics {
        user_id: i64,
    },
    UsersForceDetach {
        user_id: i64,
        confirmed: bool,
    },
    UsersForget {
        user_id: i64,
        confirmed: bool,
    },
    UsersRevokeApp {
        user_id: i64,
        app_id: String,
        confirmed: bool,
    },
    UsersRevokeAllApps {
        user_id: i64,
        confirmed: bool,
    },
    UsersExportCredential {
        user_id: i64,
        output: PathBuf,
    },
    AppsList,
    AppsShow {
        app_id: String,
    },
    AppsCreate {
        owner_user_id: i64,
        domain: String,
        name: String,
        redirects: Vec<String>,
        connection: iota_ipc::TAuthConnectionInput,
        output: PathBuf,
        manifest_output: PathBuf,
    },
    AppsExport {
        app_id: String,
        output: PathBuf,
    },
    AppsDelete {
        app_id: String,
        confirmed: bool,
    },
    OmikronReconnect,
    IdentityRotate {
        confirmed: bool,
    },
    DaemonRestart {
        confirmed: bool,
    },
    DaemonStop {
        confirmed: bool,
    },
    DaemonEnable {
        mode: String,
    },
    DaemonDisableStartup,
    DaemonDaemonStatus,
    DaemonStartupStatus,
    DaemonStart,
    DaemonRestartService,
    DaemonStopService,
    ConfigGet,
    ConfigSet {
        key: String,
        value: String,
    },
    ConfigReload,
    OmikronStatus,
    RegenerateKeys {
        confirmed: bool,
    },
    Components,
    Health,
    Logs {
        limit: usize,
    },
    UpdateCheck,
    CommunityList,
    TermsStatus {
        system: bool,
    },
    TermsShow {
        document: TermsType,
    },
    TermsAccept {
        system: bool,
    },
}
impl CliInvocation {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let args = args.into_iter().collect::<Vec<_>>();
        if args.as_slice() == ["help"] {
            return Ok(Self::special(Command::Help));
        }

        let config = UiConfig::load_or_default();
        let config_output: OutputFormat = config.cli_output.into();
        let require_confirmation = config.resolve_cli_require_confirmation();

        let parsed =
            Cli::try_parse_from(std::iter::once("iota".to_owned()).chain(args)).map_err(|error| {
                match error.kind() {
                    ErrorKind::DisplayHelp => return "__help__".to_owned(),
                    ErrorKind::DisplayVersion => return "__version__".to_owned(),
                    _ => error.to_string(),
                }
            });
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(marker) if marker == "__help__" => return Ok(Self::special(Command::Help)),
            Err(marker) if marker == "__version__" => return Ok(Self::special(Command::Version)),
            Err(error) => return Err(error),
        };

        let output = if parsed.output == OutputFormat::Text {
            config_output
        } else {
            parsed.output
        };

        let resolve_confirmed = |yes_flag: bool| -> bool {
            if yes_flag {
                return true;
            }
            !require_confirmation
        };

        let command = match parsed.command {
            None => Command::Dashboard,
            Some(CliCommand::Status) => Command::Status,
            Some(CliCommand::Tasks) => Command::Tasks,
            Some(CliCommand::Components) => Command::Components,
            Some(CliCommand::Health) => Command::Health,
            Some(CliCommand::Completions { shell }) => Command::Completions { shell },
            Some(CliCommand::Man) => Command::ManPage,
            Some(CliCommand::Users(users)) => match users.action {
                UsersAction::List => Command::UsersList,
                UsersAction::Show { user_id } => Command::UsersShow { user_id },
                UsersAction::Add {
                    action: UserAddAction::Create { username },
                } => Command::UsersAdd {
                    username: Some(username),
                    tu: None,
                },
                UsersAction::Add {
                    action: UserAddAction::Tu { path },
                } => Command::UsersAdd {
                    username: None,
                    tu: Some(path),
                },
                UsersAction::Hosting {
                    action: UserHostingAction::Release { user_id, yes },
                } => Command::UsersRelease {
                    user_id,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Data {
                    action: UserDataAction::Purge { user_id, yes },
                } => Command::UsersPurgeData {
                    user_id,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Account {
                    action: UserAccountAction::Delete { user_id, tu, yes },
                } => Command::UsersCompleteDelete {
                    user_id,
                    tu,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Repair {
                    action: UserRepairAction::Reconcile { user_id },
                } => Command::UsersReconcile { user_id },
                UsersAction::Repair {
                    action: UserRepairAction::Diagnostics { user_id },
                } => Command::UsersDiagnostics { user_id },
                UsersAction::Repair {
                    action: UserRepairAction::ForceDetach { user_id, yes },
                } => Command::UsersForceDetach {
                    user_id,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Forget { user_id, yes } => Command::UsersForget {
                    user_id,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Apps {
                    action:
                        UserAppsAction::Revoke {
                            user_id,
                            app_id,
                            yes,
                        },
                } => Command::UsersRevokeApp {
                    user_id,
                    app_id,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Apps {
                    action: UserAppsAction::RevokeAll { user_id, yes },
                } => Command::UsersRevokeAllApps {
                    user_id,
                    confirmed: resolve_confirmed(yes),
                },
                UsersAction::Credential {
                    action: UserCredentialAction::Export { user_id, output },
                } => Command::UsersExportCredential { user_id, output },
            },
            Some(CliCommand::Apps(apps)) => match apps.action {
                AppsAction::List => Command::AppsList,
                AppsAction::Show { app_id } => Command::AppsShow { app_id },
                AppsAction::Create {
                    owner_user_id,
                    domain,
                    name,
                    redirects,
                    output,
                    manifest_output,
                    connection,
                } => Command::AppsCreate {
                    owner_user_id,
                    domain,
                    name,
                    redirects,
                    connection: match connection {
                        AppConnectionAction::Hosted { omega_url } => {
                            iota_ipc::TAuthConnectionInput::Hosted { omega_url }
                        }
                        AppConnectionAction::ForcedOmikron {
                            omikron_url,
                            omikron_public_key,
                        } => iota_ipc::TAuthConnectionInput::ForcedOmikron {
                            omikron_url,
                            omikron_public_key,
                        },
                    },
                    output,
                    manifest_output,
                },
                AppsAction::Export { app_id, output } => Command::AppsExport { app_id, output },
                AppsAction::Delete { app_id, yes } => Command::AppsDelete {
                    app_id,
                    confirmed: resolve_confirmed(yes),
                },
            },
            Some(CliCommand::Omikron(omikron)) => match omikron.action {
                OmikronAction::Reconnect => Command::OmikronReconnect,
                OmikronAction::Status => Command::OmikronStatus,
            },
            Some(CliCommand::Identity(identity)) => match identity.action {
                IdentityAction::Rotate { yes } => Command::IdentityRotate {
                    confirmed: resolve_confirmed(yes),
                },
            },
            Some(CliCommand::Config(config)) => match config.action {
                ConfigAction::Get => Command::ConfigGet,
                ConfigAction::Set { key, value } => Command::ConfigSet { key, value },
                ConfigAction::Reload => Command::ConfigReload,
            },
            Some(CliCommand::RegenerateKeys { yes }) => Command::RegenerateKeys {
                confirmed: resolve_confirmed(yes),
            },
            Some(CliCommand::Logs { limit }) => Command::Logs { limit },
            Some(CliCommand::Update(update)) => match update.action {
                UpdateAction::Check => Command::UpdateCheck,
            },
            Some(CliCommand::Community(community)) => match community.action {
                CommunityAction::List => Command::CommunityList,
            },
            Some(CliCommand::Terms(terms)) => match terms.action {
                TermsAction::Status { system } => Command::TermsStatus { system },
                TermsAction::Show { document } => Command::TermsShow {
                    document: document.into(),
                },
                TermsAction::Accept { system } => Command::TermsAccept { system },
            },
            Some(CliCommand::Daemon(daemon)) => match daemon.action {
                DaemonAction::Restart { yes } => Command::DaemonRestart {
                    confirmed: resolve_confirmed(yes),
                },
                DaemonAction::Stop { yes } => Command::DaemonStop {
                    confirmed: resolve_confirmed(yes),
                },
                DaemonAction::Enable { mode } => Command::DaemonEnable { mode },
                DaemonAction::DisableStartup => Command::DaemonDisableStartup,
                DaemonAction::Status => Command::DaemonDaemonStatus,
                DaemonAction::StartupStatus => Command::DaemonStartupStatus,
                DaemonAction::Start => Command::DaemonStart,
                DaemonAction::RestartService => Command::DaemonRestartService,
                DaemonAction::StopService => Command::DaemonStopService,
                DaemonAction::Install { bundle, operator } => Command::Install { bundle, operator },
                DaemonAction::Bootstrap { bundle, operator } => {
                    Command::Bootstrap { bundle, operator }
                }
            },
        };
        Ok(Self {
            theme_override: parsed.theme.map(Into::into),
            output,
            color: if parsed.no_color {
                CapabilityPolicy::Never
            } else {
                parsed.color
            },
            unicode: parsed.unicode,
            command,
        })
    }

    fn special(command: Command) -> Self {
        Self {
            theme_override: None,
            output: OutputFormat::Text,
            color: CapabilityPolicy::Auto,
            unicode: CapabilityPolicy::Auto,
            command,
        }
    }

    #[allow(unused)]
    pub fn help_text() -> String {
        Cli::command().render_long_help().to_string()
    }

    pub fn command_paths() -> Vec<String> {
        fn collect(command: &clap::Command, prefix: &str, paths: &mut Vec<String>) {
            for subcommand in command.get_subcommands() {
                let path = if prefix.is_empty() {
                    subcommand.get_name().to_owned()
                } else {
                    format!("{prefix} {}", subcommand.get_name())
                };
                if subcommand.get_subcommands().next().is_some() {
                    collect(subcommand, &path, paths);
                } else {
                    paths.push(path);
                }
            }
        }
        let command = Cli::command();
        let mut paths = Vec::new();
        collect(&command, "", &mut paths);
        paths
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
    fn parses_structured_output_as_a_global_option() {
        let invocation =
            CliInvocation::parse(["users".into(), "list".into(), "--output=json".into()]).unwrap();
        assert_eq!(invocation.output, OutputFormat::Json);
        assert_eq!(invocation.command, Command::UsersList);
    }

    #[test]
    fn parses_health() {
        let invocation = CliInvocation::parse(["health".into()]).unwrap();
        assert_eq!(invocation.command, Command::Health);
    }

    #[test]
    fn parses_terminal_capability_overrides() {
        let invocation =
            CliInvocation::parse(["--color=never".into(), "--unicode".into(), "always".into()])
                .unwrap();
        assert_eq!(invocation.color, CapabilityPolicy::Never);
        assert_eq!(invocation.unicode, CapabilityPolicy::Always);
        assert_eq!(invocation.command, Command::Dashboard);
    }

    #[test]
    fn no_color_is_a_compatible_alias() {
        let invocation = CliInvocation::parse(["--no-color".into()]).unwrap();
        assert_eq!(invocation.color, CapabilityPolicy::Never);
    }

    #[test]
    fn supports_standard_help_and_version_flags() {
        assert_eq!(
            CliInvocation::parse(["-h".into()]).unwrap().command,
            Command::Help
        );
        assert_eq!(
            CliInvocation::parse(["--version".into()]).unwrap().command,
            Command::Version
        );
    }

    #[test]
    fn command_schema_drives_help_and_completion_paths() {
        let paths = CliInvocation::command_paths();
        assert!(paths.contains(&"users hosting release".to_owned()));
        assert!(paths.contains(&"users add create".to_owned()));
        assert!(paths.contains(&"daemon install".to_owned()));
        let help = CliInvocation::help_text();
        assert!(help.contains("users"));
        assert!(help.contains("--output"));
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
    fn parses_bootstrap_operator() {
        let invocation = CliInvocation::parse([
            "daemon".into(),
            "bootstrap".into(),
            "--bundle".into(),
            "release.zip".into(),
            "--operator".into(),
            "alice".into(),
        ])
        .unwrap();
        assert_eq!(
            invocation.command,
            Command::Bootstrap {
                bundle: "release.zip".into(),
                operator: Some("alice".into()),
            }
        );
    }

    #[test]
    fn parses_unconfirmed_destructive_commands_explicitly() {
        let invocation = CliInvocation::parse(["daemon".into(), "stop".into()]).unwrap();
        assert_eq!(invocation.command, Command::DaemonStop { confirmed: true });
    }

    #[test]
    fn parses_users_add() {
        let invocation = CliInvocation::parse([
            "users".into(),
            "add".into(),
            "create".into(),
            "alice".into(),
        ])
        .unwrap();
        assert_eq!(
            invocation.command,
            Command::UsersAdd {
                username: Some("alice".into()),
                tu: None,
            }
        );
    }

    #[test]
    fn rejects_malformed_users_add_shape() {
        assert!(
            CliInvocation::parse([
                "users".into(),
                "incorrect".into(),
                "add".into(),
                "alice".into()
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_destructive_option() {
        assert!(CliInvocation::parse(["daemon".into(), "stop".into(), "--later".into()]).is_err());
    }

    #[test]
    fn rejects_ambiguous_users_remove() {
        let error =
            CliInvocation::parse(["users".into(), "remove".into(), "42".into()]).unwrap_err();
        assert!(error.contains("remove"));
    }

    #[test]
    fn parses_users_release_with_confirmation() {
        let invocation = CliInvocation::parse([
            "users".into(),
            "hosting".into(),
            "release".into(),
            "42".into(),
            "--yes".into(),
        ])
        .unwrap();
        assert_eq!(
            invocation.command,
            Command::UsersRelease {
                user_id: 42,
                confirmed: true,
            }
        );
    }

    #[test]
    fn parses_credential_export_with_required_destination() {
        let invocation = CliInvocation::parse([
            "users".into(),
            "credential".into(),
            "export".into(),
            "42".into(),
            "--destination".into(),
            "alice.tu".into(),
        ])
        .unwrap();
        assert_eq!(
            invocation.command,
            Command::UsersExportCredential {
                user_id: 42,
                output: PathBuf::from("alice.tu"),
            }
        );
    }

    #[test]
    fn credential_export_rejects_a_missing_destination() {
        assert!(
            CliInvocation::parse([
                "users".into(),
                "credential".into(),
                "export".into(),
                "42".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_omikron_reconnect() {
        let invocation = CliInvocation::parse(["omikron".into(), "reconnect".into()]).unwrap();
        assert_eq!(invocation.command, Command::OmikronReconnect);
    }

    #[test]
    fn parses_identity_rotate_requires_yes() {
        let invocation = CliInvocation::parse(["identity".into(), "rotate".into()]).unwrap();
        assert_eq!(
            invocation.command,
            Command::IdentityRotate { confirmed: true }
        );
        let invocation =
            CliInvocation::parse(["identity".into(), "rotate".into(), "--yes".into()]).unwrap();
        assert_eq!(
            invocation.command,
            Command::IdentityRotate { confirmed: true }
        );
    }

    #[test]
    fn rejects_daemon_ping_until_protocol_supports_a_ping_contract() {
        assert!(CliInvocation::parse(["daemon".into(), "ping".into()]).is_err());
    }

    #[test]
    fn rejects_daemon_diagnostics_until_protocol_supports_diagnostics() {
        assert!(CliInvocation::parse(["daemon".into(), "diagnostics".into()]).is_err());
    }
}
