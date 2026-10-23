use super::*;

pub(super) fn print_help() {
    let color = cli_color::ColorConfig::new();
    println!("{}", cli_color::heading(&color, "Iota Operator Console"));
    println!();
    println!("Usage: iota [OPTIONS] [COMMAND]");
    println!();
    println!("{}", cli_color::info(&color, "Commands:"));
    println!("  (no command)           Launch the interactive dashboard");
    println!("  status                 Show daemon status");
    println!("  tasks                  List active tasks");
    println!("  users list             List all users");
    println!("  users show <ID>        Show user details");
    println!("  users add create <NAME> Create a new user");
    println!("  users add tu <PATH>    Attach an existing account credential");
    println!("  users data purge <ID>  Purge hosted data (requires --yes)");
    println!("  users hosting release <ID> Release from this Iota (requires --yes)");
    println!("  users account delete <ID> Delete the Tensamin account (requires --yes)");
    println!("  users repair reconcile <ID> Compare local state with Omega");
    println!("  users repair diagnostics <ID> Show local lifecycle diagnostics");
    println!("  users repair force-detach <ID> Remove local management (requires --yes)");
    println!("  users forget <ID>      Forget an empty released residency (requires --yes)");
    println!("  users apps revoke <ID> <APP> Revoke a trusted app (requires --yes)");
    println!("  users apps revoke-all <ID> Revoke all TAuth grants (requires --yes)");
    println!("  users credential export <ID> --output <PATH> Export the local TU");
    println!("  apps list              List owned TAuth apps");
    println!("  apps show <APP_ID>     Show an owned TAuth app");
    println!("  apps create ...        Create and export a TAuth app");
    println!("  apps export <APP_ID> --output <PATH> Export an existing .ta");
    println!("  apps delete <APP_ID>   Delete app key and registration (requires --yes)");
    println!("  omikron status         Show Omikron connection status");
    println!("  omikron reconnect      Reconnect to Omikron");
    println!("  identity rotate        Rotate identity keys (requires --yes)");
    println!("  config get             Show current configuration");
    println!("  config set <KEY> <VAL> Set a configuration value");
    println!("  config reload          Reload configuration");
    println!("  health                 Show component health");
    println!("  components             Show component health");
    println!("  logs [--limit N]       Show recent log entries");
    println!("  update check           Check for updates");
    println!("  update apply           Apply the selected channel's signed update");
    println!("  update channel                Show the installed update channel");
    println!("  community list         List communities");
    println!("  terms status           Show terms acceptance status");
    println!("  terms show <DOC>       Show a terms document");
    println!("  terms accept           Accept required terms");
    println!("  daemon restart         Restart the daemon (requires --yes)");
    println!("  daemon stop            Stop the daemon (requires --yes)");
    println!("  daemon enable          Enable daemon at startup");
    println!("  daemon disable-startup Disable daemon at startup");
    println!("  daemon startup-status  Show startup configuration");
    println!("  daemon start           Start the daemon");
    println!("  daemon restart-service Restart the daemon service");
    println!("  daemon stop-service    Stop the daemon service");
    println!("  daemon install         Install from a bundle");
    println!("  daemon bootstrap       Install and enable a Linux systemd bundle");
    println!("  help                   Show this help message");
    println!("  completions <SHELL>    Generate shell completions");
    println!("  man                    Show the man page");
    println!();
    println!("{}", cli_color::info(&color, "Options:"));
    println!("  --theme <THEME>        Theme: monospace, binary, ansi, surface");
    println!("  --output <FORMAT>      Output format: text, json, yaml, table");
    println!("  --color <WHEN>         Color: auto, always, never");
    println!("  --unicode <WHEN>       Unicode: auto, always, never");
    println!("  --no-color             Disable colored output");
    println!("  --yes, -y              Confirm destructive operations");
    println!("  -h, --help             Show help");
    println!("  -V, --version          Show version");
    println!();
    println!("{}", cli_color::info(&color, "Examples:"));
    println!("  iota                        Launch the interactive dashboard");
    println!("  iota status                 Show daemon status");
    println!("  iota users list --output=json   List users in JSON format");
    println!("  iota users add alice       Create a user named 'alice'");
    println!("  iota users data purge 42 --yes  Purge hosted data");
    println!("  iota config get --output=yaml   Show config in YAML format");
    println!("  iota logs --limit 50       Show last 50 log entries");
    println!("  iota completions bash      Generate bash completions");
    println!();
    println!("{}", cli_color::info(&color, "Exit Codes:"));
    println!("  0    Success");
    println!("  1    General error");
    println!("  2    Invalid command or arguments");
    println!("  130  Interrupted (Ctrl+C)");
    println!();
    println!("{}", cli_color::muted(&color, "Environment Variables:"));
    println!("  NO_COLOR      Disable colored output when set");
    println!("  TERM          Terminal type (dumb disables colors)");
    println!("  IOTA_THEME    Default theme override");
}

pub(super) fn print_completions(shell: &str) -> Result<(), StartupError> {
    let command_paths = CliInvocation::command_paths();
    let words = command_paths
        .iter()
        .flat_map(|command| command.split_whitespace())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ");
    match shell {
        "bash" => println!(
            "_iota() {{ local words='{} --help --version --theme --output --color --unicode --yes --mode --bundle --operator'; COMPREPLY=( $(compgen -W \"$words\" -- \"${{COMP_WORDS[COMP_CWORD]}}\") ); }}\ncomplete -F _iota iota",
            words
        ),
        "zsh" => println!(
            "#compdef iota\n_arguments '1:command:({})' '*::argument:->args'",
            words
        ),
        "fish" => {
            for command in words.split_whitespace() {
                println!("complete -c iota -f -a '{command}'");
            }
        }
        _ => {
            return Err(StartupError::InvalidCommand(
                "completion shell must be bash, zsh, or fish".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn print_man_page() {
    println!(".TH IOTA 1");
    println!(".SH NAME\n iota \\- Iota operator console");
    println!(".SH SYNOPSIS\n.B iota\n[global options] [command]");
    println!(".SH DESCRIPTION");
    println!("Iota is the operator console for managing Iota daemon instances.");
    println!("It provides both an interactive dashboard and headless CLI commands.");
    println!(".SH COMMANDS");
    for command in CliInvocation::command_paths() {
        println!(".TP\n.B {command}");
    }
    println!(".SH GLOBAL OPTIONS");
    println!(".TP\n.B --output text|json|yaml|table");
    println!("Set the output format for headless commands.");
    println!(".TP\n.B --color auto|always|never");
    println!("Control colored output.");
    println!(".TP\n.B --unicode auto|always|never");
    println!("Control Unicode character rendering.");
    println!(".TP\n.B --yes, -y");
    println!("Confirm destructive operations without prompting.");
    println!(".SH EXIT CODES");
    println!(".TP\n.B 0");
    println!("Success");
    println!(".TP\n.B 1");
    println!("General error");
    println!(".TP\n.B 2");
    println!("Invalid command or arguments");
    println!(".TP\n.B 130");
    println!("Interrupted (Ctrl+C)");
    println!(".SH EXAMPLES");
    println!(".TP\n.B iota");
    println!("Launch the interactive dashboard");
    println!(".TP\n.B iota status");
    println!("Show daemon status");
    println!(".TP\n.B iota users list --output=json");
    println!("List users in JSON format");
    println!(".TP\n.B iota users add alice");
    println!("Create a user named 'alice'");
    println!(".SH ENVIRONMENT");
    println!(".TP\n.B NO_COLOR");
    println!("Disable colored output when set");
    println!(".TP\n.B TERM");
    println!("Terminal type (dumb disables colors)");
    println!(".TP\n.B IOTA_THEME");
    println!("Default theme override");
}
