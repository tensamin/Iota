use super::*;

pub(super) async fn run_startup_command(command: Command) -> Result<(), StartupError> {
    let manager = iota_process_manager::detect()
        .await
        .ok_or_else(|| StartupError::Other("no supported process manager detected".into()))?;
    let status = match command {
        Command::DaemonEnable { mode } => {
            let mode = match mode.as_str() {
                "socket" | "socket-activated" => iota_process_manager::StartupMode::SocketActivated,
                "always-on" => iota_process_manager::StartupMode::AlwaysOn,
                _ => {
                    return Err(StartupError::InvalidCommand(
                        "--mode must be socket or always-on".into(),
                    ));
                }
            };
            manager
                .enable_startup(mode)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?
        }
        Command::DaemonDisableStartup => manager
            .disable_startup()
            .await
            .map_err(|e| StartupError::Other(e.to_string()))?,
        Command::DaemonStartupStatus => {
            let status = manager
                .iota_startup_status()
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("service active: {}", status.service.active);
            println!("service enabled: {}", status.service.enabled);
            println!("socket active: {}", status.socket.active);
            println!("socket enabled: {}", status.socket.enabled);
            println!("detected mode: {:?}", status.detected);
            return Ok(());
        }
        Command::DaemonStart => {
            let status = manager
                .process_action(iota_process_manager::ProcessAction::Start)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("Daemon started. detected mode: {:?}", status.detected);
            return Ok(());
        }
        Command::DaemonRestartService => {
            let status = manager
                .process_action(iota_process_manager::ProcessAction::Restart)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("Daemon restarted. detected mode: {:?}", status.detected);
            return Ok(());
        }
        Command::DaemonStopService => {
            let status = manager
                .process_action(iota_process_manager::ProcessAction::Stop)
                .await
                .map_err(|e| StartupError::Other(e.to_string()))?;
            println!("Daemon stopped. detected mode: {:?}", status.detected);
            return Ok(());
        }
        _ => unreachable!(),
    };
    println!("deployment status: {:?}", status.detected);
    Ok(())
}
