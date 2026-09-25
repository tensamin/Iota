use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    match command.as_str() {
        "check" => println!("{}", iota_updater::check_update().await?),
        "status" => println!("updater ready"),
        "apply" => {
            struct StderrObserver;
            impl iota_updater::UpdateObserver for StderrObserver {
                fn event(&self, phase: iota_updater::UpdatePhase, product_version: Option<&str>) {
                    eprintln!("update.phase phase={phase:?} product_version={product_version:?}");
                }
            }
            println!(
                "{}",
                iota_updater::apply_update_observed(&StderrObserver).await?
            );
        }
        "rollback" => {
            let version = std::env::args()
                .nth(2)
                .ok_or_else(|| anyhow::anyhow!("usage: iota-updater rollback VERSION"))?;
            iota_updater::rollback(&version)?;
            println!("rolled back to {version}");
        }
        _ => {
            return Err(anyhow::anyhow!(
                "usage: iota-updater check|status|apply|rollback VERSION"
            ));
        }
    }
    Ok(())
}
