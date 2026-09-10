use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    match command.as_str() {
        "check" => println!("{}", iota_updater::check_update().await?),
        "status" => println!("updater ready"),
        "apply" => println!("{}", iota_updater::apply_update().await?),
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
