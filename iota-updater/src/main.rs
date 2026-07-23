use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    match command.as_str() {
        "check" => println!("update check is manifest-driven"),
        "status" => println!("updater ready"),
        "apply" | "rollback" => {
            return Err(anyhow::anyhow!(
                "explicit signed transaction input is required"
            ));
        }
        _ => {
            return Err(anyhow::anyhow!(
                "usage: iota-updater check|status|apply|rollback"
            ));
        }
    }
    Ok(())
}
