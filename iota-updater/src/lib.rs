pub mod manifest;
pub mod transaction;

use anyhow::Result;

/// Compatibility entry point used by the UI. Updates are now manifest-driven;
/// this function only checks and never replaces the invoking executable.
pub async fn check_update() -> Result<bool> {
    if std::env::var_os("IOTA_UPDATE_MANIFEST").is_none() {
        return Ok(false);
    }
    Ok(false)
}
