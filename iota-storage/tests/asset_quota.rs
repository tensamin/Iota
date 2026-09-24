use iota_storage::util::{config_util, db, user_assets};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[test]
fn upload_quota_reserves_and_releases_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database()?;
    let mut config = config_util::IotaConfig::default();
    config.storage_limits.max_asset_bytes = 5;
    config.storage_limits.max_user_asset_bytes = 8;
    config.storage_limits.max_active_asset_uploads_per_user = 2;
    config.storage_limits.min_free_asset_storage_bytes = 0;
    config_util::CONFIG.store(Arc::new(config));

    let hash = Sha256::digest(b"data");
    assert!(user_assets::start(42, "oversize", "a", 6, &hash, "text/plain").is_err());
    user_assets::start(42, "first", "a", 4, &hash, "text/plain")?;
    user_assets::start(42, "second", "b", 4, &hash, "text/plain")?;
    assert!(user_assets::start(42, "third", "c", 1, &hash, "text/plain").is_err());
    assert!(user_assets::abort(42, "second")?);
    user_assets::start(42, "third", "c", 1, &hash, "text/plain")?;
    user_assets::append(42, "first", 0, b"data")?;
    user_assets::commit(42, "first")?;
    assert!(user_assets::start(42, "fourth", "d", 4, &hash, "text/plain").is_err());
    assert!(user_assets::abort(42, "third")?);
    user_assets::start(42, "fourth", "d", 4, &hash, "text/plain")?;

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let attempts: Vec<_> = ["concurrent-a", "concurrent-b"]
        .into_iter()
        .map(|upload_id| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                user_assets::start(77, upload_id, upload_id, 5, &hash, "text/plain").is_ok()
            })
        })
        .collect();
    assert_eq!(
        attempts
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
    Ok(())
}
