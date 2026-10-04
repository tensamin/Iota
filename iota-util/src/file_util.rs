use reqwest::Client;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use sysinfo::System;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use walkdir::WalkDir;
use zip::ZipArchive;

#[allow(dead_code)]
pub fn delete_directory(path: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);
    delete_dir_recursive(&dir)
}

#[allow(dead_code)]
fn delete_dir_recursive(directory: &Path) -> bool {
    if !directory.exists() {
        return false;
    }
    if let Err(e) = fs::remove_dir_all(directory) {
        println!(
            "[IMPORTANT] Couldn't delete directory {}: {}",
            directory.display(),
            e,
        );
        return false;
    }
    true
}

#[allow(dead_code)]
pub fn delete_user_directory(user_id: i64) -> io::Result<()> {
    let user_dir = Path::new(&get_directory())
        .join("users")
        .join(user_id.to_string());
    if !user_dir.exists() {
        return Ok(());
    }
    fs::remove_dir_all(user_dir)
}

fn credential_filename(username: &str) -> io::Result<String> {
    if username.is_empty()
        || username.chars().any(char::is_control)
        || username.contains(['/', '\\'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe credential owner name",
        ));
    }
    Ok(format!("{username}.tu"))
}

pub fn tauth_credential_path(app_id: &str) -> io::Result<PathBuf> {
    if app_id.len() != 64 || !app_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TAuth app ID",
        ));
    }
    Ok(storage_directory()
        .join("credentials")
        .join("apps")
        .join(format!("{}.ta", app_id.to_ascii_lowercase())))
}

pub fn read_tauth_credential(app_id: &str) -> io::Result<Option<Vec<u8>>> {
    match fs::read(tauth_credential_path(app_id)?) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn remove_tauth_credential(app_id: &str) -> io::Result<()> {
    match fs::remove_file(tauth_credential_path(app_id)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn credential_path(username: &str) -> io::Result<PathBuf> {
    credential_path_in(&storage_directory(), username)
}

fn credential_path_in(root: &Path, username: &str) -> io::Result<PathBuf> {
    Ok(root
        .join("credentials")
        .join(credential_filename(username)?))
}

fn legacy_credential_path(user_id: i64) -> io::Result<PathBuf> {
    storage_file("credentials", format!("{user_id}.tu"))
}

pub fn read_user_credential(username: &str) -> io::Result<Option<String>> {
    let path = credential_path(username)?;
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/* Resolve a credential by account id while using the owner's name for the
 * canonical filename. Older ID-based and root-level files are migrated when
 * they are encountered. */
pub fn read_user_credential_with_legacy(
    user_id: i64,
    username: &str,
) -> io::Result<Option<String>> {
    let canonical_path = credential_path(username)?;
    if let Some(credential) = read_user_credential(username)? {
        return Ok(Some(credential));
    }
    let legacy_paths = [
        legacy_credential_path(user_id)?,
        storage_file("", credential_filename(username)?)?,
    ];
    for legacy_path in legacy_paths {
        let credential = match fs::read_to_string(&legacy_path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let parsed = crate::tu::TuCredential::parse(&credential)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if parsed.user_id != user_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy credential user id mismatch",
            ));
        }
        write_user_credential(username, &parsed.to_canonical_string())?;
        if legacy_path != canonical_path {
            fs::remove_file(legacy_path)?;
        }
        return Ok(Some(parsed.to_canonical_string()));
    }
    Ok(None)
}

pub fn write_user_credential(username: &str, credential: &str) -> io::Result<()> {
    let path = credential_path(username)?;
    crate::atomic_file::replace_private(&path, credential.as_bytes(), 0)
}

pub fn remove_user_credential(user_id: i64, username: Option<&str>) -> io::Result<()> {
    let mut paths = vec![legacy_credential_path(user_id)?];
    if let Some(username) = username {
        paths.push(credential_path(username)?);
        paths.push(storage_file("", credential_filename(username)?)?);
    }

    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn load_file_buf(path: &str, name: &str) -> io::Result<BufReader<File>> {
    let file_path = storage_file(path, name)?;

    // Open the file and return a BufReader for efficient reading
    let file = File::open(&file_path)?;
    Ok(BufReader::new(file))
}
pub fn has_file(path: &str, name: &str) -> bool {
    let Ok(file_path) = storage_file(path, name) else {
        return false;
    };
    let Some(dir) = file_path.parent() else {
        return false;
    };

    if !dir.exists() {
        return false;
    }

    if !file_path.exists() {
        return false;
    }

    true
}
pub fn has_dir(path: &str) -> bool {
    let Ok(dir) = storage_child(path) else {
        return false;
    };

    if !dir.exists() {
        return false;
    }

    true
}

pub fn load_file(path: &str, name: &str) -> String {
    let Ok(file_path) = storage_file(path, name) else {
        return String::new();
    };
    let Some(dir) = file_path.parent() else {
        return String::new();
    };

    if !dir.exists() {
        return String::new();
    }

    if !file_path.exists() {
        return String::new();
    }

    let mut content = String::new();
    if let Ok(mut f) = File::open(&file_path) {
        let _ = f.read_to_string(&mut content);
    }
    content
}

pub fn load_file_vec(path: &str, name: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(storage_file(path, name)?)
}

pub fn save_file(path: &str, name: &str, value: &str) {
    if let Err(error) = try_save_file(path, name, value) {
        eprintln!("[IMPORTANT] Couldn't save file: {error}");
    }
}

pub fn try_save_file(path: &str, name: &str, value: &str) -> io::Result<()> {
    let file_path = storage_file(path, name)?;
    let dir = file_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no parent"))?;

    fs::create_dir_all(dir)?;

    // Write to a temp file first, then atomically rename to prevent partial writes.
    let tmp_name = format!(".{}.tmp", name);
    let tmp_path = dir.join(&tmp_name);
    fs::write(&tmp_path, value)?;
    if let Err(error) = fs::rename(&tmp_path, &file_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    Ok(())
}

pub fn get_children(path: &str) -> Vec<String> {
    let Ok(dir) = storage_child(path) else {
        return Vec::new();
    };
    let mut children = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            children.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    children
}

static STORAGE_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();

/// Set by the daemon immediately after resolving `IotaPaths`.  This keeps the
/// legacy storage helpers working while preventing them from independently
/// discovering a different (user-scope) directory in a system daemon.
pub fn configure_storage_directory(path: PathBuf) {
    let _ = STORAGE_DIRECTORY.set(path);
}

pub fn storage_directory() -> PathBuf {
    STORAGE_DIRECTORY.get().cloned().unwrap_or_else(|| {
        iota_paths::IotaPaths::resolve(iota_paths::Scope::User)
            .expect("resolve Iota user paths")
            .storage_dir
    })
}

/// Resolve a user supplied storage fragment without allowing it to escape the
/// resolved storage root.  Legacy call sites may use nested fragments, but
/// never absolute paths or `..` components.
pub fn storage_child(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();
    if path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe storage path",
        ));
    }
    Ok(storage_directory().join(path))
}

pub fn storage_file(path: impl AsRef<Path>, name: impl AsRef<Path>) -> io::Result<PathBuf> {
    let name = name.as_ref();
    if name.components().count() != 1 || name.is_absolute() || name == Path::new(".") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe storage file name",
        ));
    }
    storage_child(path).map(|dir| dir.join(name))
}

pub fn get_directory() -> String {
    // Legacy helpers are storage-only.  Configuration, keys, logs and runtime
    // files must use their dedicated path APIs instead.
    storage_directory().to_string_lossy().into_owned()
}

// Helper to download the zip file content to a file on disk
#[allow(dead_code)]
pub fn used_space() -> u64 {
    get_directory_size(&PathBuf::from(get_directory()))
}
pub fn used_dir_space(path: &str) -> u64 {
    get_directory_size(&PathBuf::from(format!("{}/{}", get_directory(), path)))
}

pub fn get_directory_size(directory: &Path) -> u64 {
    let mut size = 0;
    for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file()
            && let Ok(metadata) = path.metadata()
        {
            size += path.file_name().unwrap_or(OsStr::new("")).len() as u64;
            size += metadata.len();
        }
    }
    size
}

#[allow(dead_code)]
pub fn get_designed_storage(user_id: i64) -> String {
    let user_dir = Path::new(&get_directory())
        .join("users")
        .join(user_id.to_string());
    design_byte(get_directory_size(&user_dir))
}

#[allow(dead_code)]
pub fn design_byte(bytes: u64) -> String {
    let mut hr_size = format!("{:.2}B", bytes as f64);
    let k = bytes as f64 / 1024.0;
    let m = k / 1024.0;
    let g = m / 1024.0;
    let t = g / 1024.0;

    if t >= 1.0 {
        hr_size = format!("{:.2}TB", t);
    } else if g >= 1.0 {
        hr_size = format!("{:.2}GB", g);
    } else if m >= 1.0 {
        hr_size = format!("{:.2}MB", m);
    } else if k >= 1.0 {
        hr_size = format!("{:.2}KB", k);
    }
    hr_size
}

#[allow(dead_code)]
pub fn get_used_ram() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();
    let used = sys.used_memory() * 1024; // kB to bytes
    let total = sys.total_memory() * 1024;
    format!("{}/{}", design_byte(used), design_byte(total))
}

pub async fn download_zip(url: &str, zip_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let mut response = client.get(url).send().await?;

    if !response.status().is_success() {
        let err_msg = format!("Failed to download file: Status {}", response.status());
        println!("{}", err_msg.clone());
        return Err(err_msg.into());
    }

    let mut zip_file = tokio::fs::File::create(zip_path).await?;
    while let Some(chunk) = response.chunk().await? {
        zip_file.write_all(&chunk).await?;
    }

    zip_file.flush().await?;
    Ok(())
}

#[allow(dead_code, deprecated)]
fn extract_zip_contents_to_folder(
    zip_path: &Path,
    target_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    let staging_dir = target_dir.with_extension("staging");

    let _ = fs::remove_dir_all(&staging_dir);
    fs::create_dir_all(&staging_dir)?;

    let mut first_item_name: Option<PathBuf> = None;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let entry_path = staging_dir.join(file.sanitized_name());

        if i == 0 && (file.name().ends_with('/') || file.sanitized_name().components().count() == 1)
        {
            first_item_name = Some(file.sanitized_name());
        }

        if file.name().ends_with('/') {
            fs::create_dir_all(&entry_path)?;
        } else {
            if let Some(parent) = entry_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(entry_path)?;
            io::copy(&mut file, &mut out_file)?;
        }
    }

    if let Some(root_path) = first_item_name {
        let root_dir = staging_dir.join(&root_path);

        if root_dir.is_dir() {
            let root_contents_count = fs::read_dir(&staging_dir)?.count();

            if root_contents_count == 1
                || (root_contents_count > 1 && fs::metadata(&root_dir).is_ok())
            {
                let _ = fs::remove_dir_all(target_dir);
                fs::create_dir_all(target_dir)?;

                for entry in fs::read_dir(root_dir)? {
                    let entry = entry?;
                    let src = entry.path();
                    let dest = target_dir.join(entry.file_name());

                    if fs::rename(&src, &dest).is_err() {
                        if src.is_file() {
                            fs::copy(&src, &dest)?;
                        } else {
                            if entry.path().is_dir() {
                                fs::rename(&src, &dest)?;
                            }
                        }
                    }
                }

                let _ = fs::remove_dir_all(&staging_dir);
                return Ok(());
            }
        }
    }

    println!("Extracting directly (no single root folder detected).");
    let _ = fs::remove_dir_all(target_dir);
    fs::rename(&staging_dir, target_dir)?;

    Ok(())
}

#[allow(dead_code)]
pub async fn download_and_extract_zip(url: &str, as_name: &str) {
    println!("Downloading ZIP file...");
    let base_dir = PathBuf::from(get_directory());
    let zip_filename = format!("{}.zip", Uuid::new_v4());
    let zip_path = base_dir.join(&zip_filename);
    let target_dir = base_dir.join(as_name);

    if let Err(e) = download_zip(url, &zip_path).await {
        println!("Error downloading file: {}", e);
        return;
    }

    let zip_path_clone = zip_path.clone();
    let target_dir_clone = target_dir.clone();
    let extract_result = extract_zip_contents_to_folder(&zip_path_clone, &target_dir_clone);

    let successful = match extract_result {
        Ok(()) => true,
        Err(e) => {
            println!("Error during ZIP extraction: {}", e);
            false
        }
    };

    if let Err(e) = tokio::fs::remove_file(&zip_path).await {
        println!("Error cleaning up ZIP file {}: {}", zip_path.display(), e);
    } else if successful {
        println!("Downloaded and extracted ZIP file successfully.");
    }
}

#[cfg(test)]
mod tests {
    use super::credential_path_in;
    use std::path::Path;

    #[test]
    fn credential_path_uses_owner_name() {
        let path = credential_path_in(Path::new("/tmp/iota"), "alice").unwrap();
        assert!(path.ends_with("credentials/alice.tu"));
        assert!(!path.ends_with("credentials/42.tu"));
    }

    #[test]
    fn credential_path_rejects_unsafe_owner_name() {
        assert!(credential_path_in(Path::new("/tmp/iota"), "../alice").is_err());
        assert!(credential_path_in(Path::new("/tmp/iota"), "alice/bob").is_err());
    }
}
