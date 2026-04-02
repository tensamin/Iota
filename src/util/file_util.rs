use reqwest::Client;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use sysinfo::System;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use walkdir::WalkDir;
use zip::ZipArchive;

use crate::log;

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
        log!(
            "[IMPORTANT] Couldn't delete directory {}: {}",
            directory.display(),
            e,
        );
        return false;
    }
    true
}

#[allow(dead_code)]
pub fn delete_user_directory(user_id: i64) {
    let user_dir = Path::new(&get_directory())
        .join("users")
        .join(user_id.to_string());
    let _ = delete_dir_recursive(&user_dir);
}

pub fn load_file_buf(path: &str, name: &str) -> io::Result<BufReader<File>> {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    // Ensure the directory exists, create if necessary
    if !dir.exists() {
        if let Err(_) = fs::create_dir_all(&dir) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Directory creation failed",
            ));
        }
    }

    // Create the file if it doesn't exist
    if !file_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "File creation failed",
        ));
    }

    // Open the file and return a BufReader for efficient reading
    let file = File::open(&file_path)?;
    Ok(BufReader::new(file))
}
pub fn has_file(path: &str, name: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        return false;
    }

    if !file_path.exists() {
        return false;
    }

    true
}
pub fn has_dir(path: &str) -> bool {
    let dir = Path::new(&get_directory()).join(path);

    if !dir.exists() {
        return false;
    }

    true
}

pub fn load_file(path: &str, name: &str) -> String {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!("[IMPORTANT] Couldn't create directories: {}", e);
            return String::new();
        }
        return String::new();
    }

    if !file_path.exists() {
        if let Err(e) = File::create(&file_path) {
            log!("[IMPORTANT] Couldn't create file: {}", e);
        }
        return String::new();
    }

    let mut content = String::new();
    if let Ok(mut f) = File::open(&file_path) {
        let _ = f.read_to_string(&mut content);
    }
    content
}

pub fn load_file_vec(path: &str, name: &str) -> Result<Vec<u8>, std::io::Error> {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    std::fs::read(file_path)
}

pub fn save_file(path: &str, name: &str, value: &str) {
    let dir = Path::new(&get_directory()).join(path);
    let file_path = dir.join(name);

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!("[IMPORTANT] Couldn't create directories: {}", e);
            return;
        }
    }

    if let Err(e) = fs::write(&file_path, value) {
        log!(
            "[IMPORTANT] Couldn't write file {}: {}",
            file_path.display(),
            e
        );
    }
}

pub fn get_children(path: &str) -> Vec<String> {
    let dir = Path::new(&get_directory()).join(path);
    let mut children = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                children.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    children
}

pub fn get_directory() -> String {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .unwrap_or(Path::new("."))
        .to_string_lossy()
        .to_string()
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
        if path.is_file() {
            if let Ok(metadata) = path.metadata() {
                size += path.file_name().unwrap_or(OsStr::new("")).len() as u64;
                size += metadata.len();
            }
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
        log!("{}", err_msg.clone());
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

        if i == 0 {
            if file.name().ends_with('/') || file.sanitized_name().components().count() == 1 {
                first_item_name = Some(file.sanitized_name());
            }
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

                    if let Err(_) = fs::rename(&src, &dest) {
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

    log!("Extracting directly (no single root folder detected).");
    let _ = fs::remove_dir_all(target_dir);
    fs::rename(&staging_dir, target_dir)?;

    Ok(())
}

#[allow(dead_code)]
pub async fn download_and_extract_zip(url: &str, as_name: &str) {
    log!("Downloading ZIP file...");
    let base_dir = PathBuf::from(get_directory());
    let zip_filename = format!("{}.zip", Uuid::new_v4());
    let zip_path = base_dir.join(&zip_filename);
    let target_dir = base_dir.join(as_name);

    if let Err(e) = download_zip(url, &zip_path).await {
        log!("Error downloading file: {}", e);
        return;
    }

    let zip_path_clone = zip_path.clone();
    let target_dir_clone = target_dir.clone();
    let extract_result = extract_zip_contents_to_folder(&zip_path_clone, &target_dir_clone);

    let successful = match extract_result {
        Ok(()) => true,
        Err(e) => {
            log!("Error during ZIP extraction: {}", e);
            false
        }
    };

    if let Err(e) = tokio::fs::remove_file(&zip_path).await {
        log!("Error cleaning up ZIP file {}: {}", zip_path.display(), e);
    } else if successful {
        log!("Downloaded and extracted ZIP file successfully.");
    }
}
