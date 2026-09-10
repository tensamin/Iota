use crate::manifest::{Artifact, verify_artifact};
use anyhow::{Context, Result};
use fs2::FileExt;
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct UpdateTransaction {
    pub root: PathBuf,
    pub staging: PathBuf,
    pub lock_file: PathBuf,
}
impl UpdateTransaction {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            staging: root.join(".staging"),
            lock_file: root.join("update.lock"),
            root,
        }
    }
    pub fn from_paths(paths: &iota_paths::IotaPaths) -> Result<Self> {
        Ok(Self {
            root: paths.install_root.clone(),
            staging: paths.update_staging_dir(),
            lock_file: paths.update_lock_file().map_err(|e| anyhow::anyhow!(e))?,
        })
    }
    pub fn acquire(&self) -> Result<UpdateLock> {
        if let Some(parent) = self.lock_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_file)
            .with_context(|| format!("open update lock {}", self.lock_file.display()))?;
        file.try_lock_exclusive()
            .context("update already in progress")?;
        Ok(UpdateLock { _file: file })
    }
    pub fn stage_artifact(&self, source: &Path, artifact: &Artifact) -> Result<PathBuf> {
        let artifact_path = Path::new(&artifact.path);
        if artifact_path.is_absolute()
            || artifact_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            anyhow::bail!(
                "artifact path must be a relative file path: {}",
                artifact.path
            );
        }
        fs::create_dir_all(&self.staging)?;
        let target = self.staging.join(artifact_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, &target)?;
        verify_artifact(&target, artifact)?;
        set_executable_if_binary(&target, artifact)?;
        Ok(target)
    }
    pub fn activate(&self, version: &str) -> Result<()> {
        let version_dir = self.root.join("versions").join(version);
        fs::create_dir_all(version_dir.parent().unwrap())?;
        if version_dir.exists() {
            anyhow::bail!("release version already exists: {}", version_dir.display());
        }
        match fs::rename(&self.staging, &version_dir) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(cross_device_link_error()) => {
                copy_directory(&self.staging, &version_dir)?;
                fs::remove_dir_all(&self.staging)
                    .context("remove copied update staging directory")?;
            }
            Err(error) => return Err(error).context("activate staged release"),
        }
        let current_tmp = self.root.join("current.new");
        let _ = fs::remove_file(&current_tmp);
        std::os::unix::fs::symlink(&version_dir, &current_tmp)?;
        fs::rename(current_tmp, self.root.join("current"))?;
        Ok(())
    }
    pub fn rollback(&self, previous: &str) -> Result<()> {
        let current = self.root.join("current");
        let tmp = self.root.join("current.rollback");
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(self.root.join("versions").join(previous), &tmp)?;
        fs::rename(tmp, current)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_executable_if_binary(path: &Path, artifact: &Artifact) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if Path::new(&artifact.path)
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == "bin")
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_executable_if_binary(_path: &Path, _artifact: &Artifact) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn cross_device_link_error() -> i32 {
    18
}

#[cfg(not(unix))]
fn cross_device_link_error() -> i32 {
    -1
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("create release directory {}", destination.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_directory(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "copy staged artifact {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            fs::set_permissions(&destination_path, fs::metadata(&source_path)?.permissions())?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct UpdateLock {
    // Closing this file releases its advisory lock. The lock file stays in place
    // so a process crash cannot leave a stale create-only lock behind.
    _file: fs::File,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_is_exclusive_reusable_and_activation_switches_current() {
        let dir = tempfile::tempdir().unwrap();
        let tx = UpdateTransaction::new(dir.path());
        let lock = tx.acquire().unwrap();
        assert!(tx.acquire().is_err());
        drop(lock);
        assert!(tx.acquire().is_ok());
        assert!(tx.lock_file.exists());
        std::fs::create_dir_all(&tx.staging).unwrap();
        std::fs::write(tx.staging.join("manifest.json"), b"ok").unwrap();
        tx.activate("1.0.0").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("current/manifest.json")).unwrap(),
            "ok"
        );
    }
}
