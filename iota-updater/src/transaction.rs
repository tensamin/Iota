use crate::manifest::{Artifact, verify_artifact};
use anyhow::{Context, Result};
use fs2::FileExt;
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Activation {
    pub previous_target: PathBuf,
    pub new_target: PathBuf,
}

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
    pub fn current_target(&self) -> Result<PathBuf> {
        let current = self.root.join("current");
        fs::read_link(&current)
            .with_context(|| format!("read current release link {}", current.display()))
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
    pub fn activate(&self, version: &str) -> Result<Activation> {
        let current = self.root.join("current");
        let previous_target = self.current_target()?;
        let version_dir = self.root.join("versions").join(version);
        fs::create_dir_all(
            version_dir
                .parent()
                .context("release version directory has no parent")?,
        )?;
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
        replace_symlink(&current, &version_dir, &self.root.join("current.new"))?;
        Ok(Activation {
            previous_target,
            new_target: version_dir,
        })
    }
    pub fn restore_activation(&self, activation: &Activation) -> Result<()> {
        replace_symlink(
            &self.root.join("current"),
            &activation.previous_target,
            &self.root.join("current.rollback"),
        )
    }
    pub fn rollback(&self, previous: &str) -> Result<()> {
        replace_symlink(
            &self.root.join("current"),
            &self.root.join("versions").join(previous),
            &self.root.join("current.rollback"),
        )
    }
}

#[cfg(unix)]
fn replace_symlink(link: &Path, target: &Path, temporary: &Path) -> Result<()> {
    match fs::remove_file(temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove stale temporary release link"),
    }
    std::os::unix::fs::symlink(target, temporary).with_context(|| {
        format!(
            "create temporary symlink {} -> {}",
            temporary.display(),
            target.display()
        )
    })?;
    fs::rename(temporary, link).with_context(|| format!("replace symlink {}", link.display()))?;
    Ok(())
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
        let old_release = dir.path().join("versions/0.9.0");
        std::fs::create_dir_all(&old_release).unwrap();
        std::os::unix::fs::symlink(&old_release, dir.path().join("current")).unwrap();
        std::fs::create_dir_all(&tx.staging).unwrap();
        std::fs::write(tx.staging.join("manifest.json"), b"ok").unwrap();
        let activation = tx.activate("1.0.0").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("current/manifest.json")).unwrap(),
            "ok"
        );
        assert_eq!(activation.previous_target, old_release);
        tx.restore_activation(&activation).unwrap();
        assert_eq!(
            std::fs::read_link(dir.path().join("current")).unwrap(),
            old_release
        );
    }
}
