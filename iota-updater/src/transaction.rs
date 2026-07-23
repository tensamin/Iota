use crate::manifest::{Artifact, verify_artifact};
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct UpdateTransaction {
    pub root: PathBuf,
    pub staging: PathBuf,
}
impl UpdateTransaction {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            staging: root.join(".staging"),
            root,
        }
    }
    pub fn acquire(&self) -> Result<fs::File> {
        fs::create_dir_all(&self.root)?;
        let path = self.root.join("update.lock");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .context("update already in progress")?;
        Ok(file)
    }
    pub fn stage_artifact(&self, source: &Path, artifact: &Artifact) -> Result<PathBuf> {
        fs::create_dir_all(&self.staging)?;
        let target = self.staging.join(&artifact.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, &target)?;
        verify_artifact(&target, artifact)?;
        Ok(target)
    }
    pub fn activate(&self, version: &str) -> Result<()> {
        let version_dir = self.root.join("versions").join(version);
        fs::create_dir_all(version_dir.parent().unwrap())?;
        fs::rename(&self.staging, &version_dir).context("activate staged release")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_is_exclusive_and_activation_switches_current() {
        let dir = tempfile::tempdir().unwrap();
        let tx = UpdateTransaction::new(dir.path());
        let lock = tx.acquire().unwrap();
        assert!(tx.acquire().is_err());
        drop(lock);
        std::fs::create_dir_all(&tx.staging).unwrap();
        std::fs::write(tx.staging.join("manifest.json"), b"ok").unwrap();
        tx.activate("1.0.0").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("current/manifest.json")).unwrap(),
            "ok"
        );
    }
}
