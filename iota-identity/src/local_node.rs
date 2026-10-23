use super::*;

impl fmt::Display for LocalNodeIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory { path, source } => {
                write!(
                    formatter,
                    "failed to create identity directory {path}: {source}"
                )
            }
            Self::Storage { path, source } => {
                write!(formatter, "failed to access node identity {path}: {source}")
            }
            Self::Verification(error) => formatter.write_str(error),
            Self::InvalidIdentity(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LocalNodeIdentityError {}

impl fmt::Debug for LocalNodeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalNodeIdentity")
            .field("node_id", &self.node_id)
            .field("authority_id", &self.authority_id)
            .finish_non_exhaustive()
    }
}

impl LocalNodeIdentity {
    pub fn load_or_create(
        path: &Path,
        legacy: Option<mtp::crypto::Keyring>,
    ) -> Result<Self, LocalNodeIdentityError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|source| LocalNodeIdentityError::Directory {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let keyring = match tau::load_private_keyring(path) {
            Ok(Some(keyring)) => keyring,
            Ok(None) => {
                let keyring = legacy.unwrap_or_else(mtp::crypto::Keyring::generate);
                match tau::create_private_keyring(&keyring, path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Self::load_or_create(path, None);
                    }
                    Err(error) => {
                        return Err(LocalNodeIdentityError::Storage {
                            path: path.display().to_string(),
                            source: error.to_string(),
                        });
                    }
                }
                keyring
            }
            Err(error) => {
                return Err(LocalNodeIdentityError::Storage {
                    path: path.display().to_string(),
                    source: error.to_string(),
                });
            }
        };
        Self::from_keyring(keyring)
    }

    pub fn from_keyring(keyring: mtp::crypto::Keyring) -> Result<Self, LocalNodeIdentityError> {
        let node_id = IotaNodeId::from_public_keys(&keyring.public_key_bundle())
            .map_err(LocalNodeIdentityError::InvalidIdentity)?;
        let authority_id = AuthorityId::for_iota(&node_id);
        Ok(Self {
            keyring: Arc::new(keyring),
            node_id,
            authority_id,
        })
    }

    pub fn save_keyring_verified(
        keyring: &mtp::crypto::Keyring,
        path: &Path,
    ) -> Result<(), LocalNodeIdentityError> {
        tau::replace_private_keyring(keyring, path).map_err(|error| {
            LocalNodeIdentityError::Storage {
                path: path.display().to_string(),
                source: error.to_string(),
            }
        })?;
        let persisted = tau::load_private_keyring(path)
            .map_err(|error| LocalNodeIdentityError::Storage {
                path: path.display().to_string(),
                source: error.to_string(),
            })?
            .ok_or_else(|| {
                LocalNodeIdentityError::Verification("persisted keyring disappeared".into())
            })?;
        let expected = keyring
            .try_to_bytes()
            .map_err(|error| LocalNodeIdentityError::Verification(error.to_string()))?;
        let actual = persisted
            .try_to_bytes()
            .map_err(|error| LocalNodeIdentityError::Verification(error.to_string()))?;
        if expected != actual {
            return Err(LocalNodeIdentityError::Verification(
                "persisted keyring differs from requested node identity".into(),
            ));
        }
        Ok(())
    }

    pub fn keyring(&self) -> Arc<mtp::crypto::Keyring> {
        self.keyring.clone()
    }

    pub fn public_keys(&self) -> PublicKeyBundle {
        self.keyring.public_key_bundle()
    }

    pub fn node_id(&self) -> &IotaNodeId {
        &self.node_id
    }

    pub fn authority_id(&self) -> &AuthorityId {
        &self.authority_id
    }
}
