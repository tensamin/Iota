use crate::atomic_file;
use mtp::crypto::{Keyring, PublicKeyBundle};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use url::Url;

const MAGIC: &[u8; 4] = b"TAUT";
const VERSION: u16 = 1;
const MAX_FIELD_SIZE: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub enum ConnectionMode {
    Hosted {
        omega_url: Url,
        owner_iota_id: u64,
    },
    ForcedOmikron {
        omikron_url: Url,
        omikron_public_key: PublicKeyBundle,
        owner_iota_id: u64,
    },
}

pub struct TaCredential {
    pub keyring: Keyring,
    pub owner_certificate: Vec<u8>,
    pub mode: ConnectionMode,
}

impl fmt::Debug for TaCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaCredential")
            .field("app_id", &self.app_id())
            .field("owner_certificate", &"<signed certificate>")
            .field("mode", &self.mode)
            .field("keyring", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub enum TaError {
    InvalidFormat(&'static str),
    InvalidKeyring,
    InvalidPublicKey,
    InvalidUrl,
    Io(std::io::Error),
}

impl fmt::Display for TaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(message) => write!(f, "invalid .ta credential: {message}"),
            Self::InvalidKeyring => f.write_str("invalid .ta MTP keyring"),
            Self::InvalidPublicKey => f.write_str("invalid forced Omikron public key"),
            Self::InvalidUrl => f.write_str("invalid .ta connection URL"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TaError {}

impl From<std::io::Error> for TaError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl TaCredential {
    pub fn app_id(&self) -> String {
        app_id(&self.keyring.public_key_bundle())
    }

    pub fn owner_iota_id(&self) -> u64 {
        match &self.mode {
            ConnectionMode::Hosted { owner_iota_id, .. }
            | ConnectionMode::ForcedOmikron { owner_iota_id, .. } => *owner_iota_id,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TaError> {
        let keyring = self
            .keyring
            .try_to_bytes()
            .map_err(|_| TaError::InvalidKeyring)?;
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&VERSION.to_be_bytes());
        push_bytes(&mut output, &keyring)?;
        push_bytes(&mut output, &self.owner_certificate)?;
        match &self.mode {
            ConnectionMode::Hosted {
                omega_url,
                owner_iota_id,
            } => {
                output.push(0);
                output.extend_from_slice(&owner_iota_id.to_be_bytes());
                push_bytes(&mut output, omega_url.as_str().as_bytes())?;
            }
            ConnectionMode::ForcedOmikron {
                omikron_url,
                omikron_public_key,
                owner_iota_id,
            } => {
                output.push(1);
                output.extend_from_slice(&owner_iota_id.to_be_bytes());
                push_bytes(&mut output, omikron_url.as_str().as_bytes())?;
                let public_key = omikron_public_key
                    .try_as_bytes()
                    .map_err(|_| TaError::InvalidPublicKey)?;
                push_bytes(&mut output, &public_key)?;
            }
        }
        Ok(output)
    }

    pub fn from_bytes(input: &[u8]) -> Result<Self, TaError> {
        let mut reader = Reader::new(input);
        if reader.take(4)? != MAGIC {
            return Err(TaError::InvalidFormat("bad magic"));
        }
        let version = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
        if version != VERSION {
            return Err(TaError::InvalidFormat("unsupported version"));
        }
        let keyring = Keyring::from_bytes(reader.bytes()?).map_err(|_| TaError::InvalidKeyring)?;
        let owner_certificate = reader.bytes()?.to_vec();
        if owner_certificate.is_empty() {
            return Err(TaError::InvalidFormat("missing owner certificate"));
        }
        let mode = *reader
            .take(1)?
            .first()
            .ok_or(TaError::InvalidFormat("missing connection mode"))?;
        let owner_iota_id = u64::from_be_bytes(reader.take(8)?.try_into().unwrap());
        if owner_iota_id == 0 {
            return Err(TaError::InvalidFormat("invalid owner Iota ID"));
        }
        let endpoint = parse_https_url(reader.bytes()?)?;
        let mode = match mode {
            0 => ConnectionMode::Hosted {
                omega_url: endpoint,
                owner_iota_id,
            },
            1 => ConnectionMode::ForcedOmikron {
                omikron_url: endpoint,
                omikron_public_key: PublicKeyBundle::from_bytes(reader.bytes()?)
                    .map_err(|_| TaError::InvalidPublicKey)?,
                owner_iota_id,
            },
            _ => return Err(TaError::InvalidFormat("unknown connection mode")),
        };
        if !reader.remaining().is_empty() {
            return Err(TaError::InvalidFormat("trailing bytes"));
        }
        Ok(Self {
            keyring,
            owner_certificate,
            mode,
        })
    }

    pub fn write_internal(&self, path: &Path) -> Result<(), TaError> {
        atomic_file::replace_private(path, &self.to_bytes()?, 0)?;
        Ok(())
    }

    pub fn export(&self, path: &Path) -> Result<(), TaError> {
        atomic_file::create_private(path, &self.to_bytes()?)?;
        Ok(())
    }
}

pub fn app_id(public_key: &PublicKeyBundle) -> String {
    let bytes = public_key
        .try_as_bytes()
        .expect("validated public key bundle must serialize");
    hex::encode(Sha256::digest(bytes))
}

fn parse_https_url(bytes: &[u8]) -> Result<Url, TaError> {
    let value = std::str::from_utf8(bytes).map_err(|_| TaError::InvalidUrl)?;
    let url = Url::parse(value).map_err(|_| TaError::InvalidUrl)?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(TaError::InvalidUrl);
    }
    Ok(url)
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TaError> {
    if bytes.len() > MAX_FIELD_SIZE {
        return Err(TaError::InvalidFormat("field too large"));
    }
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TaError> {
        if self.remaining.len() < length {
            return Err(TaError::InvalidFormat("truncated field"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn bytes(&mut self) -> Result<&'a [u8], TaError> {
        let length = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if length > MAX_FIELD_SIZE {
            return Err(TaError::InvalidFormat("field too large"));
        }
        self.take(length)
    }

    fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_credential_round_trip_preserves_identity() {
        let credential = TaCredential {
            keyring: Keyring::generate(),
            owner_certificate: br#"{"owner":"iota:7"}"#.to_vec(),
            mode: ConnectionMode::Hosted {
                omega_url: Url::parse("https://omega.example").unwrap(),
                owner_iota_id: 7,
            },
        };
        let app_id = credential.app_id();
        let parsed = TaCredential::from_bytes(&credential.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed.app_id(), app_id);
        assert_eq!(parsed.owner_iota_id(), 7);
    }

    #[test]
    fn export_refuses_overwrite_and_is_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("app.ta");
        let credential = TaCredential {
            keyring: Keyring::generate(),
            owner_certificate: b"certificate".to_vec(),
            mode: ConnectionMode::Hosted {
                omega_url: Url::parse("https://omega.example").unwrap(),
                owner_iota_id: 7,
            },
        };
        credential.export(&path).unwrap();
        assert!(credential.export(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
