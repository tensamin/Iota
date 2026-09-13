/* Strict parsing and storage-independent handling of user credentials. A
 * `.tu` file is identified by the account ID in its contents, while storage
 * names the file after its owner's username. */

use crate::crypto_helper::{keyring_from_base64, keyring_to_base64};
use iota_identity::{AuthorityId, IotaNodeId, PrincipalId};
use mtp::crypto::{Keyring, PublicKeyBundle};
use std::fmt;

pub const MAX_PROTOCOL_ID: i64 = (1_i64 << 48) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuError {
    InvalidFormat,
    InvalidUserId,
    InvalidKeyring,
    InvalidAuthority,
}

impl fmt::Display for TuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid .tu credential format",
            Self::InvalidUserId => "invalid .tu user id",
            Self::InvalidKeyring => "invalid .tu keyring",
            Self::InvalidAuthority => "invalid .tu authority",
        })
    }
}

impl std::error::Error for TuError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TuAuthority {
    Omega(String),
    Iota(IotaNodeId),
}

pub struct TuCredential {
    pub user_id: i64,
    pub authority: TuAuthority,
    pub keyring: Keyring,
}

impl fmt::Debug for TuCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TuCredential")
            .field("user_id", &self.user_id)
            .field("authority", &self.authority)
            .field("keyring", &"<redacted>")
            .finish()
    }
}

impl TuCredential {
    pub fn parse(input: &str) -> Result<Self, TuError> {
        if let Some(versioned) = input.trim().strip_prefix("tensamin-tu:v2:") {
            return Self::parse_v2(versioned);
        }
        Self::parse_v1(input)
    }

    fn parse_v1(input: &str) -> Result<Self, TuError> {
        let (identity, encoded_keyring) = input
            .trim()
            .split_once("::")
            .ok_or(TuError::InvalidFormat)?;
        if encoded_keyring.is_empty() || encoded_keyring.contains("::") {
            return Err(TuError::InvalidFormat);
        }
        let (user_id, omega_host) = identity.split_once('@').ok_or(TuError::InvalidFormat)?;
        if omega_host.trim().is_empty() || omega_host.contains('@') {
            return Err(TuError::InvalidFormat);
        }
        let user_id = user_id.parse::<i64>().map_err(|_| TuError::InvalidUserId)?;
        if !(1..=MAX_PROTOCOL_ID).contains(&user_id) {
            return Err(TuError::InvalidUserId);
        }
        let keyring = keyring_from_base64(encoded_keyring).ok_or(TuError::InvalidKeyring)?;
        Ok(Self {
            user_id,
            authority: TuAuthority::Omega(omega_host.trim().to_owned()),
            keyring,
        })
    }

    fn parse_v2(input: &str) -> Result<Self, TuError> {
        let (identity, encoded_keyring) = input.split_once("::").ok_or(TuError::InvalidFormat)?;
        if encoded_keyring.is_empty() || encoded_keyring.contains("::") {
            return Err(TuError::InvalidFormat);
        }
        let (user_id, node_id) = identity.split_once('@').ok_or(TuError::InvalidFormat)?;
        if node_id.contains('@') {
            return Err(TuError::InvalidFormat);
        }
        let user_id = user_id.parse::<i64>().map_err(|_| TuError::InvalidUserId)?;
        if !(1..=MAX_PROTOCOL_ID).contains(&user_id) {
            return Err(TuError::InvalidUserId);
        }
        let node_id = IotaNodeId::new(node_id).map_err(|_| TuError::InvalidAuthority)?;
        let keyring = keyring_from_base64(encoded_keyring).ok_or(TuError::InvalidKeyring)?;
        Ok(Self {
            user_id,
            authority: TuAuthority::Iota(node_id),
            keyring,
        })
    }

    pub fn omega_host(&self) -> Option<&str> {
        match &self.authority {
            TuAuthority::Omega(host) => Some(host),
            TuAuthority::Iota(_) => None,
        }
    }

    pub fn principal(&self) -> Result<PrincipalId, TuError> {
        let user_id = u64::try_from(self.user_id).map_err(|_| TuError::InvalidUserId)?;
        let authority = match &self.authority {
            TuAuthority::Omega(host) => {
                AuthorityId::omega_legacy(host).map_err(|_| TuError::InvalidAuthority)?
            }
            TuAuthority::Iota(node) => AuthorityId::for_iota(node),
        };
        Ok(PrincipalId { authority, user_id })
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        self.keyring.public_key_bundle()
    }

    pub fn to_canonical_string(&self) -> String {
        match &self.authority {
            TuAuthority::Omega(host) => format!(
                "{}@{}::{}",
                self.user_id,
                host,
                keyring_to_base64(&self.keyring)
            ),
            TuAuthority::Iota(node) => format!(
                "tensamin-tu:v2:{}@{}::{}",
                self.user_id,
                node.as_str(),
                keyring_to_base64(&self.keyring)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_helper::generate_keyring;

    #[test]
    fn round_trip_is_canonical() {
        let credential = TuCredential {
            user_id: 42,
            authority: TuAuthority::Omega("omega.example:443".into()),
            keyring: generate_keyring(),
        };
        let parsed = TuCredential::parse(&credential.to_canonical_string()).unwrap();
        assert_eq!(parsed.user_id, 42);
        assert_eq!(parsed.omega_host(), Some("omega.example:443"));
        assert_eq!(
            parsed.to_canonical_string(),
            credential.to_canonical_string()
        );
    }

    #[test]
    fn decentralized_round_trip_preserves_principal() {
        let node = iota_identity::LocalNodeIdentity::from_keyring(generate_keyring())
            .unwrap()
            .node_id()
            .clone();
        let credential = TuCredential {
            user_id: 7,
            authority: TuAuthority::Iota(node.clone()),
            keyring: generate_keyring(),
        };
        let parsed = TuCredential::parse(&credential.to_canonical_string()).unwrap();
        assert_eq!(parsed.authority, TuAuthority::Iota(node.clone()));
        assert_eq!(
            parsed.principal().unwrap().authority,
            AuthorityId::for_iota(&node)
        );
    }

    #[test]
    fn rejects_malformed_credentials() {
        for value in [
            "",
            "1@omega",
            "@omega::abc",
            "0@omega::abc",
            "281474976710656@omega::abc",
            "1@::abc",
            "1@omega::abc::def",
        ] {
            assert!(TuCredential::parse(value).is_err(), "{value}");
        }
    }
}
