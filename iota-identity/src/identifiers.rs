use super::*;

impl IotaNodeId {
    pub(super) const PREFIX: &'static str = "iota:v1:";

    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let Some(fingerprint) = value.strip_prefix(Self::PREFIX) else {
            return Err(IdentityError::InvalidIdentifier(
                "Iota node ID has an unsupported format".into(),
            ));
        };
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IdentityError::InvalidIdentifier(
                "Iota node ID fingerprint must be 32 hexadecimal bytes".into(),
            ));
        }
        Ok(Self(format!(
            "{}{}",
            Self::PREFIX,
            fingerprint.to_ascii_lowercase()
        )))
    }

    pub fn from_public_keys(keys: &PublicKeyBundle) -> Result<Self, IdentityError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(format!("{}{fingerprint}", Self::PREFIX))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn mtp_authentication_hint(&self) -> u64 {
        let fingerprint = self.0.strip_prefix(Self::PREFIX).unwrap_or_default();
        u64::from_str_radix(&fingerprint[..fingerprint.len().min(16)], 16).unwrap_or_default()
            | (1_u64 << 63)
    }
}

impl RelayRouterId {
    pub(super) const PREFIX: &'static str = "router:v1:";

    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let Some(fingerprint) = value.strip_prefix(Self::PREFIX) else {
            return Err(IdentityError::InvalidIdentifier(
                "relay router ID has an unsupported format".into(),
            ));
        };
        if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IdentityError::InvalidIdentifier(
                "relay router ID fingerprint must be 32 hexadecimal bytes".into(),
            ));
        }
        Ok(Self(format!(
            "{}{}",
            Self::PREFIX,
            fingerprint.to_ascii_lowercase()
        )))
    }

    pub fn from_public_keys(keys: &PublicKeyBundle) -> Result<Self, IdentityError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(format!("{}{fingerprint}", Self::PREFIX))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AuthorityId {
    pub fn new(fingerprint: impl Into<String>) -> Result<Self, IdentityError> {
        let fingerprint = fingerprint.into();
        if fingerprint.trim().is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty authority ID".into(),
            ));
        }
        Ok(Self(fingerprint))
    }

    pub fn omega_legacy(locator: &str) -> Result<Self, IdentityError> {
        let locator = locator.trim().to_ascii_lowercase();
        if locator.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty Omega authority locator".into(),
            ));
        }
        Ok(Self(format!("omega:{locator}")))
    }

    pub fn for_omega(keys: &PublicKeyBundle) -> Result<Self, IdentityError> {
        let bytes = keys
            .try_as_bytes()
            .map_err(|error| IdentityError::InvalidIdentifier(error.to_string()))?;
        let fingerprint = mtp::crypto::sha256(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::new(format!("omega-key:{fingerprint}"))
    }

    pub fn for_iota(node: &IotaNodeId) -> Self {
        Self(format!("authority:{}", node.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
