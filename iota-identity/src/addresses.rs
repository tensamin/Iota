use super::*;

impl AuthorityLocator {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty authority locator".into(),
            ));
        }
        if value.contains('@') || value.contains('/') || value.chars().any(char::is_whitespace) {
            return Err(IdentityError::InvalidIdentifier(
                "invalid authority locator".into(),
            ));
        }

        if let Ok(address) = value.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err(IdentityError::InvalidIdentifier(
                    "authority port must not be zero".into(),
                ));
            }
            return Ok(Self(address.to_string()));
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(Self(address.to_string()));
        }
        if let Some(address) = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            let address = address
                .parse::<Ipv6Addr>()
                .map_err(|_| IdentityError::InvalidIdentifier("invalid IPv6 authority".into()))?;
            return Ok(Self(format!("[{address}]")));
        }

        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port.parse::<u16>().map_err(|_| {
                    IdentityError::InvalidIdentifier("invalid authority port".into())
                })?;
                if port == 0 {
                    return Err(IdentityError::InvalidIdentifier(
                        "authority port must not be zero".into(),
                    ));
                }
                (host, Some(port))
            }
            Some(_) => {
                return Err(IdentityError::InvalidIdentifier(
                    "IPv6 authorities must use brackets".into(),
                ));
            }
            None => (value, None),
        };
        if !valid_domain(host) {
            return Err(IdentityError::InvalidIdentifier(
                "invalid authority domain".into(),
            ));
        }

        let host = host.to_ascii_lowercase();
        Ok(Self(match port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_ip_literal(&self) -> bool {
        self.0.parse::<SocketAddr>().is_ok()
            || self.0.parse::<IpAddr>().is_ok()
            || self
                .0
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .is_some_and(|value| value.parse::<Ipv6Addr>().is_ok())
    }
}

impl UserAddress {
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        value.parse()
    }
}

impl FromStr for UserAddress {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty user address".into(),
            ));
        }
        if value.matches('@').count() > 1 {
            return Err(IdentityError::InvalidIdentifier(
                "user address contains multiple authority delimiters".into(),
            ));
        }

        let (local, authority) = match value.split_once('@') {
            Some((local, authority)) => {
                if authority.is_empty() {
                    return Err(IdentityError::InvalidIdentifier(
                        "empty authority locator".into(),
                    ));
                }
                (local, Some(AuthorityLocator::new(authority)?))
            }
            None => (value, None),
        };
        let (selector, public_key_pin) = match local.split_once("::") {
            Some((selector, pin)) => {
                if pin.is_empty() {
                    return Err(IdentityError::InvalidIdentifier(
                        "empty public-key pin".into(),
                    ));
                }
                let pin = PublicKeyBundle::from_base64(pin).map_err(|_| {
                    IdentityError::InvalidIdentifier("invalid public-key pin".into())
                })?;
                (selector, Some(pin))
            }
            None => (local, None),
        };
        if selector.is_empty() {
            return Err(IdentityError::InvalidIdentifier(
                "empty user selector".into(),
            ));
        }
        if selector
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '@' | ':'))
        {
            return Err(IdentityError::InvalidIdentifier(
                "invalid user selector".into(),
            ));
        }

        let selector = if selector.bytes().all(|byte| byte.is_ascii_digit()) {
            UserSelector::UserId(selector.parse::<u64>().map_err(|_| {
                IdentityError::InvalidIdentifier("numeric user ID is out of range".into())
            })?)
        } else {
            UserSelector::Username(selector.into())
        };

        Ok(Self {
            selector,
            public_key_pin,
            authority,
        })
    }
}

pub(super) fn valid_domain(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
