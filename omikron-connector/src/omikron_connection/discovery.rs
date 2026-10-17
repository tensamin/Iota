use super::*;

impl OmikronConnection {
    // Refresh discovery on every attempt. Pin keys per Omikron ID, and persist
    // discovery data only after MTP authentication. Environment overrides remain
    // available for local development without Omega.
    pub(super) async fn resolve_omikron_endpoint(
        &self,
        existing_iota_id: Option<u64>,
    ) -> Result<ResolvedOmikronEndpoint, String> {
        if let (Ok(host), Ok(port_str)) = (env::var("OMIKRON_HOST"), env::var("OMIKRON_PORT")) {
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("Invalid OMIKRON_PORT: {}", port_str))?;
            let key_path = Path::new("omikron.mpkb");
            let public_key = mtp::files::load_public_key_bundle(key_path)
                .map_err(|e| {
                    format!(
                        "Failed to load Omikron public key bundle from {}: {}. Obtain {} from the Omikron operator and place it at that path.",
                        key_path.display(), e, key_path.display()
                    )
                })?;
            return Ok(ResolvedOmikronEndpoint {
                id: None,
                host,
                port,
                public_key,
            });
        }

        let cached_endpoint = {
            let conf = CONFIG.load();
            match (&conf.omikron_id, &conf.omikron_host, conf.omikron_port) {
                (Some(id), Some(host), Some(port)) if !host.trim().is_empty() && port != 0 => {
                    mtp::files::load_public_key_bundle(omikron_public_key_path(*id))
                        .ok()
                        .map(|public_key| ResolvedOmikronEndpoint {
                            id: Some(*id),
                            host: host.clone(),
                            port,
                            public_key,
                        })
                }
                (Some(_), Some(_), Some(_)) => {
                    log!("Ignoring invalid cached Omikron endpoint in Iota configuration");
                    None
                }
                (None, Some(host), Some(port)) if !host.trim().is_empty() && port != 0 => {
                    mtp::files::load_public_key_bundle(legacy_omikron_public_key_path())
                        .ok()
                        .map(|public_key| ResolvedOmikronEndpoint {
                            id: None,
                            host: host.clone(),
                            port,
                            public_key,
                        })
                }
                _ => None,
            }
        };

        let discovered = match existing_iota_id {
            Some(id) => match omega_discovery::discover_primary(id).await {
                Ok(endpoint) => Some(endpoint),
                Err(e) => {
                    log!(
                        "Sticky Omikron discovery failed ({}), falling back to a random Omikron",
                        e
                    );
                    omega_discovery::discover_random().await.ok()
                }
            },
            None => omega_discovery::discover_random().await.ok(),
        };

        let endpoint = if let Some(endpoint) = discovered {
            let key_path = omikron_public_key_path(endpoint.id);
            match mtp::files::load_public_key_bundle(&key_path).ok() {
                Some(cached) => {
                    let keys_match =
                        match (cached.try_as_bytes(), endpoint.public_key.try_as_bytes()) {
                            (Ok(cached_bytes), Ok(discovered_bytes)) => {
                                cached_bytes == discovered_bytes
                            }
                            _ => false,
                        };
                    if !keys_match {
                        log!(
                            "Fetched Omikron public key differs from the trusted {}. \
                             Omikron key rotation requires an explicit trust refresh.",
                            key_path.display(),
                        );
                        return Err(format!(
                            "Omega returned a changed public key for Omikron {}",
                            endpoint.id
                        ));
                    } else {
                        ResolvedOmikronEndpoint {
                            id: Some(endpoint.id),
                            host: endpoint.host,
                            port: endpoint.port,
                            public_key: cached,
                        }
                    }
                }
                None => ResolvedOmikronEndpoint {
                    id: Some(endpoint.id),
                    host: endpoint.host,
                    port: endpoint.port,
                    public_key: endpoint.public_key,
                },
            }
        } else if let Some(cached) = cached_endpoint {
            log!(
                "Omega discovery unreachable, falling back to last-known Omikron {}:{}",
                cached.host,
                cached.port
            );
            cached
        } else {
            return Err(
                "Omega discovery failed and no cached Omikron address/key is available".to_string(),
            );
        };

        Ok(endpoint)
    }

    pub(super) fn persist_authenticated_omikron(
        &self,
        endpoint: &ResolvedOmikronEndpoint,
    ) -> Result<(), String> {
        let Some(id) = endpoint.id else {
            return Ok(());
        };
        let key_path = omikron_public_key_path(id);
        std::fs::create_dir_all(omikron_trust_directory())
            .map_err(|error| format!("create Omikron trust directory: {error}"))?;
        save_omikron_public_key(&endpoint.public_key, &key_path)?;
        modify_config(|cfg| {
            cfg.omikron_id = Some(id);
            cfg.omikron_host = Some(endpoint.host.clone());
            cfg.omikron_port = Some(endpoint.port);
        });
        Ok(())
    }
}
