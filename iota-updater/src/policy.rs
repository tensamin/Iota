use super::*;

pub(super) fn evaluate_candidate(
    manifest: &ReleaseManifest,
    current_version: Option<&str>,
    channel_state: Option<&ChannelState>,
    expected_channel: &str,
    expected_key_id: &str,
    now: DateTime<Utc>,
) -> Result<CandidateDecision> {
    validate_manifest_identity(manifest, expected_channel, expected_key_id)?;
    validate_manifest_freshness(manifest, now)?;
    if manifest.release_sequence == 0 {
        bail!("release sequence must be greater than zero");
    }
    if let Some(state) = channel_state {
        if manifest.release_sequence < state.highest_accepted_sequence {
            bail!(
                "release sequence {} is older than trusted sequence {}",
                manifest.release_sequence,
                state.highest_accepted_sequence
            );
        }
        if manifest.release_sequence == state.highest_accepted_sequence
            && manifest.product_version != state.highest_accepted_version
        {
            bail!(
                "release sequence {} was already associated with version {}",
                manifest.release_sequence,
                state.highest_accepted_version
            );
        }
        if state.last_failed_sequence == Some(manifest.release_sequence) {
            bail!(
                "release sequence {} previously failed activation",
                manifest.release_sequence
            );
        }
        if manifest.release_sequence == state.highest_accepted_sequence {
            return Ok(if current_version.is_none() {
                CandidateDecision::Install
            } else {
                CandidateDecision::NoUpdate
            });
        }
    }
    if current_version == Some(manifest.product_version.as_str()) {
        return Ok(CandidateDecision::NoUpdate);
    }
    Ok(CandidateDecision::Install)
}

pub(super) fn validate_manifest_identity(
    manifest: &ReleaseManifest,
    expected_channel: &str,
    expected_key_id: &str,
) -> Result<()> {
    if manifest.channel != expected_channel {
        bail!(
            "release channel mismatch: expected {}, got {}",
            expected_channel,
            manifest.channel
        );
    }
    if manifest.release_signing_key_id != expected_key_id {
        bail!(
            "release signing key id mismatch: expected {}, got {}",
            expected_key_id,
            manifest.release_signing_key_id
        );
    }
    Ok(())
}

pub(super) fn validate_manifest_freshness(
    manifest: &ReleaseManifest,
    now: DateTime<Utc>,
) -> Result<()> {
    let published_at = DateTime::parse_from_rfc3339(&manifest.published_at)
        .context("parse manifest published_at")?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .context("parse manifest expires_at")?
        .with_timezone(&Utc);
    if expires_at <= published_at {
        bail!("release manifest expires_at must be after published_at");
    }
    if now > expires_at {
        bail!("release manifest expired at {}", manifest.expires_at);
    }
    Ok(())
}
