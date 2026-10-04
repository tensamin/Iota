#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 10 ]]; then
    echo "usage: $0 BINARY_DIRECTORY PRODUCT_VERSION CHANNEL RELEASE_SEQUENCE PUBLISHED_AT EXPIRES_AT OS ARCHITECTURE BASE_URL OUTPUT.json" >&2
    exit 2
fi

binary_directory="$1"
product_version="$2"
channel="$3"
release_sequence="$4"
published_at="$5"
expires_at="$6"
operating_system="$7"
architecture="$8"
base_url="$(printf '%s' "$9" | sed 's#/$##')"
output="${10}"
repository_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="$repository_directory/iota-updater/artifacts.tsv"
staging_directory="$(mktemp -d)"
artifacts="$staging_directory/artifacts.jsonl"
trap 'rm -rf "$staging_directory"' EXIT

case "$channel" in stable|canary) ;; *) echo "channel must be stable or canary" >&2; exit 2 ;; esac
case "$operating_system/$architecture" in linux/x86_64|linux/aarch64) ;; *) echo "unsupported update platform" >&2; exit 2 ;; esac
source_sha="${IOTA_RELEASE_SOURCE_SHA:-$(git -C "$repository_directory" rev-parse HEAD)}"
if [[ ! "$source_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "IOTA_RELEASE_SOURCE_SHA must be a full source commit SHA" >&2
    exit 2
fi
product_version="${product_version}-${channel}-${source_sha}"
signing_key_id="${IOTA_RELEASE_SIGNING_KEY_ID:-primary}"

if [[ ! "$release_sequence" =~ ^[1-9][0-9]*$ ]]; then
    echo "release sequence must be a positive integer" >&2
    exit 2
fi
published_epoch="$(date -d "$published_at" +%s)"
expires_epoch="$(date -d "$expires_at" +%s)"
if (( expires_epoch <= published_epoch )); then
    echo "expires_at must be after published_at" >&2
    exit 2
fi

while IFS=$'\t' read -r role artifact_path; do
    [[ -n "$role" && -n "$artifact_path" ]] || continue
    asset_name="$(basename "$artifact_path")"
    source_path="$binary_directory/$asset_name"
    jq -n \
        --arg role "$role" \
        --arg os "$operating_system" \
        --arg architecture "$architecture" \
        --arg path "$artifact_path" \
        --arg url "$base_url/$asset_name-$operating_system-$architecture" \
        --arg sha256 "$(sha256sum "$source_path" | cut -d ' ' -f 1)" \
        --argjson size "$(stat -c %s "$source_path")" \
        '{role: $role, os: $os, architecture: $architecture, path: $path, url: $url, sha256: $sha256, size: $size}' \
        >> "$artifacts"
done < "$contract"

mkdir -p "$(dirname "$output")"
jq -s \
    --arg product_version "$product_version" \
    --arg channel "$channel" \
    --argjson release_sequence "$release_sequence" \
    --arg published_at "$published_at" \
    --arg expires_at "$expires_at" \
    --arg release_signing_key_id "$signing_key_id" \
    '{
        product_version: $product_version,
        channel: $channel,
        release_sequence: $release_sequence,
        published_at: $published_at,
        expires_at: $expires_at,
        minimum_data_schema: 1,
        supported_ipc_min: 2,
        supported_ipc_max: 4,
        artifacts: .,
        release_signing_key_id: $release_signing_key_id,
        rollback_compatible: true
    }' "$artifacts" > "$output"
