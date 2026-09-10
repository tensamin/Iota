#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 8 ]]; then
    echo "usage: $0 BINARY_DIRECTORY PRODUCT_VERSION CHANNEL PUBLISHED_AT OS ARCHITECTURE BASE_URL OUTPUT.json" >&2
    exit 2
fi

binary_directory="$1"
product_version="$2"
channel="$3"
published_at="$4"
operating_system="$5"
architecture="$6"
base_url="$(printf '%s' "$7" | sed 's#/$##')"
output="$8"
repository_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="$repository_directory/iota-updater/artifacts.tsv"
staging_directory="$(mktemp -d)"
artifacts="$staging_directory/artifacts.jsonl"
trap 'rm -rf "$staging_directory"' EXIT

while IFS=$'\t' read -r role artifact_path; do
    [[ -n "$role" && -n "$artifact_path" ]] || continue
    asset_name="$(basename "$artifact_path")"
    source_path="$binary_directory/$asset_name"
    jq -n \
        --arg role "$role" \
        --arg os "$operating_system" \
        --arg architecture "$architecture" \
        --arg path "$artifact_path" \
        --arg url "$base_url/$asset_name" \
        --arg sha256 "$(sha256sum "$source_path" | cut -d ' ' -f 1)" \
        --argjson size "$(stat -c %s "$source_path")" \
        '{role: $role, os: $os, architecture: $architecture, path: $path, url: $url, sha256: $sha256, size: $size}' \
        >> "$artifacts"
done < "$contract"

mkdir -p "$(dirname "$output")"
jq -s \
    --arg product_version "$product_version" \
    --arg channel "$channel" \
    --arg published_at "$published_at" \
    --arg release_signing_key_id "primary" \
    '{
        product_version: $product_version,
        channel: $channel,
        published_at: $published_at,
        minimum_data_schema: 1,
        supported_ipc_min: 2,
        supported_ipc_max: 4,
        artifacts: .,
        release_signing_key_id: $release_signing_key_id,
        rollback_compatible: true
    }' "$artifacts" > "$output"
