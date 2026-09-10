#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 9 ]]; then
    echo "usage: $0 BINARY_DIRECTORY PRODUCT_VERSION RELEASE_MANIFEST UPDATE_MANIFEST_URL UPDATE_PUBLIC_KEY UPDATE_SIGNATURE_URL UPDATE_CHANNEL UPDATE_SIGNING_KEY_ID OUTPUT.zip" >&2
    exit 2
fi

binary_directory="$1"
product_version="$2"
release_manifest="$3"
update_manifest_url="$4"
update_public_key="$5"
update_signature_url="$6"
update_channel="$7"
update_signing_key_id="$8"
output="$9"
repository_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="$repository_directory/iota-installer/bundle-files.txt"
staging_directory="$(mktemp -d)"
trap 'rm -rf "$staging_directory"' EXIT

if [[ ! "$product_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]]; then
    echo "product version contains unsupported characters: $product_version" >&2
    exit 2
fi
if ! jq -e \
    --arg product_version "$product_version" \
    --arg channel "$update_channel" \
    --arg key_id "$update_signing_key_id" \
    '.product_version == $product_version
        and .channel == $channel
        and .release_signing_key_id == $key_id
        and (.release_sequence | type == "number" and . > 0)
        and (.published_at | type == "string" and length > 0)
        and (.expires_at | type == "string" and length > 0)' \
    "$release_manifest" >/dev/null; then
    echo "release manifest identity or anti-rollback metadata is invalid" >&2
    exit 2
fi

mkdir -p "$(dirname "$output")"
output="$(cd "$(dirname "$output")" && pwd)/$(basename "$output")"
bundle_files=()

while IFS= read -r bundle_path; do
    [[ -n "$bundle_path" ]] || continue
    bundle_files+=("$bundle_path")
    destination="$staging_directory/$bundle_path"
    mkdir -p "$(dirname "$destination")"

    case "$bundle_path" in
        bin/*)
            install -m 0755 "$binary_directory/${bundle_path#bin/}" "$destination"
            ;;
        manifest.json)
            install -m 0644 "$release_manifest" "$destination"
            ;;
        systemd/update.env)
            printf 'IOTA_UPDATE_MANIFEST=%s\nIOTA_UPDATE_PUBLIC_KEY=%s\nIOTA_UPDATE_SIGNATURE=%s\nIOTA_UPDATE_CHANNEL=%s\nIOTA_UPDATE_SIGNING_KEY_ID=%s\n' \
                "$update_manifest_url" \
                "$update_public_key" \
                "$update_signature_url" \
                "$update_channel" \
                "$update_signing_key_id" \
                > "$destination"
            ;;
        *)
            install -m 0644 "$repository_directory/$bundle_path" "$destination"
            ;;
    esac
done < "$contract"

(
    cd "$staging_directory"
    zip -q "$output" "${bundle_files[@]}"
)
