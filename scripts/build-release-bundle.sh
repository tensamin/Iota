#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
    echo "usage: $0 BINARY_DIRECTORY PRODUCT_VERSION UPDATE_MANIFEST_URL UPDATE_PUBLIC_KEY UPDATE_SIGNATURE_URL OUTPUT.zip" >&2
    exit 2
fi

binary_directory="$1"
product_version="$2"
update_manifest_url="$3"
update_public_key="$4"
update_signature_url="$5"
output="$6"
repository_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
contract="$repository_directory/iota-installer/bundle-files.txt"
staging_directory="$(mktemp -d)"
trap 'rm -rf "$staging_directory"' EXIT

if [[ ! "$product_version" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]]; then
    echo "product version contains unsupported characters: $product_version" >&2
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
            printf '{"product_version":"%s"}\n' "$product_version" > "$destination"
            ;;
        systemd/update.env)
            printf 'IOTA_UPDATE_MANIFEST=%s\nIOTA_UPDATE_PUBLIC_KEY=%s\nIOTA_UPDATE_SIGNATURE=%s\n' \
                "$update_manifest_url" \
                "$update_public_key" \
                "$update_signature_url" \
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
