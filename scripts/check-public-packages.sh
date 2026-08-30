#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
package_flags=(--locked)
plugin_package_flags=()
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-notification-packages.XXXXXX")"

cleanup() {
  if [[ "${LENSO_KEEP_PACKAGE_TMP:-0}" == "1" ]]; then
    printf 'kept package verification root: %s\n' "$verification_root" >&2
  else
    rm -r "$verification_root"
  fi
}
trap cleanup EXIT

if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
  plugin_package_flags+=(--allow-dirty)
fi

capabilities=(
  lenso-capability-email-dispatch
  lenso-capability-notification-admin
  lenso-capability-notification-delivery
  lenso-capability-notification-transactional
)

for capability in "${capabilities[@]}"; do
  "$cargo_bin" package --quiet "${package_flags[@]}" -p "$capability"
done

metadata="$($cargo_bin metadata --no-deps --format-version=1)"
target_directory="$(python3 -c \
  'import json, sys; print(json.load(sys.stdin)["target_directory"])' \
  <<<"$metadata")"
package_version() {
  python3 -c \
    'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
    "$1" <<<"$metadata"
}

source_patches=()
for capability in "${capabilities[@]}"; do
  source_patches+=(--config "patch.crates-io.$capability.path=\"$repository_root/crates/$capability\"")
done

# The normalized Plugin manifest resolves Capability versions through the
# registry. During an unreleased coordinated change, patch those names to the
# exact source packages only to create the archive; the archive-only graph is
# independently checked below.
"$cargo_bin" "${source_patches[@]}" package --quiet \
  "${plugin_package_flags[@]}" --no-verify -p lenso-notification-plugin

archive_patches=()
for capability in "${capabilities[@]}"; do
  version="$(package_version "$capability")"
  archive="$target_directory/package/$capability-$version.crate"
  tar -xzf "$archive" -C "$verification_root"
  package="$verification_root/$capability-$version"
  [[ -f "$package/Cargo.toml" ]]
  archive_patches+=(--config "patch.crates-io.$capability.path=\"$package\"")
done

plugin_version="$(package_version lenso-notification-plugin)"
plugin_archive="$target_directory/package/lenso-notification-plugin-$plugin_version.crate"
tar -xzf "$plugin_archive" -C "$verification_root"
plugin_manifest="$verification_root/lenso-notification-plugin-$plugin_version/Cargo.toml"
[[ -f "$plugin_manifest" ]]

"$cargo_bin" "${archive_patches[@]}" generate-lockfile --manifest-path "$plugin_manifest"
"$cargo_bin" "${archive_patches[@]}" check --quiet --locked --all-targets \
  --manifest-path "$plugin_manifest"
"$cargo_bin" "${archive_patches[@]}" test --quiet --locked \
  --manifest-path "$plugin_manifest"
"$cargo_bin" clippy "${archive_patches[@]}" --quiet --locked --all-targets \
  --manifest-path "$plugin_manifest" -- -D warnings
