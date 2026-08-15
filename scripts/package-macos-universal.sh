#!/usr/bin/env bash
set -euo pipefail

arm_core_path="${1:-target/aarch64-apple-darwin/release/fortress}"
intel_core_path="${2:-target/x86_64-apple-darwin/release/fortress}"
app_path="${3:-target/release/Fortress.app}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/fortress-universal.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Universal macOS apps must be packaged on macOS." >&2
  exit 1
fi
if [[ ! -f "$arm_core_path" ]]; then
  echo "Apple Silicon core not found: $arm_core_path" >&2
  exit 1
fi
if [[ ! -f "$intel_core_path" ]]; then
  echo "Intel core not found: $intel_core_path" >&2
  exit 1
fi

require_arch() {
  local binary_path="$1"
  local expected_arch="$2"
  local binary_arches
  binary_arches=" $(xcrun lipo -archs "$binary_path") "
  if [[ "$binary_arches" != *" $expected_arch "* ]]; then
    echo "$binary_path does not contain the expected $expected_arch architecture." >&2
    exit 1
  fi
}

require_arch "$arm_core_path" arm64
require_arch "$intel_core_path" x86_64

universal_core_path="$work_dir/fortress-core"
xcrun lipo -create \
  "$arm_core_path" \
  "$intel_core_path" \
  -output "$universal_core_path"
chmod 755 "$universal_core_path"

"$script_dir/package-macos.sh" "$universal_core_path" "$app_path"

for bundled_binary in Fortress fortress-core age age-keygen; do
  require_arch "$app_path/Contents/MacOS/$bundled_binary" arm64
  require_arch "$app_path/Contents/MacOS/$bundled_binary" x86_64
done

echo "Created universal macOS app: $app_path"
