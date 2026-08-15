#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
age_version="$(tr -d '[:space:]' < "$repo_root/AGE_VERSION")"
checksum_manifest="$repo_root/AGE_CHECKSUMS"
requested_os="${1:-}"
requested_arch="${2:-$(uname -m)}"

case "$requested_os:$requested_arch" in
  darwin:arm64 | darwin:aarch64 | macos:arm64 | macos:aarch64)
    release_os="darwin"
    release_arch="arm64"
    archive_extension="tar.gz"
    executable_name="age"
    keygen_name="age-keygen"
    ;;
  darwin:x86_64 | darwin:amd64 | macos:x86_64 | macos:amd64)
    release_os="darwin"
    release_arch="amd64"
    archive_extension="tar.gz"
    executable_name="age"
    keygen_name="age-keygen"
    ;;
  linux:x86_64 | linux:amd64)
    release_os="linux"
    release_arch="amd64"
    archive_extension="tar.gz"
    executable_name="age"
    keygen_name="age-keygen"
    ;;
  linux:arm64 | linux:aarch64)
    release_os="linux"
    release_arch="arm64"
    archive_extension="tar.gz"
    executable_name="age"
    keygen_name="age-keygen"
    ;;
  windows:x86_64 | windows:amd64)
    release_os="windows"
    release_arch="amd64"
    archive_extension="zip"
    executable_name="age.exe"
    keygen_name="age-keygen.exe"
    ;;
  *)
    echo "Unsupported age release target: $requested_os $requested_arch" >&2
    exit 1
    ;;
esac

if [[ ! -f "$checksum_manifest" ]]; then
  echo "age checksum manifest not found: $checksum_manifest" >&2
  exit 1
fi
expected_sha256="$(awk \
  -v version="$age_version" \
  -v os="$release_os" \
  -v arch="$release_arch" \
  '$1 == version && $2 == os && $3 == arch { print $4 }' \
  "$checksum_manifest")"
if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "No valid checksum for age v$age_version $release_os-$release_arch." >&2
  exit 1
fi

cache_dir="$repo_root/target/vendor/age/v$age_version/$release_os-$release_arch"
archive_name="age-v$age_version-$release_os-$release_arch.$archive_extension"
archive_path="$cache_dir/$archive_name"
bundle_dir="$cache_dir/age"
download_url="https://github.com/FiloSottile/age/releases/download/v$age_version/$archive_name"

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

mkdir -p "$cache_dir"

if [[ ! -f "$archive_path" ]] || [[ "$(sha256_file "$archive_path")" != "$expected_sha256" ]]; then
  temp_archive="$(mktemp "$cache_dir/$archive_name.download.XXXXXX")"
  trap 'rm -f "$temp_archive"' EXIT
  curl --fail --location --retry 3 --output "$temp_archive" "$download_url"
  actual_sha256="$(sha256_file "$temp_archive")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "age archive checksum mismatch: expected $expected_sha256, got $actual_sha256" >&2
    exit 1
  fi
  mv "$temp_archive" "$archive_path"
  trap - EXIT
fi

if [[ ! -x "$bundle_dir/$executable_name" ]] \
  || [[ ! -x "$bundle_dir/$keygen_name" ]] \
  || [[ ! -f "$bundle_dir/LICENSE" ]]; then
  temp_extract="$(mktemp -d "$cache_dir/extract.XXXXXX")"
  trap 'rm -rf "$temp_extract"' EXIT
  if [[ "$archive_extension" == "zip" ]]; then
    if command -v unzip >/dev/null 2>&1; then
      unzip -q "$archive_path" \
        "age/$executable_name" \
        "age/$keygen_name" \
        age/LICENSE \
        -d "$temp_extract"
    elif command -v powershell.exe >/dev/null 2>&1 && command -v cygpath >/dev/null 2>&1; then
      archive_windows="$(cygpath -w "$archive_path")"
      extract_windows="$(cygpath -w "$temp_extract")"
      powershell.exe -NoProfile -NonInteractive -Command \
        'Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force' \
        "$archive_windows" "$extract_windows"
    else
      echo "No ZIP extractor is available for $archive_path." >&2
      exit 1
    fi
  else
    tar -xf "$archive_path" -C "$temp_extract" \
      "age/$executable_name" \
      "age/$keygen_name" \
      age/LICENSE
  fi
  rm -rf "$bundle_dir"
  mv "$temp_extract/age" "$bundle_dir"
  chmod 755 "$bundle_dir/$executable_name"
  chmod 755 "$bundle_dir/$keygen_name"
  trap - EXIT
  rmdir "$temp_extract"
fi

host_system="$(uname -s)"
case "$release_os:$host_system" in
  darwin:Darwin | linux:Linux | windows:MINGW* | windows:MSYS* | windows:CYGWIN*)
    "$bundle_dir/$executable_name" --version >&2
    "$bundle_dir/$keygen_name" --version >&2
    ;;
  *)
    echo "Verified age v$age_version archive for $release_os-$release_arch (launch test deferred to target OS)." >&2
    ;;
esac
printf '%s\n' "$bundle_dir"
