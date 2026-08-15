#!/usr/bin/env bash
set -euo pipefail

binary_path="${1:-target/release/fortress}"
app_path="${2:-target/release/Fortress.app}"
age_bundle_dir="${3:-}"
bundle_name="${FORTRESS_BUNDLE_NAME:-Fortress}"
bundle_id="${FORTRESS_BUNDLE_ID:-dev.local.fortress}"
version="${FORTRESS_BUNDLE_VERSION:-0.1.0}"
executable_name="Fortress"
core_executable_name="fortress-core"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
icon_path="$repo_root/assets/Fortress.icns"
native_source_dir="$repo_root/macos-native/FortressNative"

if [[ ! -f "$binary_path" ]]; then
  echo "Binary not found: $binary_path" >&2
  exit 1
fi
if [[ ! -f "$icon_path" ]]; then
  echo "Application icon not found: $icon_path" >&2
  exit 1
fi
if [[ ! -d "$native_source_dir" ]]; then
  echo "Native macOS source directory not found: $native_source_dir" >&2
  exit 1
fi
if ! command -v xcrun >/dev/null 2>&1; then
  echo "Xcode command-line tools are required to build the native macOS interface." >&2
  exit 1
fi

if [[ -z "$age_bundle_dir" ]]; then
  binary_description="$(file -b "$binary_path")"
  case "$binary_description" in
    *arm64*) age_arch="arm64" ;;
    *x86_64*) age_arch="x86_64" ;;
    *)
      echo "Cannot determine macOS binary architecture: $binary_description" >&2
      exit 1
      ;;
  esac
  age_bundle_dir="$("$script_dir/fetch-age.sh" darwin "$age_arch")"
fi

if [[ ! -x "$age_bundle_dir/age" ]]; then
  echo "Bundled age executable not found: $age_bundle_dir/age" >&2
  exit 1
fi
if [[ ! -x "$age_bundle_dir/age-keygen" ]]; then
  echo "Bundled age-keygen executable not found: $age_bundle_dir/age-keygen" >&2
  exit 1
fi
if [[ ! -f "$age_bundle_dir/LICENSE" ]]; then
  echo "Bundled age license not found: $age_bundle_dir/LICENSE" >&2
  exit 1
fi

rm -rf "$app_path"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"

binary_description="$(file -b "$binary_path")"
case "$binary_description" in
  *arm64*) swift_target="arm64-apple-macos12.0" ;;
  *x86_64*) swift_target="x86_64-apple-macos12.0" ;;
  *)
    echo "Cannot determine native Swift target from Rust core: $binary_description" >&2
    exit 1
    ;;
esac
module_cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/fortress-swift-cache.XXXXXX")"
trap 'rm -rf "$module_cache_dir"' EXIT
localization_audit="$module_cache_dir/localization-audit"
xcrun swiftc \
  -parse-as-library \
  -warnings-as-errors \
  -module-cache-path "$module_cache_dir" \
  -target "$swift_target" \
  "$native_source_dir/Localization.swift" \
  "$repo_root/macos-native/LocalizationAudit.swift" \
  -o "$localization_audit"
"$localization_audit" "$repo_root/src/main.rs"
parity_audit="$module_cache_dir/native-parity-audit"
xcrun swiftc \
  -parse-as-library \
  -warnings-as-errors \
  -module-cache-path "$module_cache_dir" \
  -target "$swift_target" \
  "$repo_root/macos-native/NativeParityAudit.swift" \
  -o "$parity_audit"
"$parity_audit" \
  "$repo_root/src/main.rs" \
  "$native_source_dir/Components.swift" \
  "$native_source_dir/MouseEntropy.swift" \
  "$native_source_dir/Views.swift"
bridge_audit="$module_cache_dir/bridge-audit"
xcrun swiftc \
  -warnings-as-errors \
  -module-cache-path "$module_cache_dir" \
  -target "$swift_target" \
  "$native_source_dir/Bridge.swift" \
  "$repo_root/macos-native/BridgeAudit.swift" \
  -o "$bridge_audit"
swift_sources=("$native_source_dir"/*.swift)
xcrun swiftc \
  -parse-as-library \
  -warnings-as-errors \
  -O \
  -whole-module-optimization \
  -module-cache-path "$module_cache_dir" \
  -target "$swift_target" \
  "${swift_sources[@]}" \
  -framework SwiftUI \
  -framework AppKit \
  -framework CryptoKit \
  -o "$app_path/Contents/MacOS/$executable_name"
chmod 755 "$app_path/Contents/MacOS/$executable_name"
cp "$binary_path" "$app_path/Contents/MacOS/$core_executable_name"
chmod 755 "$app_path/Contents/MacOS/$core_executable_name"
cp "$age_bundle_dir/age" "$app_path/Contents/MacOS/age"
chmod 755 "$app_path/Contents/MacOS/age"
cp "$age_bundle_dir/age-keygen" "$app_path/Contents/MacOS/age-keygen"
chmod 755 "$app_path/Contents/MacOS/age-keygen"
cp "$age_bundle_dir/LICENSE" "$app_path/Contents/Resources/age-LICENSE.txt"
cp "$icon_path" "$app_path/Contents/Resources/Fortress.icns"
cp "$repo_root/assets/Noto-CJK-LICENSE.txt" "$app_path/Contents/Resources/Noto-CJK-LICENSE.txt"

cat > "$app_path/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${executable_name}</string>
  <key>CFBundleIdentifier</key>
  <string>${bundle_id}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${bundle_name}</string>
  <key>CFBundleDisplayName</key>
  <string>${bundle_name}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleIconFile</key>
  <string>Fortress</string>
  <key>CFBundleShortVersionString</key>
  <string>${version}</string>
  <key>CFBundleVersion</key>
  <string>${version}</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
PLIST

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$app_path/Contents/Info.plist" >/dev/null
fi

if command -v codesign >/dev/null 2>&1; then
  signing_identity="${FORTRESS_CODESIGN_IDENTITY:--}"
  signing_flags=(--force --sign "$signing_identity")
  if [[ "$signing_identity" != "-" ]]; then
    signing_flags+=(--timestamp --options runtime)
  fi
  codesign "${signing_flags[@]}" "$app_path/Contents/MacOS/age" >/dev/null
  codesign "${signing_flags[@]}" "$app_path/Contents/MacOS/age-keygen" >/dev/null
  codesign "${signing_flags[@]}" "$app_path/Contents/MacOS/$core_executable_name" >/dev/null
  codesign "${signing_flags[@]}" "$app_path/Contents/MacOS/$executable_name" >/dev/null
  codesign "${signing_flags[@]}" "$app_path" >/dev/null
  codesign --verify --deep --strict "$app_path"
fi

"$app_path/Contents/MacOS/age" --version >/dev/null
"$app_path/Contents/MacOS/age-keygen" --version >/dev/null
printf '%s\n' '{"operation":"health"}' \
  | "$app_path/Contents/MacOS/$core_executable_name" --native-bridge \
  | grep -q '"ok":true'
"$bridge_audit" "$app_path/Contents/MacOS/$core_executable_name"

echo "Created $app_path"
