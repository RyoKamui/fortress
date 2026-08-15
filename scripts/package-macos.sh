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
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/fortress-macos-package.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

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
if [[ "$app_path" != *.app || "$app_path" == "/" ]]; then
  echo "The macOS package output must be a specific .app path: $app_path" >&2
  exit 1
fi
if ! command -v xcrun >/dev/null 2>&1; then
  echo "Xcode command-line tools are required to build the native macOS interface." >&2
  exit 1
fi

binary_arches="$(xcrun lipo -archs "$binary_path")"
swift_targets=()
for binary_arch in $binary_arches; do
  case "$binary_arch" in
    arm64) swift_targets+=("arm64-apple-macos12.0") ;;
    x86_64) swift_targets+=("x86_64-apple-macos12.0") ;;
    *)
      echo "Unsupported macOS binary architecture: $binary_arch" >&2
      exit 1
      ;;
  esac
done
if [[ "${#swift_targets[@]}" -eq 0 ]]; then
  echo "Cannot determine macOS binary architecture: $(file -b "$binary_path")" >&2
  exit 1
fi

if [[ -z "$age_bundle_dir" ]]; then
  if [[ "${#swift_targets[@]}" -eq 1 ]]; then
    case "${swift_targets[0]}" in
      arm64-*) age_arch="arm64" ;;
      x86_64-*) age_arch="x86_64" ;;
    esac
    age_bundle_dir="$("$script_dir/fetch-age.sh" darwin "$age_arch")"
  else
    arm_age_bundle_dir="$("$script_dir/fetch-age.sh" darwin arm64)"
    intel_age_bundle_dir="$("$script_dir/fetch-age.sh" darwin x86_64)"
    age_bundle_dir="$work_dir/universal-age"
    mkdir -p "$age_bundle_dir"
    xcrun lipo -create \
      "$arm_age_bundle_dir/age" \
      "$intel_age_bundle_dir/age" \
      -output "$age_bundle_dir/age"
    xcrun lipo -create \
      "$arm_age_bundle_dir/age-keygen" \
      "$intel_age_bundle_dir/age-keygen" \
      -output "$age_bundle_dir/age-keygen"
    cp "$arm_age_bundle_dir/LICENSE" "$age_bundle_dir/LICENSE"
    chmod 755 "$age_bundle_dir/age" "$age_bundle_dir/age-keygen"
  fi
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
for required_arch in $binary_arches; do
  for age_executable in age age-keygen; do
    age_arches=" $(xcrun lipo -archs "$age_bundle_dir/$age_executable") "
    if [[ "$age_arches" != *" $required_arch "* ]]; then
      echo "Bundled $age_executable is missing the $required_arch architecture." >&2
      exit 1
    fi
  done
done

rm -rf -- "$app_path"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"

module_cache_dir="$work_dir/swift-cache"
mkdir -p "$module_cache_dir"
localization_audit="$module_cache_dir/localization-audit"
xcrun swiftc \
  -parse-as-library \
  -warnings-as-errors \
  -module-cache-path "$module_cache_dir" \
  "$native_source_dir/Localization.swift" \
  "$repo_root/macos-native/LocalizationAudit.swift" \
  -o "$localization_audit"
"$localization_audit" "$repo_root/src/main.rs"
parity_audit="$module_cache_dir/native-parity-audit"
xcrun swiftc \
  -parse-as-library \
  -warnings-as-errors \
  -module-cache-path "$module_cache_dir" \
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
  "$native_source_dir/Bridge.swift" \
  "$repo_root/macos-native/BridgeAudit.swift" \
  -o "$bridge_audit"
swift_sources=("$native_source_dir"/*.swift)
swift_executables=()
for swift_target in "${swift_targets[@]}"; do
  swift_arch="${swift_target%%-*}"
  swift_executable="$work_dir/$executable_name-$swift_arch"
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
    -o "$swift_executable"
  swift_executables+=("$swift_executable")
done
if [[ "${#swift_executables[@]}" -eq 1 ]]; then
  cp "${swift_executables[0]}" "$app_path/Contents/MacOS/$executable_name"
else
  xcrun lipo -create \
    "${swift_executables[@]}" \
    -output "$app_path/Contents/MacOS/$executable_name"
fi
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
