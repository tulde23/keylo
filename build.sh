#!/bin/zsh
# Builds Keylo for macOS: dist/Keylo.app, holding the app, the keylo command (and MCP server) and
# keylo-mac, the Swift helper for Touch ID, the pasteboard and approval alerts.
#   ./build.sh             build
#   ./build.sh --install   build, then install (install.sh)
#   ./build.sh --debug     Debug build (enables KEYLO_SNAPSHOTS for UI checks)
#   ./build.sh --release   signed with Developer ID and notarized: dist/keylo-<version>-macos-<arch>.zip
#                          (once: xcrun notarytool store-credentials keylo-notary ...)
set -euo pipefail
cd "$(dirname "$0")"

dotnet_cmd=${DOTNET:-$(command -v dotnet || echo "$HOME/.dotnet/dotnet")}
rid=osx-$( [[ $(uname -m) == arm64 ]] && echo arm64 || echo x64 )
config=Release
[[ " $* " == *" --debug "* ]] && config=Debug
release=false
[[ " $* " == *" --release "* ]] && release=true
# KEYLO_COMMIT stamps a build made from a copy without .git (e.g. a release built on another machine).
commit=${KEYLO_COMMIT:-$(git rev-parse --short=7 HEAD 2>/dev/null || echo nogit)}
[[ -z ${KEYLO_COMMIT:-} && -n $(git status --porcelain 2>/dev/null) ]] && commit+=-dirty
version=1.1.0

if $release; then
  [[ $config == Release ]] || { echo "error: --release and --debug don't mix" >&2; exit 1; }
  [[ $commit != *-dirty ]] || { echo "error: --release needs a clean working tree (commit first)" >&2; exit 1; }
fi

app=dist/Keylo.app
bin=$app/Contents/MacOS
rm -rf "$app" dist/keylo-macos
mkdir -p "$bin" "$app/Contents/Resources"

# The app, self-contained so it runs without a .NET install. The keylo command is the same
# executable (KeyloApp --cli): one code signature, so the keychain trusts one app for both.
"$dotnet_cmd" publish src/Keylo.Desktop -c "$config" -f net10.0 -r "$rid" --self-contained true -o "$bin" -nologo -v q \
  "-p:InformationalVersion=$version+$(date +%Y%m%d).$commit"
rm -f "$bin"/*.pdb "$bin/keylo" "$bin/keylo.runtimeconfig.json" "$bin/keylo.deps.json"

cat > "$bin/keylo" <<'EOF'
#!/bin/sh
# The keylo command: Keylo.app's own executable in CLI mode.
exec "$(dirname "$(realpath "$0")")/KeyloApp" --cli "$@"
EOF
chmod +x "$bin/keylo"

swiftc -O -o "$bin/keylo-mac" src/Keylo.Platform.MacOS/helper/keylo-mac.swift

# Icon: assets/keylo-1024.png at every size macOS asks for.
iconset=$(mktemp -d)/keylo.iconset
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
  sips -z $size $size assets/keylo-1024.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
  sips -z $((size * 2)) $((size * 2)) assets/keylo-1024.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/keylo.icns"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Keylo</string>
  <key>CFBundleDisplayName</key><string>Keylo</string>
  <key>CFBundleIdentifier</key><string>io.github.tulde23.keylo</string>
  <key>CFBundleExecutable</key><string>KeyloApp</string>
  <key>CFBundleIconFile</key><string>keylo</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version.$(date +%Y%m%d)</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Your secrets, not ours.</string>
</dict>
</plist>
EOF

# Sign with a certificate when there is one (KEYLO_SIGN_IDENTITY, else the first "Apple Development"
# identity): the keychain then trusts every build, not just this one. An ad-hoc signature is tied to
# this exact build, so each rebuild asks again for every keychain item.
if ! $release; then
  identity=${KEYLO_SIGN_IDENTITY:-$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Apple Development: .*\)"/\1/p' | head -1)}
  if [[ -n $identity ]] && codesign --force --deep --sign "$identity" "$app" >/dev/null 2>&1; then
    echo "Signed with $identity"
  else
    [[ -n $identity ]] && echo "warning: couldn't sign with $identity; signing ad hoc" >&2
    codesign --force --deep --sign - "$app" >/dev/null 2>&1 || echo "warning: codesign failed" >&2
  fi
else
  # Distribution: a Developer ID certificate, the hardened runtime and a secure timestamp, each file
  # in Contents/MacOS signed before the bundle (not --deep). The .NET host needs the JIT entitlement;
  # library validation stays on, since every dylib is signed with the same Developer ID. (No XML
  # comments in the entitlements file: the kernel's parser rejects them.)
  identity=${KEYLO_SIGN_IDENTITY:-}
  [[ $identity == "Developer ID Application: "* ]] ||
    identity=$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application: .*\)"/\1/p' | head -1)
  [[ -n $identity ]] || { echo "error: --release needs a Developer ID Application certificate" >&2; exit 1; }
  entitlements=src/Keylo.Desktop/Keylo.entitlements
  sign() {
    local out
    out=$(codesign --force --timestamp --options runtime --sign "$identity" "$@" 2>&1) || {
      echo "$out" >&2
      echo "error: couldn't sign ${@[-1]} with $identity" >&2
      [[ $out == *errSecInternalComponent* && -n ${SSH_CONNECTION:-} ]] &&
        echo "       over SSH the keychain is locked: run 'security unlock-keychain' in this session first" >&2
      exit 1
    }
  }
  # KeyloApp is the bundle's main executable: signing the bundle signs it (with the entitlements),
  # and only once everything else in Contents/MacOS is signed.
  for f in "$bin"/*(.); do
    [[ ${f:t} == KeyloApp ]] || sign "$f"
  done
  sign --entitlements "$entitlements" "$app"
  codesign --verify --strict "$app"
  echo "Signed with $identity"

  # Notarize: Apple scans the zip, then the ticket is stapled to the app so it opens offline too.
  profile=${KEYLO_NOTARY_PROFILE:-keylo-notary}
  zip=dist/keylo-$version-macos-${rid#osx-}.zip
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  echo "Notarizing with profile $profile (a few minutes)..."
  result=$(xcrun notarytool submit "$zip" --keychain-profile "$profile" --wait 2>&1) || true
  if [[ $result != *"status: Accepted"* ]]; then
    echo "$result" >&2
    id=$(sed -n 's/^ *id: *//p' <<< "$result" | head -1)
    [[ -n $id ]] && xcrun notarytool log "$id" --keychain-profile "$profile" >&2
    echo "error: notarization failed" >&2
    exit 1
  fi
  xcrun stapler staple -q "$app"
  spctl --assess --type exec "$app"
  rm -f "$zip"
  ditto -c -k --keepParent "$app" "$zip"
  echo "Notarized: $zip"
  echo "  sha256 $(shasum -a 256 "$zip" | cut -d' ' -f1)"
fi

echo "Built Keylo $version ($commit, $config) for macOS ($rid): $app"
[[ " $* " == *" --install "* ]] && ./install.sh
exit 0
