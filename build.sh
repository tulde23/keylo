#!/bin/zsh
# Builds Keylo for macOS: dist/Keylo.app, holding the app, the keylo command (and MCP server) and
# keylo-mac, the Swift helper for Touch ID, the pasteboard and approval alerts.
#   ./build.sh             build
#   ./build.sh --install   build, then install (install.sh)
#   ./build.sh --debug     Debug build (enables KEYLO_SNAPSHOTS for UI checks)
set -euo pipefail
cd "$(dirname "$0")"

dotnet_cmd=${DOTNET:-$(command -v dotnet || echo "$HOME/.dotnet/dotnet")}
rid=osx-$( [[ $(uname -m) == arm64 ]] && echo arm64 || echo x64 )
config=Release
[[ " $* " == *" --debug "* ]] && config=Debug
commit=$(git rev-parse --short=7 HEAD 2>/dev/null || echo nogit)
[[ -n $(git status --porcelain 2>/dev/null) ]] && commit+=-dirty
version=1.0.0

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
  <key>NSHumanReadableCopyright</key><string>Your secrets, kept close.</string>
</dict>
</plist>
EOF

# Ad-hoc signature: a stable identity for this build (the keychain's "Always Allow" is per signature).
codesign --force --deep --sign - "$app" >/dev/null 2>&1 || echo "warning: codesign failed" >&2

echo "Built Keylo $version ($commit, $config) for macOS ($rid): $app"
[[ " $* " == *" --install "* ]] && ./install.sh
exit 0
