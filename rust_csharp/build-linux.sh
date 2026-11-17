#!/usr/bin/env bash
# Builds Keylo for Linux: the app (Avalonia) and the keylo command (and MCP server), which is the
# app's own executable in CLI mode, self-contained (no .NET install needed to run it).
#   ./build-linux.sh                 build dist/keylo-<version>-linux-<arch>.tar.gz
#   ./build-linux.sh --arch arm64    for 64-bit ARM (default: this machine's architecture)
#   ./build-linux.sh --install       build, then install for this user (install.sh in the bundle)
# Needs the .NET 10 SDK. Runs on Linux, or anywhere Docker runs:
#   docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 ./build-linux.sh
set -euo pipefail
cd "$(dirname "$0")"

dotnet_cmd=${DOTNET:-$(command -v dotnet || echo "$HOME/.dotnet/dotnet")}
arch=$( [[ $(uname -m) == aarch64 || $(uname -m) == arm64 ]] && echo arm64 || echo x64 )
args=" $* "
if [[ $args =~ " --arch "([a-z0-9]+)" " ]]; then arch=${BASH_REMATCH[1]}; fi
[[ $arch == x64 || $arch == arm64 ]] || { echo "error: --arch must be x64 or arm64" >&2; exit 1; }

version=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props | head -1)
# KEYLO_COMMIT stamps a build made from a copy without .git (e.g. inside a container).
commit=${KEYLO_COMMIT:-$(git rev-parse --short=7 HEAD 2>/dev/null || echo nogit)}
[[ -z ${KEYLO_COMMIT:-} && -n $(git status --porcelain 2>/dev/null) ]] && commit+=-dirty

name=keylo-$version-linux-$arch
stage=dist/$name
lib=$stage/lib
rm -rf "$stage" "dist/$name.tar.gz"
mkdir -p "$lib"

# Invariant globalization: no libicu needed (minimal containers lack it); Keylo's UI is English.
"$dotnet_cmd" publish src/Keylo.Desktop -c Release -f net10.0 -r "linux-$arch" --self-contained true -o "$lib" -nologo -v q \
  -p:InvariantGlobalization=true "-p:InformationalVersion=$version+$(date +%Y%m%d).$commit"
rm -f "$lib"/*.pdb "$lib/keylo" "$lib/keylo.runtimeconfig.json" "$lib/keylo.deps.json"

# The keylo command: KeyloApp in CLI mode, so the app and the command are one program.
cat > "$lib/keylo" <<'EOF'
#!/bin/sh
exec "$(dirname "$(realpath "$0")")/KeyloApp" --cli "$@"
EOF
chmod +x "$lib/keylo" "$lib/KeyloApp"

cp src/Keylo.Platform.Linux/polkit/io.github.tulde23.keylo.policy "$stage/"
cp assets/keylo-256.png "$stage/keylo.png"
cp install-linux.sh "$stage/install.sh"
chmod +x "$stage/install.sh"

tar -C dist -czf "dist/$name.tar.gz" "$name"
echo "Built Keylo $version ($commit) for Linux ($arch): dist/$name.tar.gz"
echo "  sha256 $(sha256sum "dist/$name.tar.gz" | cut -d' ' -f1)"

[[ $args == *" --install "* ]] && "$stage/install.sh"
exit 0
