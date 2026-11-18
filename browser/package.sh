#!/usr/bin/env bash
# Packages the browser extension for a release: keylo-<version>-browser-chrome.zip (Chrome, Edge,
# Brave; load unpacked) and keylo-<version>-browser-firefox.zip (Firefox's manifest).
# Usage: browser/package.sh VERSION OUT_DIR
set -euo pipefail
version="${1:?version}"
out="$(cd "${2:?out dir}" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for target in chrome firefox; do
  mkdir -p "$work/$target"
  cp -r "$here/extension/." "$work/$target/"
  if [ "$target" = firefox ]; then cp "$here/manifest.firefox.json" "$work/$target/manifest.json"; fi
  # The release's version (Chrome takes up to four dot-separated numbers).
  sed -i.bak "s/\"version\": \"[0-9.]*\"/\"version\": \"$version\"/" "$work/$target/manifest.json" && rm "$work/$target/manifest.json.bak"
  if command -v zip >/dev/null; then
    (cd "$work/$target" && zip -qr "$out/keylo-$version-browser-$target.zip" .)
  else
    python -c "import shutil, sys; shutil.make_archive(sys.argv[1], 'zip', sys.argv[2])" "$out/keylo-$version-browser-$target" "$work/$target"
  fi
done
echo "Packaged keylo-$version-browser-{chrome,firefox}.zip"
