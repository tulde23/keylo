#!/bin/zsh
# Installs dist/Keylo.app to ~/Applications and links ~/.local/bin/keylo to the keylo command inside
# it. Secrets (in the login keychain) and settings (~/Library/Application Support/Keylo) are left alone.
#   ./install.sh              install from dist/Keylo.app
#   ./install.sh --uninstall  remove the program only
set -euo pipefail
cd "$(dirname "$0")"

target=$HOME/Applications/Keylo.app
link=$HOME/.local/bin/keylo
legacy=$HOME/.local/share/keylo   # the command-line-only install, before Keylo.app

if [[ ${1:-} == --uninstall ]]; then
  osascript -e 'quit app "Keylo"' >/dev/null 2>&1 || true
  rm -rf "$target" "$link" "$legacy"
  echo "Keylo uninstalled. Secrets in your login keychain and settings were left in place."
  exit 0
fi

[[ -d dist/Keylo.app ]] || { echo "Nothing to install. Run ./build.sh first." >&2; exit 1; }
osascript -e 'quit app "Keylo"' >/dev/null 2>&1 || true
mkdir -p "$HOME/Applications" "$(dirname "$link")"
rsync -a --delete dist/Keylo.app/ "$target/"
ln -sf "$target/Contents/MacOS/keylo" "$link"
rm -rf "$legacy"

echo "Installed $target"
echo "  - open it from ~/Applications or Spotlight, or run: keylo"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) echo "  - 'keylo' is on your PATH" ;;
  *) echo "  - add ~/.local/bin to your PATH (e.g. in ~/.zshrc): export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
