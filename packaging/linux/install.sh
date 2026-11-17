#!/usr/bin/env bash
# Installs Keylo for this user, from the folder this script is in (the Linux release tarball):
#   ~/.local/lib/keylo       keylow (the app) and keylo (the command)
#   ~/.local/bin/keylo       link to the command
#   a menu entry and icon, and (with sudo, once) Keylo's polkit policy for the identity check.
# Secrets and settings (~/.local/share/Keylo, the keyring) are left alone by --uninstall.
#   ./install.sh                 install
#   ./install.sh --no-polkit     skip the polkit policy (no sudo)
#   ./install.sh --uninstall     remove the program only
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

lib=$HOME/.local/lib/keylo
link=$HOME/.local/bin/keylo
apps=$HOME/.local/share/applications
desktop=$apps/io.github.tulde23.keylo.desktop
icon=$HOME/.local/share/icons/hicolor/256x256/apps/io.github.tulde23.keylo.png
policy=/usr/share/polkit-1/actions/io.github.tulde23.keylo.policy

if [[ ${1:-} == --uninstall ]]; then
  pkill -x keylow 2>/dev/null || true
  rm -rf "$lib" "$link" "$desktop" "$icon"
  echo "Keylo uninstalled. Your secrets and settings were left in place."
  [[ -f $policy ]] && echo "To remove its polkit policy too: sudo rm $policy"
  exit 0
fi

[[ -x $here/keylow && -x $here/keylo ]] || { echo "This isn't a Keylo bundle (no keylow and keylo next to install.sh)." >&2; exit 1; }
pkill -x keylow 2>/dev/null || true

rm -rf "$lib"
mkdir -p "$lib" "$(dirname "$link")" "$apps" "$(dirname "$icon")"
cp "$here/keylow" "$here/keylo" "$lib/"
ln -sf "$lib/keylo" "$link"
cp "$here/keylo.png" "$icon"
cat > "$desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Keylo
Comment=Your secrets, for you and your AI agents
Exec=$lib/keylow
Icon=io.github.tulde23.keylo
Terminal=false
Categories=Utility;Security;
StartupWMClass=keylow
EOF
command -v update-desktop-database >/dev/null && update-desktop-database -q "$apps" 2>/dev/null || true
echo "Installed Keylo in $lib"

# The identity check (Keylo's Windows Hello / Touch ID) is a polkit action, which needs a policy file.
if [[ " $* " != *" --no-polkit "* ]]; then
  if [[ -f $policy ]] && cmp -s "$here/io.github.tulde23.keylo.policy" "$policy"; then
    :
  elif command -v pkcheck >/dev/null; then
    echo "Installing Keylo's polkit policy (asks for sudo)..."
    sudo install -m 644 "$here/io.github.tulde23.keylo.policy" "$policy" ||
      echo "  skipped: without it, run 'keylo config hello never' (no identity check)."
  else
    echo "  polkit isn't installed, so there's no identity check: run 'keylo config hello never'."
  fi
fi

# What the app and the optional parts need from the system.
missing=()
ldconfig -p 2>/dev/null | grep -q libwebkit2gtk-4.1.so.0 || missing+=("libwebkit2gtk-4.1-0 (needed by the app, keylow; the keylo command works without it)")
command -v zenity >/dev/null || command -v kdialog >/dev/null || missing+=("zenity or kdialog (approval dialogs for AI agents without the app)")
command -v wl-copy >/dev/null || command -v xclip >/dev/null || command -v xsel >/dev/null || missing+=("wl-clipboard or xclip (copying)")
if ((${#missing[@]})); then
  echo "Not installed:"
  printf '  - %s\n' "${missing[@]}"
fi

case ":$PATH:" in
  *":$HOME/.local/bin:"*) echo "Run 'keylo help' for the command, or open Keylo from your menu." ;;
  *) echo "Add ~/.local/bin to your PATH (e.g. in ~/.bashrc): export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
