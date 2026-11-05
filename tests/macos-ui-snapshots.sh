#!/bin/zsh
# Debug builds only (./build.sh --debug): renders the Mac app's main screens to PNGs against a
# throwaway keychain and data folder, for checking the UI without a screen (e.g. over SSH).
#   tests/macos-ui-snapshots.sh [OUT_DIR]
#   KEYLO_SHOTS="settings scroll:1200" tests/macos-ui-snapshots.sh   (just these states)
set -euo pipefail
cd "$(dirname "$0")/.."

out=${1:-/tmp/keylo-snaps}
app=$PWD/dist/Keylo.app/Contents/MacOS
export KEYLO_HOME=$(mktemp -d /tmp/keylo-ui-home.XXXXXX)
export KEYLO_PREFIX=KeyloUiTest:
export KEYLO_KEYCHAIN=$KEYLO_HOME/ui.keychain-db

cleanup() { security delete-keychain "$KEYLO_KEYCHAIN" 2>/dev/null || true; rm -rf "$KEYLO_HOME"; }
trap cleanup EXIT

security create-keychain -p ui "$KEYLO_KEYCHAIN"
security unlock-keychain -p ui "$KEYLO_KEYCHAIN"
security set-keychain-settings "$KEYLO_KEYCHAIN"
# KEYLO_SNAPSHOT_CONFIG: a config.json to start from (e.g. with provider environments).
config='{"hello":"never"}'
print -r -- "${KEYLO_SNAPSHOT_CONFIG:-$config}" > "$KEYLO_HOME/config.json"
mkdir -p "$out" && rm -f "$out"/*.png(N)

printf 'hunter2' | "$app/keylo" set github-token --category dev --username octocat --notes "Personal token for CI" >/dev/null
printf 'pw-123' | "$app/keylo" set prod-db --type database --field engine=postgres --field host=db.local --field port=5432 \
  --field database=app --field username=alice --category ops >/dev/null
printf 'abc' | "$app/keylo" set stripe-key --category billing >/dev/null
echo '["prod-db"]' > "$KEYLO_HOME/pins.json"

shots=(${=KEYLO_SHOTS:-home select:prod-db edit:prod-db new settings categories light lock})
spec=""
for i in {1..${#shots}}; do spec+="${shots[$i]}=$out/$(printf %02d $i)-${shots[$i]//:/-}.png;"; done
KEYLO_SNAPSHOTS=$spec "$app/KeyloApp" &
pid=$!
for _ in {1..60}; do kill -0 $pid 2>/dev/null || break; sleep 1; done
kill $pid 2>/dev/null && echo "app didn't exit; killed" >&2

for name in github-token prod-db stripe-key; do "$app/keylo" rm "$name" --yes >/dev/null; done
ls "$out"
