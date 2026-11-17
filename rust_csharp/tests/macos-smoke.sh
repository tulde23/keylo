#!/bin/zsh
# End-to-end check of the macOS build against a throwaway keychain (never your login keychain).
#   ./build.sh && tests/macos-smoke.sh [path/to/mcp_client.py]
# Covers: keychain items, large values (protected files under the keychain master key), typed
# secrets, keylo run, access keys, and (with an MCP test client) search + run_with_secrets with
# redaction. Touch ID isn't exercised (Windows Hello / Touch ID is off for the run).
set -euo pipefail
cd "$(dirname "$0")/.."

keylo=$PWD/dist/Keylo.app/Contents/MacOS/keylo

export KEYLO_HOME=$(mktemp -d /tmp/keylo-smoke-home.XXXXXX)
export KEYLO_PREFIX=KeyloSmoke:
export KEYLO_KEYCHAIN=$KEYLO_HOME/smoke.keychain-db

cleanup() { security delete-keychain "$KEYLO_KEYCHAIN" 2>/dev/null || true; rm -rf "$KEYLO_HOME"; }
trap cleanup EXIT

security create-keychain -p smoke "$KEYLO_KEYCHAIN"
security unlock-keychain -p smoke "$KEYLO_KEYCHAIN"
security set-keychain-settings "$KEYLO_KEYCHAIN"   # no auto-lock during the run
echo '{"hello":"never"}' > "$KEYLO_HOME/config.json"

pass=0
check() { # check NAME EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "  ok   $1"
  else echo "  FAIL $1: expected [$2], got [$3]"; exit 1; fi
}

echo "keylo: $("$keylo" version)"

printf 's3cret-value' | "$keylo" set plain --category dev --username me >/dev/null
check "get plain" "s3cret-value" "$("$keylo" get plain)"
check "get --field username" "me" "$("$keylo" get plain --field username)"
check "list" "1" "$("$keylo" list --json | grep -c '"name": "plain"' || true)"

head -c 20000 /dev/urandom | base64 > "$KEYLO_HOME/big.txt"
"$keylo" set big --file "$KEYLO_HOME/big.txt" >/dev/null
check "large value round-trips" "$(cat "$KEYLO_HOME/big.txt")" "$("$keylo" get big)"
check "large value stored as a protected file" "1" "$(ls "$KEYLO_HOME"/blobs/*.bin | wc -l | tr -d ' ')"

printf 'pw-123' | "$keylo" set db --type database --field engine=postgres --field host=db.local --field username=alice >/dev/null
check "typed field" "postgresql://alice:pw-123@db.local/" "$("$keylo" get db --field connection_string)"

"$keylo" edit plain --rename renamed --category ops >/dev/null
check "rename keeps the value" "s3cret-value" "$("$keylo" get renamed)"

check "keylo run passes the value" "12" "$("$keylo" run --env X=renamed -- /bin/sh -c 'printf %s ${#X}')"

token=$("$keylo" keys create smoke --all 2>/dev/null)
check "access key created" "kyl_" "${token:0:4}"

if [[ -n ${1:-} ]]; then
  out=$(KEYLO_ACCESS_KEY=$token python3 "$1" "$keylo" '[["search_secrets",{"query":"db"}],["run_with_secrets",{"env":{"P":"db:password"},"command":"echo leaked=$P"}]]')
  check "mcp search sees the schema" "1" "$(echo "$out" | grep -c '"connection_string"' || true)"
  check "mcp run output is redacted" "1" "$(echo "$out" | grep -c 'leaked=\[keylo:db:password\]' || true)"
fi

for name in renamed big db; do "$keylo" rm "$name" --yes >/dev/null; done
check "all removed" "0" "$("$keylo" list --json | grep -c '"name"' || true)"
echo "macOS smoke test passed ($pass checks)."
