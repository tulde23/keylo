#!/usr/bin/env bash
# End-to-end check of the Linux build in a throwaway data folder (never your real secrets).
#   tests/linux-smoke.sh [path/to/keylo]        (default: the newest dist/keylo-*-linux-*/lib/keylo)
# KEYLO_STORE picks the store under test: file (default; Keylo's vault) or keyring (needs a running,
# unlocked Secret Service, e.g. gnome-keyring in dbus-run-session). The identity check is off.
set -euo pipefail
cd "$(dirname "$0")/.."

keylo=${1:-$(ls -d dist/keylo-*-linux-*/lib/keylo 2>/dev/null | tail -1)}
[[ -x $keylo ]] || { echo "No keylo to test. Run ./build-linux.sh first, or pass its path." >&2; exit 1; }

export KEYLO_HOME=$(mktemp -d /tmp/keylo-smoke.XXXXXX)
export KEYLO_PREFIX=KeyloSmoke:
export KEYLO_STORE=${KEYLO_STORE:-file}
export KEYLO_PASSPHRASE=smoke-passphrase-1
export KEYLO_VAULT_CACHE_MINUTES=0
trap 'rm -rf "$KEYLO_HOME"' EXIT
echo '{"hello":"never"}' > "$KEYLO_HOME/config.json"

pass=0
check() { # check NAME EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "  ok   $1"
  else echo "  FAIL $1: expected [$2], got [$3]"; exit 1; fi
}

echo "keylo: $("$keylo" version) (store: $KEYLO_STORE)"

if [[ $KEYLO_STORE == file ]]; then
  # A new vault is created from KEYLO_PASSPHRASE on first use.
  printf 'first' | "$keylo" set first >/dev/null
  check "vault created" "1" "$(ls "$KEYLO_HOME/vault.json" | wc -l)"
  check "vault is private (0600)" "600" "$(stat -c %a "$KEYLO_HOME/vault.json")"
  check "value isn't readable in the vault file" "0" "$(grep -c first "$KEYLO_HOME/vault.json" || true)"
  check "wrong passphrase is refused" "1" "$(KEYLO_PASSPHRASE=wrong "$keylo" get first 2>&1 | grep -c "doesn't unlock" || true)"
  check "no passphrase, no terminal: clear message" "1" "$(env -u KEYLO_PASSPHRASE setsid "$keylo" get first </dev/null 2>&1 | grep -c "vault is locked" || true)"
  "$keylo" rm first --yes >/dev/null
fi

printf 's3cret-value' | "$keylo" set plain --category dev --username me >/dev/null
check "get plain" "s3cret-value" "$("$keylo" get plain)"
check "get --field username" "me" "$("$keylo" get plain --field username)"
check "list" "1" "$("$keylo" list --json | grep -c '"name": "plain"' || true)"

head -c 20000 /dev/urandom | base64 > "$KEYLO_HOME/big.txt"
"$keylo" set big --file "$KEYLO_HOME/big.txt" >/dev/null
check "large value round-trips" "$(cat "$KEYLO_HOME/big.txt")" "$("$keylo" get big)"
check "large value stored as a protected file" "1" "$(ls "$KEYLO_HOME"/blobs/*.bin | wc -l)"

printf 'pw-123' | "$keylo" set db --type database --field engine=postgres --field host=db.local --field username=alice >/dev/null
check "typed field" "postgresql://alice:pw-123@db.local/" "$("$keylo" get db --field connection_string)"

"$keylo" edit plain --rename renamed --category ops >/dev/null
check "rename keeps the value" "s3cret-value" "$("$keylo" get renamed)"

check "keylo run passes the value" "12" "$("$keylo" run --env X=renamed -- /bin/sh -c 'printf %s ${#X}')"

token=$("$keylo" keys create smoke --all 2>/dev/null)
check "access key created" "kyl_" "${token:0:4}"

# The MCP server: tools list (no get_secret), search, and a redacted run.
mcp() { # mcp JSON-LINES... → server output
  { printf '%s\n' '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
                  '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$@"; sleep 3; } |
    KEYLO_ACCESS_KEY=$token "$keylo" mcp --stdio 2>/dev/null
}
out=$(mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
          '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_secrets","arguments":{"query":"db"}}}' \
          '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"env":{"P":"db:password"},"command":"echo leaked=$P"}}}' \
          '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_secret","arguments":{"name":"db"}}}')
check "mcp has no get_secret tool" "0" "$(grep '"id":1' <<< "$out" | grep -c '"name":"get_secret"' || true)"
check "mcp search sees the schema" "1" "$(grep '"id":2' <<< "$out" | grep -c 'connection_string' || true)"
check "mcp run output is redacted" "1" "$(grep '"id":3' <<< "$out" | grep -c 'leaked=\[keylo:db:password\]' || true)"
check "mcp never prints the value" "0" "$(grep -c 'pw-123' <<< "$out" || true)"
check "mcp refuses get_secret" "1" "$(grep '"id":4' <<< "$out" | grep -c -i 'unknown tool' || true)"

for name in renamed big db; do "$keylo" rm "$name" --yes >/dev/null; done
check "all removed" "0" "$("$keylo" list --json | grep -c '"name"' || true)"
echo "Linux smoke test passed ($pass checks, store: $KEYLO_STORE)."
