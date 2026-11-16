#!/usr/bin/env bash
# Checks that the Rust keylo and the C# keylo share one store on Windows: each reads what the other
# wrote (plain, typed, large file-backed values, access keys), and the Rust MCP server works.
# Uses a throwaway data folder and credential prefix, so real secrets are never touched.
#   rust/tests/windows-compat.sh [path/to/rust/keylo.exe] [path/to/csharp/keylo.exe]
set -euo pipefail
cd "$(dirname "$0")/.."

rust=${1:-target/debug/keylo.exe}
csharp=${2:-$LOCALAPPDATA/Programs/Keylo/keylo.exe}
[[ -x $rust && -x $csharp ]] || { echo "Need both keylo builds: $rust and $csharp" >&2; exit 1; }

export KEYLO_HOME=$(mktemp -d)
export KEYLO_PREFIX="KeyloCompat$RANDOM:"
unset KEYLO_ACCESS_KEY
echo '{"hello":"never"}' > "$KEYLO_HOME/config.json"
cleanup() {
  for n in $("$rust" list --json 2>/dev/null | grep '"name"' | sed 's/.*"name": "\(.*\)",/\1/'); do
    "$rust" rm "$n" --yes >/dev/null 2>&1 || true
  done
  rm -rf "$KEYLO_HOME"
}
trap cleanup EXIT

pass=0
check() { # check NAME EXPECTED ACTUAL
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "  ok   $1"
  else echo "  FAIL $1: expected [$2], got [$3]"; exit 1; fi
}

echo "rust:   $("$rust" version)"
echo "csharp: $("$csharp" version)"

# C# writes, Rust reads.
printf 'from-csharp' | "$csharp" set cs-plain --category dev --username alice --notes "a note" >/dev/null 2>&1
check "plain value written by C#" "from-csharp" "$("$rust" get cs-plain)"
check "username written by C#" "alice" "$("$rust" get cs-plain --field username)"
check "category written by C#" "1" "$("$rust" list cat:dev 2>/dev/null | grep -c cs-plain || true)"
printf 'pw-1' | "$csharp" set cs-db --type database --field engine=postgres --field host=db.local --field username=bob >/dev/null 2>&1
check "typed main field written by C#" "pw-1" "$("$rust" get cs-db)"
check "derived connection string" "postgresql://bob:pw-1@db.local/" "$("$rust" get cs-db --field connection_string)"
head -c 6000 /dev/urandom | base64 -w0 > "$KEYLO_HOME/big.txt"
"$csharp" set cs-big --file "$KEYLO_HOME/big.txt" >/dev/null 2>&1
check "large (DPAPI file) value written by C#" "$(cat "$KEYLO_HOME/big.txt")" "$("$rust" get cs-big)"

# Rust writes, C# reads.
printf 'from-rust' | "$rust" set rs-plain --category ops --username carol >/dev/null 2>&1
check "plain value written by Rust" "from-rust" "$("$csharp" get rs-plain | tr -d '\r')"
check "username written by Rust" "carol" "$("$csharp" get rs-plain --field username | tr -d '\r')"
printf 'tok-2' | "$rust" set rs-login --type login --field username=dave --field url=https://example.com >/dev/null 2>&1
check "typed secret written by Rust" "tok-2" "$("$csharp" get rs-login | tr -d '\r')"
check "non-secret field written by Rust" "https://example.com" "$("$csharp" get rs-login --field url | tr -d '\r')"
head -c 6000 /dev/urandom | base64 -w0 > "$KEYLO_HOME/big2.txt"
"$rust" set rs-big --file "$KEYLO_HOME/big2.txt" >/dev/null 2>&1
check "large value written by Rust" "$(cat "$KEYLO_HOME/big2.txt")" "$("$csharp" get rs-big | tr -d '\r\n')"
check "C# lists Rust's category" "1" "$("$csharp" list cat:ops 2>/dev/null | grep -c rs-plain || true)"

# Edit and rename across builds.
"$rust" edit cs-plain --rename cs-renamed --category ops >/dev/null 2>&1
check "rename by Rust keeps the value" "from-csharp" "$("$csharp" get cs-renamed | tr -d '\r')"

# keylo run.
check "rust run passes the value" "11" "$("$rust" run --env X=cs-renamed -- bash -c 'printf %s ${#X}')"

# Access keys: created by Rust, listed by C#; the Rust MCP server.
token=$("$rust" keys create compat --category ops 2>/dev/null)
check "access key created" "kyl_" "${token:0:4}"
check "C# sees the key" "1" "$("$csharp" keys 2>/dev/null | grep -c compat || true)"
mcp() {
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' "$1" |
    KEYLO_ACCESS_KEY=$token "$rust" mcp --stdio 2>/dev/null
}
check "mcp has no get_secret" "0" "$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | grep -c get_secret || true)"
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_secrets","arguments":{"query":"rs-plain"}}}')
check "mcp search: covered secret is usable" "1" "$(grep -c '\\"access\\":\\"run\\"' <<< "$out" || true)"
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"env":{"T":"rs-plain"},"command":"echo value=$T","shell":"bash"}}}')
check "mcp run output is redacted" "1" "$(grep -c 'value=\[keylo:rs-plain\]' <<< "$out" || true)"
check "mcp never prints the value" "0" "$(grep -c from-rust <<< "$out" || true)"
check "audit log written" "1" "$(grep -c '"via":"access key"' "$KEYLO_HOME/audit.log" || true)"
"$csharp" keys revoke compat >/dev/null 2>&1
check "key revoked by C# stops the Rust server" "1" "$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_types","arguments":{}}}' | grep -c "isn't valid" || true)"

echo "$pass checks passed."
