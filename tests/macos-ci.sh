#!/usr/bin/env bash
# macOS checks for the Rust build in CI: the keylo command against a throwaway keychain
# (KEYLO_KEYCHAIN), never the login keychain. Touch ID can't run on a CI machine, so the identity
# check is off (hello = never); try it on a real Mac.
#   tests/macos-ci.sh [path/to/keylo]
set -euo pipefail
cd "$(dirname "$0")/.."
keylo=${1:-target/debug/keylo}

keychain="${RUNNER_TEMP:-}/keylo-ci.keychain-db"
[[ -n ${RUNNER_TEMP:-} ]] || keychain="$(mktemp -d)/keylo-ci.keychain-db"
security create-keychain -p ci-password "$keychain"
security set-keychain-settings "$keychain"          # no auto-lock
security unlock-keychain -p ci-password "$keychain"
trap 'security delete-keychain "$keychain" 2>/dev/null || true' EXIT

# Pin the Keychain store: CI runners have no desktop session, so auto-detect would otherwise fall
# back to the passphrase vault file (tested separately below).
export KEYLO_KEYCHAIN=$keychain KEYLO_HOME=$(mktemp -d) KEYLO_PREFIX="KeyloCiTest:" KEYLO_STORE=keychain
echo '{"hello":"never"}' > "$KEYLO_HOME/config.json"

pass=0
check() { # NAME EXPECTED ACTUAL
  if [[ "$3" == *"$2"* ]]; then pass=$((pass + 1)); echo "  ok   $1"
  else echo "  FAIL $1: expected [$2], got [$3]"; exit 1; fi
}

"$keylo" version
printf 'mac-value' | "$keylo" set plain --category dev --username alice >/dev/null
check "value round-trips" "mac-value" "$("$keylo" get plain)"
check "username" "alice" "$("$keylo" get plain --field username)"
check "category" "plain" "$("$keylo" list cat:dev)"
# Secrets live in the SQLite vault now, not as individual Keychain items.
check "secret is in the vault file" "keylo.db" "$(ls "$KEYLO_HOME")"
if security dump-keychain "$keychain" 2>/dev/null | grep -q 'KeyloCiTest:plain'; then
  echo "  FAIL secret leaked into the Keychain as an item"; exit 1
else
  pass=$((pass + 1)); echo "  ok   secret is not a Keychain item (it's in the vault)"
fi

head -c 40000 /dev/urandom | base64 > "$KEYLO_HOME/big.txt"
"$keylo" set big --file "$KEYLO_HOME/big.txt" >/dev/null
check "large value (sealed file, master key in the keychain)" "$(cat "$KEYLO_HOME/big.txt")" "$("$keylo" get big)"
check "master key (vault + files) in the keychain" "Keylo.Internal" "$(security dump-keychain "$keychain" 2>/dev/null | grep -o 'Keylo.Internal' | head -1)"

printf 'pw-1' | "$keylo" set db --type database --field engine=postgres --field host=db.local --field username=bob >/dev/null
check "typed field" "postgresql://bob:pw-1@db.local/" "$("$keylo" get db --field connection_string)"
"$keylo" edit db --rename orders-db >/dev/null
check "rename" "orders-db" "$("$keylo" list)"

for n in plain big orders-db; do "$keylo" rm "$n" --yes >/dev/null 2>&1 || true; done
check "all removed" "0" "$("$keylo" list --json | grep -c '"name"' || true)"
check "status" "Keylo" "$("$keylo" status)"

# The headless fallback: a passphrase-protected vault file, no Keychain (as over SSH or on a server).
echo "== headless vault file (KEYLO_STORE=file)"
(
  export KEYLO_STORE=file KEYLO_HOME=$(mktemp -d) KEYLO_PREFIX="KeyloCiFile:" KEYLO_PASSPHRASE="correct horse battery staple 7"
  echo '{"hello":"never"}' > "$KEYLO_HOME/config.json"
  printf 'file-value' | "$keylo" set plain --category dev >/dev/null
  check "file vault: value round-trips" "file-value" "$("$keylo" get plain)"
  check "file vault: it's the vault file, not the Keychain db" "vault.json" "$(ls "$KEYLO_HOME")"
  check "file vault: status names it" "encrypted vault" "$("$keylo" status)"
  check "file vault: run delivers the value" "V=file-value" "$("$keylo" run --env V=plain -- sh -c 'echo V=$V')"
  # Binary round-trips through --file (a file vault stores raw bytes, no Keychain involved).
  printf '\000\377\001\002' > "$KEYLO_HOME/bin"
  "$keylo" set cert --file "$KEYLO_HOME/bin" >/dev/null
  check "file vault: binary via --file" "len=4" "$("$keylo" run --file C=cert -- sh -c 'printf len=%s "$(wc -c < "$C" | tr -d " ")"')"
)
echo "$pass checks passed."
