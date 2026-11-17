#!/usr/bin/env bash
# Linux checks for the Rust build, run inside a throwaway container (see the docker command below):
# the vault-file store and the desktop keyring (gnome-keyring on a private D-Bus), each written by
# one build and read by the other when the C# build is given.
#
#   docker run --rm -v "$PWD:/src:ro" -v keylo-rust-target:/target [-v CSHARP_BUNDLE:/csharp:ro] \
#     rust:trixie bash /src/tests/linux-compat.sh
#
# /csharp is the unpacked C# release (keylo-X-linux-x64), optional. In CI: KEYLO_BIN=path/to/keylo
# tests/linux-compat.sh (gnome-keyring and dbus installed; no C# comparison).
set -euo pipefail

if [[ -n ${KEYLO_BIN:-} ]]; then
  # CI: a keylo already built; the runner installed gnome-keyring and dbus.
  rust=$KEYLO_BIN
else
  export CARGO_TARGET_DIR=/target DEBIAN_FRONTEND=noninteractive
  echo "== packages"
  apt-get update -qq >/dev/null
  apt-get install -y -qq gnome-keyring dbus libsecret-1-0 libicu-dev >/dev/null 2>&1
  echo "== build and unit tests"
  cd /src
  cargo build -q -p keylo-cli
  cargo test -q -p keylo-core -p keylo-platform 2>&1 | grep -E "test result|FAILED|panicked" || true
  rust=$CARGO_TARGET_DIR/debug/keylo
fi
csharp=/csharp/lib/keylo
[[ -x $csharp ]] || csharp=""

pass=0
check() { # NAME EXPECTED ACTUAL
  if [[ "$3" == *"$2"* ]]; then pass=$((pass + 1)); echo "  ok   $1"
  else echo "  FAIL $1: expected [$2], got [$3]"; exit 1; fi
}

suite() { # the same checks, in whichever store this environment selects
  local store=$1
  export KEYLO_HOME=$(mktemp -d) KEYLO_PREFIX="KeyloLinuxTest:"
  echo '{"hello":"never"}' > "$KEYLO_HOME/config.json"
  echo "== $store"
  printf 'rust-value' | $rust set rs-plain --category dev --username alice >/dev/null
  check "$store: Rust reads its own" "rust-value" "$($rust get rs-plain)"
  check "$store: status names the store" "$store" "$($rust status)"
  head -c 30000 /dev/urandom | base64 -w0 > "$KEYLO_HOME/big.txt"
  $rust set rs-big --file "$KEYLO_HOME/big.txt" >/dev/null
  check "$store: large value (protected file)" "$(cat "$KEYLO_HOME/big.txt")" "$($rust get rs-big)"
  printf 'pw-1' | $rust set rs-db --type database --field engine=postgres --field host=db.local --field username=bob >/dev/null
  check "$store: typed field" "db.local" "$($rust get rs-db --field host)"
  if [[ -n $csharp ]]; then
    check "$store: C# reads Rust's value" "rust-value" "$($csharp get rs-plain 2>&1)"
    check "$store: C# reads Rust's username" "alice" "$($csharp get rs-plain --field username 2>&1)"
    check "$store: C# reads Rust's large value" "$(cat "$KEYLO_HOME/big.txt")" "$($csharp get rs-big 2>&1)"
    check "$store: C# reads Rust's typed field" "postgresql://bob:pw-1@db.local/" "$($csharp get rs-db --field connection_string 2>&1)"
    printf 'csharp-value' | $csharp set cs-plain --category ops >/dev/null 2>&1
    check "$store: Rust reads C#'s value" "csharp-value" "$($rust get cs-plain)"
    check "$store: Rust sees C#'s category" "cs-plain" "$($rust list cat:ops)"
    head -c 30000 /dev/urandom | base64 -w0 > "$KEYLO_HOME/big2.txt"
    $csharp set cs-big --file "$KEYLO_HOME/big2.txt" >/dev/null 2>&1
    check "$store: Rust reads C#'s large value" "$(cat "$KEYLO_HOME/big2.txt")" "$($rust get cs-big)"
  fi
  for n in $($rust list --json | grep '"name"' | sed 's/.*"name": "\(.*\)",/\1/'); do $rust rm "$n" --yes >/dev/null; done
  check "$store: all removed" "0" "$($rust list --json | grep -c '"name"' || true)"
}

# 1. No desktop keyring: Keylo's vault file, unlocked with KEYLO_PASSPHRASE.
(
  # The vault, even where a keyring service could start on demand (as on CI machines).
  unset DBUS_SESSION_BUS_ADDRESS
  export KEYLO_STORE=file KEYLO_PASSPHRASE="correct horse battery staple"
  suite "encrypted vault"
  # A wrong passphrase is refused; the vault isn't readable without it.
  printf 'x1234' | $rust set probe >/dev/null
  $rust lock >/dev/null   # forget the cached vault key, so the passphrase is what's checked
  check "vault: wrong passphrase refused" "doesn't unlock" "$(KEYLO_PASSPHRASE='wrong passphrase!!' $rust get probe 2>&1 || true)"
  check "vault: file is sealed" "0" "$(grep -c x1234 "$KEYLO_HOME/vault.json" || true)"
  check "vault: the vault file exists" "keylo-vault" "$(head -c 200 "$KEYLO_HOME/vault.json")"
)

# 2. A desktop keyring (gnome-keyring on a private session bus, unlocked with a test password).
dbus-run-session -- bash -c '
  echo -n "keyring-test-password" | gnome-keyring-daemon --unlock --components=secrets >/dev/null 2>&1
  sleep 1
  '"$(declare -f check suite)"'
  rust='"$rust"' csharp='"$csharp"' pass=0
  suite "desktop keyring"
  check "keyring: remembered" "keyring" "$(cat "$KEYLO_HOME/store.txt")"
  echo "keyring checks: $pass"
'
echo "$pass vault checks passed (keyring counted above)."
