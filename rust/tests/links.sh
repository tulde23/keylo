#!/usr/bin/env bash
# Linked secrets (1Password, AWS Secrets Manager, per-environment links), push and provider
# commands, and the MCP server's link and AWS tools, against fake `op` and `aws` (tests/fakevault)
# in a throwaway data folder and credential prefix. Never touches real vaults or secrets.
#   rust/tests/links.sh FAKEVAULT_DIR [path/to/keylo.exe]
cd "$(dirname "$0")/.."
FAKE=${1:?Usage: tests/links.sh FAKEVAULT_DIR (a folder with the fake op.exe and aws.exe)}
K=$(realpath "${2:-target/debug/keylo.exe}")
T=$(mktemp -d)
export KEYLO_HOME="$T" KEYLO_PREFIX="KeyloLinkTest$RANDOM:" FAKE_LOG="$T/fake.log"
export PATH="$FAKE:$PATH"
export AWS_CONFIG_FILE="$T/aws-config" AWS_SHARED_CREDENTIALS_FILE="$T/aws-credentials"
unset AWS_REGION AWS_DEFAULT_REGION AWS_PROFILE KEYLO_ACCESS_KEY
echo '{"hello":"never"}' > "$T/config.json"
printf '[default]\nregion = us-west-2\n[profile dev-p]\nsso_session = corp\nregion = us-east-1\n[profile uat-p]\nregion = us-east-1\n[profile prod-p]\nrole_arn = arn:aws:iam::1:role/x\n' > "$AWS_CONFIG_FILE"
printf '[ci]\naws_access_key_id = AKIAFAKE\naws_secret_access_key = fake\n' > "$AWS_SHARED_CREDENTIALS_FILE"

pass=0; fail=0
check() { # name expected actual
  if [[ "$3" == *"$2"* ]]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $1"; echo "  expected: $2"; echo "  got: $3"; fi
}
k() { "$K" "$@" 2>&1; }

check "1p search lists both accounts" "acme.1password.com" "$(k link --search git)"
check "ambiguous title" "matches 2 items" "$(k link gh --item GitHub)"
check "link 1p" "category '1Password · Private (personal)'" "$(k link gh --item GitHub --vault Private)"
check "get main field" "fake-gh-password-123" "$(k get gh)"
check "get field" "fake-gh-token-456" "$(k get gh:api_token)"
check "get --both" "website: https://github.com" "$(k get gh --both)"
check "item get used account + reveal" "item get gh1 --format json --vault v1 --account my.1password.com --reveal" "$(cat "$FAKE_LOG")"
check "list shows link" "gh" "$(k list)"
check "@env on plain link" "isn't linked per environment" "$(k get gh@dev)"

k provider env aws set dev dev-p us-east-1 >/dev/null
k provider env aws set uat uat-p >/dev/null
check "prod is always-ask" "always asks" "$(k provider env aws set prod prod-p us-east-2)"
k provider env aws default dev >/dev/null
check "env list" "prod         prod-p" "$(k provider env aws list)"
check "per-env link" "Use it as orders-db@ENV (dev, prod, uat)" "$(k link orders-db --provider aws --item orders/db --environment dev --env-name prod=orders/db-prod)"
check "default env" "fake-dev-pw" "$(k get orders-db)"
check "uat field" "uat.db" "$(k get orders-db@uat:host)"
check "prod own name" "fake-prod-pw" "$(k get orders-db@prod)"
check "uat region from profile" "--region us-east-1 --profile uat-p" "$(grep 'get-secret-value.*uat-p' "$FAKE_LOG" | head -1)"
check "unknown env" "There's no environment 'qa'" "$(k get orders-db@qa)"
check "run with env" "P=fake-uat-pw" "$(k run --env P=orders-db@uat:password -- cmd //c echo P=%P%)"

check "plain aws link" "Fields: username, password, host" "$(k link web --provider aws --profile dev-p --region eu-west-1 --item orders/db)"
check "plain aws get" "orders_dev" "$(k get web:username)"
check "expired explains" "aws sso login --profile expired" "$(k link --search x --provider aws --profile expired --region us-east-1)"
check "unknown profile" "no profile named 'nope'" "$(k link --search x --provider aws --profile nope)"

printf 'fake-plain-value' | k set plain-x --category Pushme >/dev/null
check "push needs vault" "Set a vault" "$(k push 1password plain-x --yes)"
k provider set 1password vault Private >/dev/null
check "push 1p" "Created in 'Private'" "$(k push 1password plain-x --yes)"
check "op got value on stdin" '"value":"fake-plain-value"' "$(grep 'op stdin' "$FAKE_LOG")"
check "value not on op command line" "" "$(grep '^op item create' "$FAKE_LOG" | grep -c fake-plain-value | sed 's/^0$//')"
k provider set aws region us-east-1 >/dev/null
check "push aws" "Created “keylo/plain-x” in us-east-1" "$(k push aws plain-x --yes)"
check "aws value via file" "aws value file: fake-plain-value" "$(cat "$FAKE_LOG")"
check "temp file gone" "0" "$(ls "${TMP:-/tmp}" 2>/dev/null | grep -c '^keylo-.*\.tmp$')"
check "provider list" "region=✓" "$(k provider list)"

# MCP: a key for everything, then search and run.
KEY=$(k keys create linktest --all | grep -oE 'kyl_[A-Za-z0-9_-]+' | head -1)
mcp() { printf '%s\n' "$1" | KEYLO_ACCESS_KEY="$KEY" "$K" mcp --stdio 2>&1; }
INIT='{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
out=$(mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_secrets","arguments":{"query":"orders"}}}')
check "mcp search environments" 'alwaysAsk\":[\"prod\"]' "$out"
check "mcp link type" '\"type\":\"link\"' "$out"
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"env":{"P":"orders-db@uat:password","H":"orders-db@uat:host"},"command":"echo pw=%P% host=%H%","shell":"cmd"}}}')
check "mcp run redacts linked value" 'pw=[keylo:orders-db:password]' "$out"
out=$(mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_aws_profiles","arguments":{}}}')
check "mcp aws profiles" 'signIn\":\"assume role' "$out"
check "mcp aws profiles no keys" "" "$(echo "$out" | grep -o AKIAFAKE)"
out=$(mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_aws_secrets","arguments":{"environment":"dev"}}}')
check "mcp aws secrets linked" 'linkedInKeyloAs\":[\"web\",\"orders-db\"]' "$out"
check "audit has env label" "orders-db@uat" "$(cat "$T/audit.log" 2>/dev/null)"

# keys create --add-to-claude registers the server through (the fake) claude.
check "add to claude" "added Keylo to Claude Code" "$(k keys create claude-test --all --add-to-claude)"
check "claude mcp add args" "claude mcp add keylo --scope user --env KEYLO_ACCESS_KEY=kyl_" "$(cat "$FAKE_LOG")"
check "claude mcp remove first" "claude mcp remove keylo --scope user" "$(cat "$FAKE_LOG")"

# Clean up the throwaway credentials.
for n in gh orders-db web plain-x; do k rm "$n" --yes >/dev/null; done
echo "left: $(cmdkey //list | grep -c "$KEYLO_PREFIX")"
rm -rf "$T"
echo "passed $pass, failed $fail"
[[ $fail == 0 ]]
