#!/usr/bin/env bash
# Stamps this build's version into Cargo.toml (the app, the keylo command and the installers read it
# from there): <major>.<minor> from Cargo.toml, then the workflow's run number, e.g. 1.2.0 -> 1.2.14.
# Each release is newer than the last, which the in-app updater relies on. Sets VERSION for later steps.
set -euo pipefail
base=$(sed -n 's/^version = "\([0-9]*\.[0-9]*\)\..*"/\1/p' Cargo.toml | head -1)
version="$base.${GITHUB_RUN_NUMBER:?}"
sed -i.bak "s/^version = \".*\"/version = \"$version\"/" Cargo.toml && rm Cargo.toml.bak
grep -q "^version = \"$version\"" Cargo.toml
echo "VERSION=$version" >> "${GITHUB_ENV:-/dev/null}"
echo "Version $version"
