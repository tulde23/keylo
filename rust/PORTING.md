# Keylo in Rust + Tauri

The Rust port lives in `rust/`, next to the C# code it replaces. It shares the C# build's data
exactly (secrets in the OS store, `config.json`, `types.json`, `session.bin`, `audit.log`, the
encrypted `blobs/` files), so both builds can be used on one machine during the move.

## Layout

| Crate | What |
|---|---|
| `crates/keylo-core` | Store format, secret types, settings, access keys, the identity gate, audit log, redaction, search, pins/recent |
| `crates/keylo-platform` | The OS layer: Windows (Credential Manager, DPAPI, Windows Hello, clipboard, process ancestry); macOS and Linux to come |
| `crates/keylo-cli` | The `keylo` command and the MCP server (`keylo mcp`) |
| `app/` (to come) | The Tauri app with a React front end |

## Building on Windows

Cargo needs the MSVC x64 libraries. On a machine where the newest Visual Studio lacks them
(LNK1104 `msvcrt.lib`), build inside an older install's environment, e.g.:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cargo build --release
```

`tests/windows-compat.sh` checks the Rust and C# builds read each other's secrets and keys, and
exercises the MCP server, in a throwaway data folder and credential prefix.

## Status

| Area | State |
|---|---|
| Store format, types, config, keys, gate, audit, redaction | Done; compatible with C# (22 checks) |
| Windows platform | Done (Credential Manager, DPAPI, Hello, clipboard, ancestry) |
| CLI: list, categories, types, get, set, edit, rm, run, keys, unlock, lock, status, config, version | Done |
| MCP server: search_secrets, list_categories, list_types, run_with_secrets, request_access | Done; approvals use a message box until the app exists |
| CLI: import, link, push, provider, backup, restore, keys --add-to-claude | To do |
| Linked secrets (1Password, AWS Secrets Manager, per-environment links), list_aws_* tools | To do |
| Tauri + React app (secrets, details, settings, access keys, types, categories, approval window) | To do: designed fresh, not a copy of the WPF/Avalonia screens |
| macOS platform (Keychain, Touch ID) and Linux (Secret Service / file vault, polkit) | To do |
| Packaging and CI (release workflow, signing, notarization) | To do |
