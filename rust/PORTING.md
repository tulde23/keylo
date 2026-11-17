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
| `app/` | The Tauri app (`keylow`): React front end in `app/src`, Rust commands in `app/src-tauri` |

## Building on Windows

Cargo needs the MSVC x64 libraries. On a machine where the newest Visual Studio lacks them
(LNK1104 `msvcrt.lib`), build inside an older install's environment, e.g.:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cargo build --release
```

`tests/windows-compat.sh` checks the Rust and C# builds read each other's secrets and keys, and
exercises the MCP server, in a throwaway data folder and credential prefix. `tests/links.sh` tests
linked secrets against fake `op` and `aws` programs (build `tests/fakevault`, copy it to `op.exe`
and `aws.exe` in one folder, and pass that folder; set `FAKEVAULT` to it for the compat link checks).

## Status

| Area | State |
|---|---|
| Store format, types, config, keys, gate, audit, redaction | Done; compatible with C# (38 checks with backups, import and links) |
| Windows platform | Done (Credential Manager, DPAPI, Hello, clipboard, ancestry) |
| CLI: list, categories, types, get, set, edit, rm, run, keys, unlock, lock, status, config, version | Done |
| MCP server: search_secrets, list_categories, list_types, run_with_secrets, request_access | Done; approvals use a message box until the app exists |
| CLI: import (type guessing, subfolder categories), backup, restore (C# KEYLOBK1 format, both directions) | Done |
| CLI: link, push, provider (settings, per-environment `provider env`) | Done |
| Claude Code registration: `keys create --add-to-claude`, status in `keylo mcp` and Settings → Access keys, Add to Claude Code in the app | Done |
| Linked secrets (1Password, AWS Secrets Manager, per-environment links, "always ask" environments), push, list_aws_* tools | Done in core, CLI and MCP: through the `op` and `aws` CLIs, not SDKs. `tests/links.sh` runs them against fake CLIs (`tests/fakevault`) |
| Tauri + React app: lock screen, top bar (ported from the WPF app, system window buttons), sidebar, list, detail, slide-in editor, settings, access keys, activity, approval window (`keylow --approve`) | Done (first version) |
| App: custom secret types editor (Settings → Secret types; built-ins: icon and colour) | Done |
| App: lock on screen lock, single instance | Done |
| App: categories manager (create, rename, merge, style, delete with move or delete), per-secret icon and colour | Done |
| App: icon images (upload, image address, paste; same icons/ files as C#), build number in the sidebar and lock screen | Done |
| App: import panel (Import tile, drop files on the window, `keylow --import PATH...`), Settings → Backup (back up, restore with preview) | Done |
| App: linked secrets (detail view with environment picker, Link panel for 1Password and AWS, details-only edit), push to a vault, Settings → Vault providers (settings, AWS environments with always ask and default) | Done |
| `keylo mcp` opening the app's approval window (message box only without the app) | Done; buttons wake after 0.8 s so a stray click can't answer |
| macOS platform (Keychain, Touch ID) and Linux (Secret Service / file vault, polkit) | To do |
| Packaging and CI (release workflow, signing, notarization) | To do |
