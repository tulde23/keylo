# Keylo

Local secrets for one Windows machine, stored in Windows Credential Manager, with a command line
(`keylo`) and a desktop app (`keylow`). No server, no account, no sync.

## Install

```powershell
./build.ps1 -Install     # publish to dist\Keylo, then install to %LOCALAPPDATA%\Programs\Keylo
```

This adds Keylo to your user PATH and the Start menu. Requires the .NET 10 runtime.
`./install.ps1 -Uninstall` removes the program but leaves your secrets.

## Use

| | |
|---|---|
| `keylo` | Open the app |
| `keylo set NAME [--category C] [--username U] [--notes N] [--file F]` | Add or update (value is prompted, piped, or read from a file) |
| `keylo list [search…] [--category C] [--json]` | Search names, categories, usernames and notes (never values) |
| `keylo get NAME [--clip] [--out FILE] [--field username]` | Print, copy (auto-clears) or export |
| `keylo edit NAME [--rename NEW] [--category C] …` | Change details without touching the value |
| `keylo rm NAME` | Delete |
| `keylo import PATH… [--category C] [--overwrite] [--delete-originals]` | One secret per file; subfolders become categories |
| `keylo run --env VAR=NAME [...] -- CMD ARGS` | Run a command with secrets as environment variables |
| `keylo push 1password [NAME…] [--category C] [--all]` | Copy secrets into another vault |
| `keylo backup FILE [--force]` | Password-protected backup of every secret, category and icon |
| `keylo restore FILE [--overwrite] [--dry-run]` | Restore one (existing secrets are kept unless `--overwrite`) |
| `keylo trust` | Show trust groups and whether the current caller matches |
| `keylo unlock` / `lock` / `status` / `config` | Windows Hello session and settings |

Migrating a `.secrets` folder: `keylo import .\.secrets`, check `keylo list`, then re-run with
`--overwrite --delete-originals` (or delete the folder yourself).

## In the app

- **Search** across name, category, key and notes; filter by category in the sidebar.
- **Import** files or folders (button, drag and drop, or `keylow --import PATH`). The dialog
  previews the result and lets you use subfolder names, put everything in one existing or new
  category, or leave them uncategorized, and choose whether to replace existing secrets.
- **Multi-select** with Ctrl/Shift+click (Ctrl+A for all) to move secrets to a category or delete
  them in bulk. Delete on the list deletes the selection, after confirming.
- **Category manager** (Manage, next to Categories): create empty categories, rename (applies to
  every secret in it), rename onto another to merge, delete (moving its secrets to another
  category, to none, or deleting them), and set icons.
- **Icons and colours** for secrets and categories: a built-in icon set, colour swatches, or an
  uploaded image (resampled to fit its box, never cropped, stored in `%LOCALAPPDATA%\Keylo\icons`).
  A secret without its own icon uses its category's.
- **Resizable panels**: drag the dividers; widths are remembered.

## How it stores things

- **Values up to 2,559 bytes** live in the Credential Manager entry `Keylo:<name>` (visible in
  Control Panel → Credential Manager). Username and notes use the entry's own fields; the category
  is a credential attribute.
- **Larger values** (certificates, key files) are DPAPI-encrypted into
  `%LOCALAPPDATA%\Keylo\blobs\`, referenced from the Credential Manager entry.
- Both are tied to your Windows account on this machine. Nothing roams.
- `%LOCALAPPDATA%\Keylo\config.json` holds settings; `audit.log` records access that skipped Windows Hello.
- Icon and colour choices are credential attributes on each secret; category icons, colours and
  empty categories are in `categories.json`; window layout is in `ui.json`. None of these hold values.

## Backups

Keylo's normal storage only opens for your Windows account on this PC. A backup (Settings →
Backup & restore, or `keylo backup`) is what gets your secrets onto a new PC or survives a lost account.

- One `.keylo` file: every secret's value and details, categories (including empty ones and their
  styles) and uploaded icons.
- Encrypted with **AES-256-GCM**; the key comes from your password via **PBKDF2-SHA256, 600,000
  iterations** and a random salt. The header is authenticated too, and nothing — not even secret
  names — is readable without the password. A wrong password or any change to the file is rejected.
- Creating one always asks for Windows Hello (it exports everything). Passwords must be at least
  10 characters; the CLI prompts for them (or reads `--password-stdin`) and never accepts one as an argument.
- **There is no recovery.** Keep the password somewhere other than Keylo.

## Windows Hello

`keylo config hello session|always|never` (or Settings in the app):

- **session** (default): verify once, then the app and CLI share a 15-minute unlock.
- **always**: verify every time a value is revealed, copied, exported or run.
- **never**: rely on your Windows sign-in only.

Changing these settings, or trust groups, always asks for Windows Hello.

**What this protects against:** other Windows users, a stolen or copied disk, backups, and
plaintext files getting committed or synced. **What it doesn't:** malware running as you — it can
read DPAPI-protected data directly. Windows Hello here is a presence check, not encryption.

## Trust groups (for Claude Code and other tools)

Managed in the app under Settings. A group lets named callers (`claude.exe`) use certain
categories or secrets without Windows Hello:

```bash
keylo run --env GITHUB_TOKEN=github-token -- gh repo list
```

- **Run-only by default.** `keylo get` still prompts, because a value an agent prints becomes part
  of its conversation. Turn on "Also allow printing values" per group only if you must.
- A trusted caller that isn't unlocked sees only the secrets its groups cover in `keylo list`.
- Every bypass is appended to the audit log (shown in Settings) with the full caller chain.
- Callers are matched by program name in the process ancestry, with parent start times checked to
  defeat PID reuse. It is **not** a security boundary: anything running as you can imitate a
  program name. Keep groups small.

## Vault providers

`IVaultProvider` (in `Keylo.Core.Providers`) pushes secrets to other vaults. Built in:

- **1Password** via the `op` CLI: `keylo provider set 1password vault Private`, then
  `keylo push 1password --category cloud`. Items are tagged `keylo`; pushing again updates them.
  Values go over stdin, never the command line.

Add others by building a class library that references `Keylo.Core`, implementing
`IVaultProvider` with a parameterless constructor, and dropping the DLL into
`%LOCALAPPDATA%\Keylo\plugins`. Plugins run as you with full trust.

## Develop

```powershell
dotnet build
dotnet test     # uses a separate Credential Manager prefix and cleans up after itself
```

`KEYLO_HOME` and `KEYLO_PREFIX` point the CLI and app at a scratch data folder and credential
prefix, which keeps experiments away from your real secrets.
