# Keylo

*Your secrets, kept close.*

Local secrets for one machine, with a command line (`keylo`) and a desktop app. On Windows they
live in Credential Manager (app: `keylow`); on macOS in your login keychain (app: Keylo.app).
No server, no account, no sync. Backups move between the two.

## Install

```powershell
./build.ps1 -Install     # publish to dist\Keylo, then install to %LOCALAPPDATA%\Programs\Keylo
```

This adds Keylo to your user PATH and the Start menu. Requires the .NET 10 runtime.
`./install.ps1 -Uninstall` removes the program but leaves your secrets.

## macOS

Keylo.app (the same app, on Avalonia) plus the `keylo` command and its MCP server, on Apple
silicon or Intel.

```zsh
./build.sh --install    # needs the .NET 10 SDK and Xcode command-line tools (swiftc)
```

This builds `dist/Keylo.app` (self-contained: no .NET install needed to run it), copies it to
`~/Applications`, and links `~/.local/bin/keylo` to the command inside it. Run `keylo` with no
arguments to open the app. `./install.sh --uninstall` removes the program but leaves your secrets.

- `keylo` is the app's own executable in command-line mode, so the keychain sees one app. It's
  ad-hoc signed: macOS asks once per secret to let Keylo use the keychain (choose **Always Allow**),
  and may ask again after a rebuild.
- Keylo locks when the screen locks.

- Secrets are generic-password items in your **login keychain** (service `Keylo`, visible in
  Keychain Access). Large values are AES-256-GCM files sealed with a master key kept in the keychain.
- **Touch ID** (or Apple Watch, or your password) replaces Windows Hello; access-key approvals show a
  native alert, then Touch ID.
- Copied values are marked concealed and transient, so clipboard managers skip them.
- `keylo-mac` (built from `src/Keylo.Platform.MacOS/helper`) handles Touch ID, the pasteboard and
  alerts; it sits inside Keylo.app next to `keylo`.
- The login keychain is locked in SSH sessions; `KEYLO_KEYCHAIN=/path/to.keychain-db` points Keylo at
  another keychain (`tests/macos-smoke.sh` uses a throwaway one).

## Use

| | |
|---|---|
| `keylo` | Open the app |
| `keylo set NAME [--category C] [--username U] [--notes N] [--file F]` | Add or update (value is prompted, piped, or read from a file) |
| `keylo list [search…] [--category C] [--json]` | Search names, categories, usernames and notes (never values) |
| `keylo get NAME [--clip] [--out FILE] [--field username] [--both]` | Print, copy (auto-clears) or export; `--both` prints key and value |
| `keylo edit NAME [--rename NEW] [--category C] …` | Change details without touching the value |
| `keylo rm NAME` | Delete |
| `keylo import PATH… [--category C] [--overwrite] [--delete-originals]` | One secret per file; subfolders become categories |
| `keylo run --env VAR=NAME [...] -- CMD ARGS` | Run a command with secrets as environment variables (`NAME:username` maps the key/username) |
| `keylo push 1password [NAME…] [--category C] [--all]` | Copy secrets into another vault |
| `keylo backup FILE [--force]` | Password-protected backup of every secret, category and icon |
| `keylo restore FILE [--overwrite] [--dry-run]` | Restore one (existing secrets are kept unless `--overwrite`) |
| `keylo keys [create NAME … \| revoke NAME]` | Access keys for agents (see below) |
| `keylo mcp` | MCP server for Claude Code and other agents |
| `keylo unlock` / `lock` / `status` / `config` / `version` | Windows Hello session, settings and version |

Migrating a `.secrets` folder: `keylo import .\.secrets`, check `keylo list`, then re-run with
`--overwrite --delete-originals` (or delete the folder yourself).

## Secret types

Like 1Password's categories, a secret can have a **type** with named fields:

| Type | Fields (secret ones in bold) |
|---|---|
| Login | username, **password**, url |
| API key | key_id, **secret**, endpoint |
| Database | engine, host, port, database, username, **password**, **connection_string** |
| SSH key | username, **private_key**, **passphrase**, host, public_key |
| Secure note | **note** |

Add your own in Settings → Secret types, each with its own icon and colour (built-ins can change
theirs). Secret fields are encrypted together as the value; the others are stored as metadata,
so they're searchable (`keylo list db.local`, `type:database`) and shown to agents whose key covers
the secret. A database without its own connection string gets one built from its fields
(postgres, mysql, sqlserver, mongodb, redis). Plain secrets (one value, an optional key) still work as before.

```powershell
keylo set prod-db --type database --field engine=postgres --field host=db.local --field username=alice   # password is prompted
keylo get prod-db                       # main value (the password)
keylo get prod-db --field connection_string
keylo get prod-db --both                # every field
keylo run --env DATABASE_URL=prod-db:connection_string -- npm run migrate
keylo edit prod-db --field host=db2.local
keylo types                             # all types and fields
```

## In the app

- **Home** (the default view) shows pinned secrets (pin button on a secret) and recently used ones — by you in the app, or by agents (from the audit log). Search covers everything; categories show their full lists. The top bar has search for everything (Ctrl+K), New ▾ (import, link from 1Password), Settings and Lock.
- **Search** across name, category, key, notes and non-secret fields; filter by category in the sidebar.
- **Import** files or folders (button, drag and drop, or `keylow --import PATH`). Each file is listed with its name (from the file name; edit it) and a guessed type: SSH keys, database URLs (split into host, port, user…), tokens and passwords; anything else stays plain. The dialog
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

Keylo's normal storage only opens for your account on this machine. A backup (Settings →
Backup & restore, or `keylo backup`) is what gets your secrets onto a new machine or survives a lost
account. The format is the same on Windows and macOS, so a backup made on one restores on the other
(linked secrets need that vault's CLI signed in there too).

- One `.keylo` file: every secret's value and details, categories (including empty ones and their
  styles) and uploaded icons.
- Encrypted with **AES-256-GCM**; the key comes from your password via **PBKDF2-SHA256, 600,000
  iterations** and a random salt. The header is authenticated too, and nothing — not even secret
  names — is readable without the password. A wrong password or any change to the file is rejected.
- Creating one always asks for Windows Hello / Touch ID (it exports everything). Passwords must be at least
  10 characters; the CLI prompts for them (or reads `--password-stdin`) and never accepts one as an argument.
- **There is no recovery.** Keep the password somewhere other than Keylo.

## Windows Hello

`keylo config hello session|always|never` (or Settings in the app):

- **session** (default): verify once, then the app and CLI share an unlock that lasts 15 minutes after your last activity in the app (keyboard or mouse); agents' use doesn't extend it.
- **always**: verify every time a value is revealed, copied, exported or run.
- **never**: rely on your Windows sign-in only.

Changing these settings, or access keys, always asks for Windows Hello.

**What this protects against:** other Windows users, a stolen or copied disk, backups, and
plaintext files getting committed or synced. **What it doesn't:** malware running as you — it can
read DPAPI-protected data directly. Windows Hello here is a presence check, not encryption.

## Claude Code and other agents (MCP server + access keys)

`keylo mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server. Agents identify
themselves with an **access key**; create one in the app (Settings → Access keys → New key → Save),
which shows the key once with a button and the command that registers the server:

```bash
claude mcp add keylo --scope user --env KEYLO_ACCESS_KEY=kyl_… -- "%LOCALAPPDATA%\Programs\Keylo\keylo.exe" mcp
```

or from a terminal: `keylo keys create "Claude Code" --all --add-to-claude` (or `--category dev`).

| Tool | Does |
|---|---|
| `search_secrets` / `list_categories` | Find secrets (never values), with each one's type, field schema and whether the key covers it. |
| `list_types` | Secret types and their fields. |
| `run_with_secrets` | Runs a command with secrets (or single fields, `name:field`) as environment variables; values in its output become `[keylo:name]`. |
| `get_secret` | Returns every field, or one — into the AI conversation, so only when needed. |
| `request_access` | Asks you to add secrets to the key permanently. |

- **What a key can use without asking**: *Everything*, *Only these categories*, or *Nothing — ask
  me each time*. It only passes values to commands unless "Also let it read values" is on.
- **Outside the scope**, Keylo opens an approval window showing the secrets, the command and the
  agent's stated reason: Deny, Allow for 15 min (your session length), or Always allow (adds them
  to the key). Allowing needs Windows Hello; unanswered requests are denied after 5 minutes.
- **Keys are stored as SHA-256 hashes**, can expire, and are revoked by deleting them. The key
  lives in Claude Code's user config (`~/.claude.json`) — never put it in a project's `.mcp.json`.
  Commands run by the server don't receive it.
- `KEYLO_ACCESS_KEY` works for the plain CLI too (`keylo run`, `keylo get`).
- Every use without Windows Hello is in the audit log (Settings → Open log), with the key and the
  process chain. Entries older than 90 days are pruned (Settings → Keep audit log, or
  `keylo config audit-days 365|forever`).
- Redaction catches accidental leaks, not deliberate ones (a command could encode a value first).
  Neither keys nor Hello stop malware already running as you.

## Linked secrets (1Password and other vaults)

A linked secret points at an item in another vault. Keylo stores only the reference (vault, item,
account); the value is read from the vault each time it's used and never copied, so changes there
apply at once. To Claude it's an ordinary secret: same search, `name:field` access, approvals,
redaction and audit log.

- **App:** Link from 1Password… in the sidebar: search, pick an item, keep all its fields or just one.
- **CLI:** `keylo link --search github`, then `keylo link gh --item "GitHub" [--field password] [--category dev]`.
- 1Password is read through its CLI (`op`), signed in via the 1Password app (Settings → Developer →
  Integrate with 1Password CLI). Every signed-in account is searched; 1Password may ask you to unlock it.

## Vault providers

Two plugin interfaces in `Keylo.Core.Providers`:

- **`ILinkedVaultProvider`**: search a vault, describe an item's fields, and read their values —
  for linked secrets. Bitwarden, KeePass, Azure Key Vault or AWS Secrets Manager would implement this.
- **`IVaultProvider`**: push Keylo secrets into another vault.

1Password implements both:

- **Push**: `keylo provider set 1password vault Private`, then `keylo push 1password --category cloud`.
  Items are tagged `keylo`; pushing again updates them. Values go over stdin, never the command line.

Add others by building a class library that references `Keylo.Core`, implementing either interface
(or both) with a parameterless constructor, and dropping the DLL into `%LOCALAPPDATA%\Keylo\plugins`.
Plugins run as you with full trust.

## Develop

| Project | |
|---|---|
| `Keylo.Core` | Everything OS-neutral (`net10.0`): secrets, types, search, links, access keys, backups, MCP-facing logic |
| `Keylo.Platform.Windows` | Credential Manager, DPAPI, Windows Hello, clipboard, process ancestry — an `IKeyloPlatform` |
| `Keylo.Platform.MacOS` | Keychain, Touch ID (via the `keylo-mac` Swift helper), pasteboard, `ps` ancestry |
| `Keylo.UI` | View models and services shared by both apps; toolkit bits (icons, brushes, timers, pickers) come from an `IUiHost` |
| `Keylo.App` | `keylow`, the Windows app (WPF + WPF-UI) |
| `Keylo.Desktop` | Keylo.app, the macOS app (Avalonia); `KeyloApp --cli` is the macOS `keylo` |
| `Keylo.Cli` | `keylo` and the MCP server; builds for Windows and macOS |

Another OS means implementing `IKeyloPlatform` in a new `Keylo.Platform.*` project; Core needs no
changes. The tests include an in-memory platform for this.

On a Mac, `tests/macos-smoke.sh` checks the command line and MCP server against a throwaway
keychain, and `tests/macos-ui-snapshots.sh` (after `./build.sh --debug`) renders the app's screens
to PNGs, which works without a display (e.g. over SSH).

```powershell
dotnet build
dotnet test     # uses a separate Credential Manager prefix and cleans up after itself
```

`KEYLO_HOME` and `KEYLO_PREFIX` point the CLI and app at a scratch data folder and credential
prefix, which keeps experiments away from your real secrets.
