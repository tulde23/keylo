# Design: a synced vault

Status: draft. Scope: step 1 of the "distributed vault" path. One person, several devices, no Keylo server.

## Goal

The same secrets on every device, kept up to date automatically, by syncing an encrypted vault
through a folder the user already syncs: iCloud Drive, OneDrive, Dropbox, a network share, or a git
repo. The sync provider only ever sees ciphertext. Everything that works today keeps working:
Windows Hello and Touch ID, the CLI, MCP approvals, typed secrets, and backups.

Not in scope: sharing with other people, a hosted server, mobile, or browser autofill. The format
leaves room for these (see *Later*), but nothing here depends on them.

## Where things stand

- `SecretStore` keeps each secret as one OS-store item: Credential Manager on Windows, the Keychain
  on macOS. Category, type and fields are attributes; large values are `IDataProtector` files under
  `blobs/`. All of it is bound to one user on one machine.
- Settings beside it are plain JSON in the data directory: `categories.json`, `types.json`,
  `icons/`, `pins.json`, `recent.json`, `config.json`, `ui.json`.
- `KeyloBackup` already has portable crypto: PBKDF2-SHA256, then AES-256-GCM over a JSON payload
  that carries every secret, category, type and icon.

The synced vault keeps the OS store, but changes its job: it holds the **vault key**, behind
Windows Hello or Touch ID. The secrets themselves live in the shared folder.

## Modes

The vault's mode is a setting in `config.json`, so the current behaviour stays the default:

| Mode | Secrets live in | Who uses it |
|---|---|---|
| `local` (today) | OS store + `blobs/` | everyone, until they turn on sync |
| `synced` | `<folder>/Keylo/` (encrypted), with a local cache | after `keylo sync init` / `join` |

`SecretStore`'s public API (`List`, `Find`, `Get`, `Save`, `UpdateDetails`, `Delete`,
`Categories`) stays as it is, so the CLI, MCP server, view models and backups don't change. Inside,
it delegates to an `ISecretBackend`:

- `CredentialBackend`: today's code, moved there unchanged.
- `VaultBackend`: the synced vault described below.

`CategoryCatalog` and `SecretTypes` do the same with their JSON files. In synced mode they read
and write vault records instead.

## The folder

```
<sync folder>/Keylo/
  vault.json                    header: ids, KDF parameters, wrapped vault key (no secrets)
  records/<deviceId>/<seq>.rec  immutable, encrypted change records; one folder per device
  snapshots/<deviceId>-<seq>.snap  optional compaction (see Compaction)
```

Two rules make this safe on file-sync services:

1. **Each device writes only in its own folder.** No two devices write the same file, so
   OneDrive and Dropbox never create "conflicted copies", and iCloud never merges files.
2. **Files are written once and never changed.** A record is written to `<seq>.rec.tmp` and then
   renamed. A reader that sees a half-synced file finds that it fails to decrypt, skips it, and
   picks it up on the next pass. Append-only log files would hit torn reads; one immutable file
   per change avoids them.

### vault.json

```json
{
  "format": "keylo-vault/1",
  "vaultId": "8c1f…",                // random 128-bit, hex
  "kdf": { "alg": "pbkdf2-sha256", "iterations": 600000, "salt": "…" },
  "wrappedVaultKey": "…",            // AES-256-GCM(accountKey, vaultKey), AAD = "keylo-vault/1|" + vaultId
  "generation": 1,                   // bumped when the vault key is rotated
  "createdAt": "2026-11-05T…Z"
}
```

## Keys

```
secretKey   128 random bits, made by `sync init`; shown once in an emergency kit, never synced
password    the master password (min 10 chars, same rule as backups)

accountKey = HKDF-SHA256(
               ikm  = PBKDF2-SHA256(password, salt, iterations) || secretKey,
               info = "keylo-account|" + vaultId)
vaultKey   = 256 random bits, wrapped by accountKey in vault.json
```

- **Why a secret key as well as the password:** a copy of the folder leaked from the sync
  provider can't be attacked with password guesses alone, because the secret key adds 128 bits of
  entropy. It's the same idea as 1Password's Secret Key.
- **Why PBKDF2:** the secret key already makes offline guessing infeasible, and PBKDF2 is built
  into .NET, so no native crypto dependency (Argon2) is needed. The `kdf` field leaves room to
  change this later.
- **Day to day,** joining a device stores `vaultKey` in the OS store (`Keylo:#vault`). It sits
  behind the same Windows Hello or Touch ID gate (`AccessGate`) as today. The password and secret
  key are only needed again to join another device, or after a rotation.

## Records

One record is one change to one item. Its file is:

```
"KEYLOREC" | version(1) | nonce(12) | AES-256-GCM(vaultKey, payload) | tag(16)
AAD = vaultId | generation | deviceId | seq
```

The payload is gzip-compressed JSON. Nothing in the clear names the item or its kind; an observer
sees only how many changes there are, their sizes and their timing.

```json
{
  "id": "3b9e…",                 // the item's own random id; renaming keeps it
  "kind": "secret",              // secret | category | type | icon
  "rev": { "clock": 42, "device": "d7…" },
  "base": { "clock": 40, "device": "a1…" },   // the revision this edit started from (null on create)
  "prev": "sha256 of this device's previous record",
  "deleted": false,
  "body": { "name": "prod-db", "category": "ops", "username": "alice", "notes": null,
            "icon": null, "color": null, "type": "database",
            "fields": { "host": "db.local" }, "value": "base64…" }
}
```

- **`clock`** is a Lamport counter: one more than the largest clock this device has seen. Two
  revisions compare by `(clock, device)`.
- **`base`** lets a reader tell a straight edit apart from two devices editing at once.
- **`prev`** chains each device's records into a hash chain. A device remembers the last head it
  saw for every other device, so a record that is deleted or rolled back in the folder is detected
  and reported, not silently lost.
- **Kinds:** categories (`CategoryStyle`), custom types (`SecretTypeDefinition`) and uploaded
  icons (the PNG bytes) are records of their own kinds, so they sync too.
- **What stays per device:** `pins.json`, `recent.json`, `ui.json` and `config.json`, which
  includes MCP access keys. Access to MCP stays granted per device.

## Merging

Every device builds the same state from the same set of records. For each `id`:

1. **Winner:** the record with the highest `(clock, device)`. A delete is a tombstone, and it
   wins the same way.
2. **Conflict:** if the winner's `base` isn't the previous winner (two edits started from the
   same revision), the losing edit is kept as a **conflict version**. The item gets a badge in the
   app and a mark in `keylo ls`. The person picks a version, or keeps both under different names.
   Nothing is ever silently discarded.
3. **Same name created on two devices:** two items get the same name with different ids. Names
   must stay unique, because the CLI and MCP address secrets by name. The later item (by
   `(clock, device)`) is shown as `name (2)` and flagged, until it is renamed or merged.

Whole items are merged, not individual fields. A secret is small, and choosing between two
versions of an item is easier to understand than a mix of the two.

## The local cache

Decrypting every record on every `keylo get` would be slow, and it would fail while the folder is
being synced. Each device therefore keeps `vault-cache.bin` in its data directory: the merged
state plus the last head seen for each device, encrypted with the vault key.

- **Reads** (`List`, `Get`) come from the cache.
- **Writes** go through two steps: write the record to the folder, then apply it to the cache.
- **Picking up other devices' changes:**
  - when the app starts, and when it unlocks;
  - through a `FileSystemWatcher` on `records/`, while the app is running;
  - every 5 minutes, to catch providers that don't raise file events;
  - with `keylo sync now`.
- **When the folder is unavailable** (offline, or iCloud has evicted the files), reads still work
  from the cache. Writes are queued in `outbox/` in the data directory and flushed when the
  folder is back.
- **iCloud:** placeholder files (`.<name>.icloud`) count as "not yet here". On macOS the helper
  asks for them to be downloaded with `NSFileManager.startDownloadingUbiquitousItem`.

## Compaction

Records add up over time. Any device can write `snapshots/<deviceId>-<seq>.snap`: the merged
state as of a set of heads, encrypted the same way as a record. A new device loads the newest
snapshot and replays only the records after it. Old records are never deleted automatically in
v1. Pruning is a later, explicit `keylo sync compact`.

## Keys over time

- **Password change:** re-wrap `vaultKey` with the new account key and rewrite `vault.json`.
  The records are untouched.
- **Rotating the vault key** (after a device is lost):
  1. Generate a new `vaultKey`.
  2. Write a snapshot under `generation + 1`, in a new folder.
  3. Archive the old records.
  4. Every other device must re-enter the password and secret key.

  A lost device that can still reach the folder will lose access to new changes, but it already
  had everything up to the rotation. This is said plainly in the UI.
- **The real boundary:** the threat model is "the sync provider, or someone with a copy of the
  folder". Someone with the folder plus an unlocked, enrolled device has the secrets. Protection
  there is the OS account lock plus Hello or Touch ID, the same as today.

## Commands and UI

```
keylo sync init <folder>    create a vault, copy this device's secrets into it, print the emergency kit
keylo sync join <folder>    add this device (asks for password + secret key, Hello/Touch ID to store the key)
keylo sync status           folder, device id, last sync, pending outbox, conflicts, rollback warnings
keylo sync now              pull and push immediately
keylo sync leave            back to local mode (copies the merged secrets into the OS store first)
keylo sync rotate           new vault key (other devices re-join)
keylo sync password         change the master password
```

- **Settings → Sync:** choose a folder, show the emergency kit, list devices, rotate the key.
- **Main window:** a status chip (synced / syncing / offline / attention) and a conflict badge on
  affected items, with a "Resolve" dialog that shows both versions side by side. Values stay
  hidden until revealed, as today.
- **`init` on a device that already has local secrets:** they are copied in. Matching names are
  only an issue on `join`: the person chooses between keep both, keep the vault's, or keep this
  device's. This reuses the import dialog's options.

## Backups

`KeyloBackup` doesn't change. It reads through `SecretStore`, so in synced mode it backs up the
merged vault. Restoring into a synced vault writes ordinary records, so restored secrets sync too.

## Testing

- **Crypto:** known-answer tests for key derivation and wrapping. Tampering with any AAD field
  (vault id, generation, device, sequence number) must fail to decrypt.
- **Merge:** property tests that apply random edits from N simulated devices in random orders
  and check that every device ends up in the same state, that no edit is lost (each is either the
  winner or a conflict version), and that names stay unique.
- **Rollback:** delete or replace a record file, and check that it is reported.
- **Two devices on one machine:** two `KEYLO_HOME`s with separate `KEYLO_PREFIX`es, sharing one
  temporary folder. Run `init`, `join`, edits on both, a concurrent edit, delete, `rename` and
  `leave`. The script also runs across the Windows and Mac pair, using a throwaway Mac keychain,
  like `tests/macos-smoke.sh`.
- **Flaky folder:** half-written `.tmp` files, files that appear late, and iCloud placeholder
  files.

## Order of work

1. **Move today's `SecretStore` internals into `CredentialBackend`,** behind `ISecretBackend`,
   with no change in behaviour. Do the same for categories and types. The existing tests must pass
   unchanged.
2. **Write `VaultCrypto` and `VaultHeader`:** key derivation, wrapping, and record encryption,
   with their tests.
3. **Write `RecordLog` and `VaultState`:** writing and reading records, merging, the hash chains,
   and the cache, with the merge property tests.
4. **Write `VaultBackend`** and add `keylo sync init/join/status/now/leave`, with the
   two-device script.
5. **Add the outbox, `FileSystemWatcher` and polling,** and the iCloud placeholder handling.
6. **App UI:** Settings → Sync, the status chip, and conflict resolution.
7. **Rotation, password change, and snapshots.**

Steps 1–4 give a working synced vault from the command line.

## Later

- **Sharing:** give each item its own key, wrapped by the vault key, and give each user an X25519
  key pair. A shared vault is a second vault whose key is wrapped for each member. The record
  format above doesn't need to change.
- **A server:** the record set is already a log of encrypted, append-only changes. A server would
  store and relay the same records, with OPAQUE for sign-in, without seeing any contents.

## Open questions

- **Should conflict versions expire?** For example, auto-resolve to the winner after 30 days.
- **Should `sync init` require a fresh backup first?** It changes where secrets live. A backup
  first is cheap insurance.
- **Should a device-wide, per-session "MCP may read synced secrets" toggle exist,** or is today's
  per-key access enough?
