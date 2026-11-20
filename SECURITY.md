# Security

## Reporting a vulnerability

Please report security problems privately, not in a public issue:
**[Report a vulnerability](https://github.com/tulde23/keylo/security/advisories/new)** (GitHub's
private vulnerability reporting).

Include what you found, how to reproduce it, the Keylo version (`keylo version`) and your operating
system. You'll get a reply within a few days. Fixes ship in a new release, and the advisory is
published once people have had a chance to update.

Only the latest release is supported. The app offers updates as they come out (Settings → About to
check now); on Windows, `keylo update` also installs them.

## Threat model

Keylo keeps API keys, passwords and tokens out of AI agents' context: agents **use** secrets by
having Keylo run commands with them, and never **read** them. This is a summary; the README's
[Security model](README.md#security-model) has the details.

### What Keylo protects against

- **Values reaching an agent's context.** No MCP tool returns a value, access keys are run-only, and
  values that appear in a command's output are replaced with `[keylo:name]` before the agent sees it.
- **Agents using secrets they shouldn't.** An access key covers chosen categories or secrets; anything
  else needs your approval, confirmed with Windows Hello, Touch ID or your system password. Approvals
  show the exact command and the agent's stated reason. Every use is written to an audit log.
- **Secrets in plain-text files** (`.env`, key folders) being read, committed, synced or shared.
- **Values in shell history or the process list.** Values are never taken as command-line arguments.
- **Other users on the computer, and a stolen disk or copied backup.** Secret values live in Keylo's
  vault, each encrypted under a key protected by the OS (DPAPI on Windows), or in the macOS Keychain
  or the Linux keyring or vault, all tied to your account. On Windows and macOS, secrets' details
  (names, categories, usernames, websites, notes) are readable by programs running as you, as
  Credential Manager and Keychain attributes always were. Keylo authenticates the whole vault (every
  value, every detail and the set of entries) under its key and checks it before every read and
  change, so a secret added, removed, altered or rolled back to an older copy by anything **without
  the key** is refused. This detection assumes the attacker never had the key: code running as you
  can read the key and so could also re-sign the vault, and replacing the entire vault file with a
  complete older copy can't be caught without an anchor outside the file — both are the same-user
  case below.
- **The sync folder and the service that syncs it.** Synced secrets are encrypted (AES-256-GCM) with a
  key the service never sees; changed files are rejected.

### What it doesn't protect against

- **A master passphrase closes most of this** (Windows, opt-in): with one set, the vault key is also
  wrapped by an Argon2id key from the passphrase, so a copied disk or same-user code can't open the
  vault while it's locked, and can't open it at all without the passphrase. During an unlocked session
  the key is cached (OS-sealed) so agents can use it, as on Linux; `keylo lock` ends that.
- **Unlocking with Windows Hello** (opt-in, needs a master passphrase first): the vault key is wrapped
  a second way, under a key that a Windows Hello gesture releases from a TPM-bound credential
  (`KeyCredentialManager`), so you unlock with a PIN or fingerprint instead of typing the passphrase.
  The private key never leaves the TPM and is useless without the gesture, so this wrap can't be undone
  at rest. It never replaces the passphrase: the passphrase stays your recovery key, so a reset PIN, a
  cleared TPM or a new PC loses only the Hello shortcut, never the vault. Removing the passphrase
  removes the Hello wrap too.
- **Recovering the vault.** The vault file is tied to this OS account (DPAPI on Windows), so copying it
  to another machine won't open it — even with the passphrase. The portable recovery artifact is an
  **encrypted backup** (`.keylo`, AES-256-GCM, PBKDF2-SHA256), which opens on any PC or Mac with its
  password; keep one, and its password, somewhere other than Keylo. Synced installs can also recover
  from another device with the join code.
- **An agent, or any program, with unrestricted shell access as you.** Keylo's protection holds for
  agents that use secrets through Keylo (the MCP server or `keylo run`). It doesn't sandbox the agent.
  A program running as you can read the same store Keylo uses:
  - **Windows:** the vault's key is protected with DPAPI, which any program running as your user can
    ask Windows to decrypt, so such a program can decrypt the vault's values (as it could read
    Credential Manager).
  - **Linux:** an unlocked desktop keyring can be read by any program in your session, and the vault
    key is cached in your kernel keyring for 15 minutes after unlocking.
  - **macOS:** the Keychain asks you before a program other than Keylo reads one of its items. Deny it
    unless you started that program yourself.

  To keep an agent from going around Keylo, limit what its shell can do: run it in a sandbox, a
  container or dev container, or as a different user account, and use your agent's own permission
  rules to block commands that read credential stores. `keylo get` always asks for your identity
  check, so it can't be used silently.
- **A command you approve.** It receives the real value and can do anything with it, including sending
  it elsewhere or encoding it so the redactor doesn't recognise it. Redaction catches accidental
  leaks, not deliberate ones. Don't approve commands you don't understand.
- **Malware running as you.** The identity check is a presence check, not encryption.
- **Linked vaults** (1Password, AWS Secrets Manager): Keylo is only as strong as their setup.
- **A synced device you no longer control,** or anyone with the join code and access to the sync
  folder.

### What Keylo connects to

Keylo has no server and no account. It goes online only to check for updates (GitHub releases), to
download an icon from an address you paste, and through the `op` and `aws` command lines for linked
secrets. Releases are signed: Windows and macOS updates carry a minisign signature that the updater
checks, and the macOS app is signed with a Developer ID and notarized by Apple.
