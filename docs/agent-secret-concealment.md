# How Keylo conceals secrets from AI agents

This is the technical explanation of Keylo's central guarantee: **an AI agent can *use* a
secret without ever *reading* it.** It describes the exact mechanism — the MCP tool surface, the
run path, output redaction, file delivery, and the access-key gate — with references to the
source so the claims can be audited rather than taken on faith.

The short version: a secret value leaves Keylo only as an environment variable or a file **inside a
child process that Keylo starts**, never as a value returned to the agent. The agent names secrets;
Keylo supplies the values to the command and hands back only the command's exit code and its
(redacted) output.

> Contrast with secret-injection tools (including 1Password's developer SDKs, Vault agents, and
> `.env` loaders): those **deliver the value to the consuming code or agent** at runtime. Keylo does
> not. This is the architectural difference, not a configuration option.

---

## 1. The boundary: the MCP tool surface returns no value

An agent talks to Keylo through the MCP server (`keylo mcp`, `crates/keylo-cli/src/mcp.rs`). The
complete set of tools it exposes is defined in `definitions()` (`mcp.rs:1180`):

| Tool | Returns |
|---|---|
| `search_secrets` | names, categories, types, field **schemas**, non-secret field details (host, url) for covered secrets — **never a secret value** |
| `list_categories` / `list_types` | counts and schemas |
| `list_aws_profiles` / `list_aws_secrets` | names, ARNs, tags — **never values** |
| `check_for_updates` | version info |
| `request_access` | asks the user to widen the agent's key |
| `run_with_secrets` | exit code, stdout, stderr (redacted) |

There is deliberately **no `get_secret`, `read`, or `reveal` tool.** The server's own module doc
states it plainly (`mcp.rs:2`):

> *Keylo never returns secret values to agents: they reach commands as environment variables and are
> redacted from [output].*

`search_secrets` returns a field **schema** marking which fields are secret and which is the "main"
value, but the values themselves are never serialized into a response. This is enforced structurally
— there is no code path from a secret value to a tool result — not by a filter that could be
misconfigured.

---

## 2. `run_with_secrets`: values flow into a child, never back out

`run_with_secrets` is "the only way to use a secret" (its own description, `mcp.rs:1242`). The flow,
implemented in `Server::run` (`mcp.rs:438`):

1. **The agent names secrets, it does not hold them.** It passes two optional maps:
   - `env`: `{ "GITHUB_TOKEN": "github-token" }` — environment variable → **secret name**
   - `files`: `{ "GOOGLE_APPLICATION_CREDENTIALS": "google-oauth" }` — variable → **secret name**

   The grammar is a reference (`name`, `name:field`, `name@env`, `name@env:field`), never a value.
   The agent supplies no secret material and receives none.

2. **Authorization happens before any value is read** (`mcp.rs:462`): `authorize(... SecretOperation::Run ...)`.
   See §5.

3. **Keylo reads the values itself and places them:**
   - `env` entries: read via `read_all` (`mcp.rs:674`) and inserted into an in-process
     `environment: BTreeMap<String, String>`.
   - `files` entries: read as raw bytes via `read_bytes` (`mcp.rs:720`) and written to a private
     temporary file by `SecretFiles::add`; the variable is set to the file's **path**, not its
     contents (`mcp.rs:470-483`).

4. **The command runs** with those variables (`run_shell`, `mcp.rs:490`). The secret is now present
   only in the child process Keylo spawned.

5. **Values are destroyed immediately after the run:** every read value is zeroized (`mcp.rs:485-493`,
   using `zeroize`), and the temporary files are wiped and removed (`drop(files)`, `mcp.rs:494`; see §4).

6. **The agent gets back only** the exit code, stdout, and stderr — after redaction (`mcp.rs:497-505`,
   §3).

At no point does a secret value exist in a value returned to the agent. The only outputs are the
process's exit status and its console streams.

---

## 3. Output redaction: a second, defense-in-depth layer

A command might echo its own credential (a verbose client, an error dumping a connection string).
To stop that reaching the conversation by accident, every value Keylo hands to a command is
registered with an `OutputRedactor` (`crates/keylo-core/src/redactor.rs`), and the command's stdout
and stderr are passed through it before return.

- Values are registered as they are read (`read_all`/`read_bytes` call `redactor.add`,
  `mcp.rs:699, 707, 732`). The redactor is a single long-lived instance on the server
  (`redactor: Mutex<OutputRedactor>`, `mcp.rs:111`), so **a value handed out in one call is redacted
  from every later call's output too.**
- `redact` replaces each occurrence of a value with `[keylo:<name>]` (`redactor.rs:39`). Both the
  raw value and its trimmed form are registered, so a value imported with a trailing newline is
  still caught (`redactor.rs:28`). Longer values are matched first, so one value containing another
  is replaced whole (`redactor.rs:36`).
- The stored values are zeroized when the redactor is dropped (`redactor.rs:50`).

### The honest limit (stated, not hidden)

Redaction catches **accidental** leaks, not **deliberate** ones. The module doc says so
(`redactor.rs:1`):

> *Catches accidental leaks (a command that echoes its token), not deliberate ones: a command can
> still transform a value (base64, reversed) so it no longer matches.*

Two concrete limits:
- A command that transforms a value (base64, reverse, hash, encrypt) produces output the redactor
  won't recognize.
- Values shorter than `MIN_LENGTH` (4 bytes) are not redacted, because they would match ordinary
  text (`redactor.rs:7`).

This is why redaction is the **second** layer, not the first. The first layer — access keys and
approvals (§5) — decides *which* secrets a command may receive at all. Redaction keeps those
secrets out of the conversation by accident; it is not a defense against a command you approved that
is actively trying to exfiltrate. The rule follows: **don't approve commands you don't understand.**

### Derived values pass through (by design)

Redaction is purely value-based: the `OutputRedactor` only holds the specific values Keylo
*injected* for a run (`redactor.add`, `redactor.rs:26`), and `redact` does nothing but match and
replace those exact strings (`redactor.rs:39`). A value the command *produces* at runtime — a
short-lived access token an API returns in exchange for your key — was never injected, so it is not
in the redactor's set and reaches the agent unchanged. This is intentional, not a gap: it is what
lets an agent exchange a long-lived key for a session token and use that token in later calls. There
is no "mark this output safe" flag because there is nothing to opt out of — the default is already
"pass through unless it is a stored secret."

The trade-off: Keylo conceals the **long-lived credential you stored**, not an ephemeral token
derived from it. If that derived token is itself sensitive and you don't want the agent to hold it,
keep the whole chain — the token exchange *and* the call that uses it — inside a **single**
`run_with_secrets` command, so the token lives and dies in the child process and never surfaces.

---

## 4. File delivery: path in, value never

Some credentials are consumed as files, not variables — a service-account or OAuth JSON, a
kubeconfig, a PEM key — and some are binary (a `.p12`/PFX certificate, a keystore) and cannot be an
environment variable at all. For these, Keylo writes the value to a short-lived file and hands the
command the **path**. The agent never names, sees, or writes the file itself.

`SecretFiles` (`crates/keylo-cli/src/runner.rs:17`) implements this:

- **Private per-run directory.** Created mode `0700` on Unix (`create_private_dir`, `runner.rs:76`);
  on Windows it inherits `%TEMP%`, which lives under the user's profile and is not readable by other
  users (`runner.rs:82`).
- **Per-value files, `0600` on Unix** (`write_private_file`, `runner.rs:89`), created with
  `create_new` so they never clobber an existing file.
- **Only the path is exposed.** `add` returns the `PathBuf`; the caller puts that path (not the
  bytes) into the environment (`runner.rs:44`, `mcp.rs:475`).
- **Filename sanitization.** A hostile reference name can't escape the directory or hide the file:
  `sanitize` reduces the name to `[A-Za-z0-9._-]`, trims leading dots, and never yields an empty or
  hidden name (`runner.rs:65`). The test `two_files_do_not_collide_and_names_are_safe`
  (`runner.rs:228`) feeds it `../../etc/passwd` and asserts the result stays inside the private
  directory.
- **Wiped and removed on drop.** When `SecretFiles` is dropped — right after the command exits — each
  file is overwritten with zeros and deleted, and the directory is removed (`Drop`, `runner.rs:52`).
  The test `secret_file_holds_the_value_then_is_wiped_on_drop` (`runner.rs:207`) asserts both the
  file and the directory are gone afterward.

So a file-delivered secret exists on disk only for the lifetime of the one command, in a file only
the user can read, and is zeroized when that command finishes.

---

## 5. The access-key gate: which secrets, without a prompt

Concealment answers "can the agent read the value" (no). Authorization answers "which secrets may the
agent *use*, and when must the user approve." This is the access-key system
(`crates/keylo-core/src/access.rs`).

- **Each agent presents a key** in `KEYLO_ACCESS_KEY`. Keylo stores **only its SHA-256 hash**
  (`access.rs:4`, `create` at `access.rs:104`); the token itself is shown once and never persisted.
- **Keys are run-only.** `AccessKey::allows` (`access.rs:91`) encodes the rule exactly:
  ```rust
  SecretOperation::Browse => true,      // listing names/details is always allowed
  SecretOperation::Get    => false,     // reading/printing a value is NEVER allowed by a key
  SecretOperation::Run    => !secrets.is_empty() && secrets.iter().all(|s| self.covers(s)),
  ```
  A `Get` (print/copy/export a value) can never be authorized by a key — it always requires the
  user's identity check. A `Run` is allowed only when the key covers **every** secret in the request.
- **Coverage is scoped** (`covers`, `access.rs:83`): a key covers a secret if its scope is `All`, or
  the secret's name is listed explicitly, or its category is listed. A key created
  `--category dev` covers the `dev` category and nothing else.
- **Uncovered → the user is asked.** `authorize` (`mcp.rs:537`) checks the key; if it doesn't cover
  the request (or the secret is in an "always ask" environment such as prod), it opens an approval
  window (`ask`, `mcp.rs:596`) showing the exact command and the agent's stated reason, confirmed by
  the OS identity check (Windows Hello / Touch ID / polkit). "Always allow" adds the secret to the
  key; "Deny" fails the call and tells the agent not to retry (`mcp.rs:577`). "Always ask"
  environments prompt **every** time regardless of the key (`mcp.rs:562`).
- **Every use is audited** (`access::audit`, `mcp.rs:564, 573, 589`), recording the operation, the
  secrets (with environment), the key, and how it was authorized.

Two more containment facts:
- **Commands don't receive the access key.** `KEYLO_ACCESS_KEY` is not passed into the child
  environment, so a command Keylo runs can't read the key and widen its own access
  (README "What agents can't do").
- **The identity check is a presence check, not encryption** (`crates/keylo-core/src/gate.rs:1`).
  It gates *when* a value is used; it is not what keeps the value secret at rest (that's the vault's
  OS-sealed key — DPAPI / Keychain / keyring / passphrase file).

---

## 6. Values are never command-line arguments

Throughout, secret values reach a command as **environment variables or file paths**, never as
argv. They therefore never appear in shell history or the process list (visible to other users via
`ps`/Task Manager). This holds for both `keylo run` and the MCP server.

---

## 7. Putting it together: the threat it addresses

The reason this category exists is that an AI agent's context is quietly hostile to secrets — it is
logged, sent to a model provider, potentially replayed, and readable by anything that can see the
conversation. Keylo's design keeps the value out of that context entirely:

1. **No tool returns a value** — there is no read path to leak (§1).
2. **Values flow only into a child process Keylo starts**, then are zeroized (§2, §4).
3. **Output is redacted** against accidental echoes (§3).
4. **A run-only, scoped key** limits which secrets a command can receive, with per-use approval and
   an audit trail for the rest (§5).

What it does **not** defend against — and does not claim to — is a command the user **approves** that
then deliberately exfiltrates the value it was given, or any program running as the user that reads
the vault's OS-sealed store directly. Those are the same-user cases documented in
[SECURITY.md](../SECURITY.md); the mitigation is to sandbox the agent's shell and not approve
commands you don't understand, not to pretend the value can be hidden from a program you handed it to.

---

### Source map

| Concern | File |
|---|---|
| MCP tool surface, `run_with_secrets`, authorization | `crates/keylo-cli/src/mcp.rs` |
| Output redaction | `crates/keylo-core/src/redactor.rs` |
| File delivery (private temp files, wipe-on-drop) | `crates/keylo-cli/src/runner.rs` |
| Access keys (run-only, scope, audit) | `crates/keylo-core/src/access.rs` |
| Identity-check gate | `crates/keylo-core/src/gate.rs` |
| Threat model | `SECURITY.md` |
