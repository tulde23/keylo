# Contributing to Keylo

Thanks for helping. Bug reports, fixes, docs and ideas are all welcome.

## Security problems

Don't open a public issue. Report them privately: see [SECURITY.md](SECURITY.md).

## Issues

- **Bugs:** what you did, what happened, what you expected, `keylo version` and your OS. For the
  app, a screenshot helps. Never paste a secret's value, an access key (`kyl_…`) or a backup's
  password.
- **Features:** describe the problem first, then the change you'd like. For anything large, open an
  issue before writing code, so we can agree on the approach.

## Pull requests

1. Build and test as in the README's [Building from source](README.md#building-from-source):

   ```bash
   cargo test -p keylo-core -p keylo-platform -p keylo-cli
   cd app && npx tsc --noEmit -p .
   ```

2. **Test against a throwaway store, never your real secrets.** Set `KEYLO_HOME` to an empty folder
   and `KEYLO_PREFIX` to something like `KeyloDev:`, so the CLI and the app (`npx tauri dev`) use
   their own data folder and OS-store entries:

   ```bash
   KEYLO_HOME=/tmp/keylo-dev KEYLO_PREFIX=KeyloDev: cargo run -p keylo-cli -- list
   ```

3. Keep each PR to one change, with a description of what it does and how you tested it.
4. Update the README when behaviour changes: it's the user guide.
5. Changes that touch how values are stored, shown, redacted or handed to agents get extra review.
   Say what the change means for the [threat model](SECURITY.md#threat-model).

Merges to `main` that change shipped code are released automatically (see
[Releases](README.md#releases)), so `main` should always be releasable.

## Layout

The crates, the app and the tests are described in the README's
[Layout](README.md#layout). In short: OS-neutral logic in `crates/keylo-core`, each operating system
in `crates/keylo-platform`, the `keylo` command and MCP server in `crates/keylo-cli`, and the desktop
app in `app/`.

## License

By contributing, you agree that your contributions are licensed under the project's
[MIT License](LICENSE).
