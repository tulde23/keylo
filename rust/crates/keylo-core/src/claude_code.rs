//! Registers Keylo's MCP server with Claude Code (user scope, so it's in every project but never in
//! a repo), and says whether it's registered and with which access key.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use serde_json::Value;

use crate::access::{self, KeyScope};
use crate::config::KeyloConfig;
use crate::{Error, Result};

pub const SERVER_NAME: &str = "keylo";

/// The `claude` command: on PATH, else in ~/.local/bin (where its installer puts it).
pub fn find_cli() -> Option<PathBuf> {
    crate::links::process::which("claude").or_else(|| {
        let bin = dirs::home_dir()?.join(".local").join("bin");
        let names: &[&str] = if cfg!(windows) { &["claude.exe", "claude.cmd"] } else { &["claude"] };
        names.iter().map(|n| bin.join(n)).find(|p| p.is_file())
    })
}

/// The command that registers `keylo_exe mcp` with `token`, for people to run themselves.
pub fn add_command(keylo_exe: &str, token: &str) -> String {
    format!("claude mcp add {SERVER_NAME} --scope user --env {}={token} -- \"{keylo_exe}\" mcp", access::ENVIRONMENT_VARIABLE)
}

/// Replaces any "keylo" server with one that runs `keylo_exe mcp` with `token` as its access key.
/// The key goes into Claude Code's user config (~/.claude.json), which only this account can read.
pub fn register(keylo_exe: &str, token: &str) -> Result<()> {
    let cli = find_cli().ok_or_else(|| Error::msg("Claude Code ('claude') wasn't found on PATH."))?;
    run(&cli, &["mcp", "remove", SERVER_NAME, "--scope", "user"], true)?;
    let env = format!("{}={token}", access::ENVIRONMENT_VARIABLE);
    run(&cli, &["mcp", "add", SERVER_NAME, "--scope", "user", "--env", &env, "--", keylo_exe, "mcp"], false)
}

fn run(cli: &Path, args: &[&str], allow_failure: bool) -> Result<()> {
    let is_cmd = cli.extension().is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"));
    let mut command = if is_cmd {
        let mut c = Command::new(std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into()));
        c.args(["/d", "/c"]).arg(cli);
        c
    } else {
        Command::new(cli)
    };
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // no console window
    }
    let out = command.output().map_err(|e| Error::msg(format!("Couldn't start Claude Code: {e}")))?;
    if !out.status.success() && !allow_failure {
        // Never echo the arguments: they contain the key.
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let detail = if err.is_empty() { String::from_utf8_lossy(&out.stdout).trim().to_string() } else { err };
        return Err(Error::msg(format!("Claude Code couldn't add the server: {detail}")));
    }
    Ok(())
}

/// Whether Claude Code has Keylo's server at user scope, with which key (matched by hash; the token
/// is never returned), and whether it runs this keylo.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub registered: bool,
    pub command: Option<String>,
    /// The access key it was given, if Keylo still knows it (not revoked or expired).
    pub key_name: Option<String>,
    /// What that key covers: "everything", its categories, or "asks each time".
    pub key_covers: Option<String>,
    pub has_token: bool,
    pub points_at: bool,
}

impl Registration {
    /// One line for people: "connected, with the access key 'Claude Code'" and so on.
    pub fn describe(&self) -> String {
        match (self.registered, &self.key_name, self.points_at) {
            (false, _, _) => "not set up".into(),
            (true, Some(k), true) => format!("connected, with the access key '{k}'"),
            (true, Some(k), false) => format!(
                "set up with the access key '{k}', but it runs another keylo: {}",
                self.command.as_deref().unwrap_or("?")
            ),
            (true, None, _) if self.has_token => "set up, but its access key was revoked, expired or replaced: create a new one".into(),
            (true, None, _) => "set up without an access key, so every request is refused: create one".into(),
        }
    }
}

pub fn inspect(config: &KeyloConfig, keylo_exe: &str) -> Registration {
    let path = dirs::home_dir().map(|h| h.join(".claude.json"));
    let text = path.and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    inspect_text(config, keylo_exe, &text)
}

pub(crate) fn inspect_text(config: &KeyloConfig, keylo_exe: &str, text: &str) -> Registration {
    let none = Registration { registered: false, command: None, key_name: None, key_covers: None, has_token: false, points_at: false };
    let Ok(doc) = serde_json::from_str::<Value>(text) else { return none };
    let Some(server) = doc.get("mcpServers").and_then(|s| s.get(SERVER_NAME)) else { return none };
    let command = server.get("command").and_then(Value::as_str).map(str::to_string);
    let token = server.get("env").and_then(|e| e.get(access::ENVIRONMENT_VARIABLE)).and_then(Value::as_str).filter(|t| !t.is_empty());
    let key = access::find(config, token);
    let same = |a: &str, b: &str| {
        let full = |p: &str| std::path::absolute(p).map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_else(|_| p.to_lowercase());
        full(a) == full(b)
    };
    Registration {
        registered: true,
        points_at: command.as_deref().is_some_and(|c| same(c, keylo_exe)),
        command,
        key_name: key.map(|k| k.name.clone()),
        key_covers: key.map(|k| match k.scope {
            KeyScope::All => "everything".to_string(),
            _ if !k.categories.is_empty() => k.categories.join(", "),
            _ if !k.secrets.is_empty() => format!("{} secret(s)", k.secrets.len()),
            _ => "asks each time".to_string(),
        }),
        has_token: token.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_matches_the_key_by_hash_and_the_command() {
        let mut config = KeyloConfig::default();
        let (key, token) = access::create("Claude Code", None);
        config.access_keys.push(key);
        let exe = if cfg!(windows) { "C:\\Keylo\\keylo.exe" } else { "/opt/keylo/keylo" };
        let text = serde_json::json!({ "mcpServers": { "keylo": { "command": exe, "args": ["mcp"], "env": { "KEYLO_ACCESS_KEY": token } } } }).to_string();
        let r = inspect_text(&config, exe, &text);
        assert!(r.registered && r.points_at && r.has_token);
        assert_eq!(r.key_name.as_deref(), Some("Claude Code"));
        assert!(r.describe().starts_with("connected"));

        let revoked = inspect_text(&KeyloConfig::default(), exe, &text);
        assert!(revoked.key_name.is_none() && revoked.has_token);
        assert!(revoked.describe().contains("revoked"));
        assert!(!inspect_text(&config, exe, "{}").registered);
        assert!(!inspect_text(&config, "D:\\other\\keylo.exe", &text).points_at);
        assert!(add_command(exe, "kyl_x").contains("--env KEYLO_ACCESS_KEY=kyl_x"));
    }
}
