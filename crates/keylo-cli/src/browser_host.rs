//! The browser extension's native messaging host. A browser starts `keylo` with the extension's
//! origin as its argument (Chrome, Edge, Brave: "chrome-extension://ID/"; Firefox: the manifest's
//! path and the extension's id), then exchanges JSON messages, each preceded by its length (4 bytes,
//! native byte order), on stdin and stdout. Nothing else may be written to stdout.
//!
//! Requests: {"id": n, "type": ..., ...}. Every reply has the request's id and "ok", and on failure
//! "error" (and "locked": true when Keylo needs unlocking first).
//! - status                → version, unlocked, verifier
//! - unlock                → the identity check, then status
//! - logins {url}          → logins for the page (names, usernames, sites; never values)
//! - search {query}        → logins matching the query, for any site
//! - fill {name, url}      → username and password, only for a login that belongs to the page
//! - copy {name, field}    → copies username, password or code to the secure clipboard
//! - generate {length, symbols} → a new password
//!
//! Values leave Keylo only through fill (for the page the login belongs to) and copy, each after the
//! identity check (or within a session), and each is recorded in recent activity.

use std::io::{Read, Write};

use keylo_core::activity::Activity;
use keylo_core::browser::{self, site_matches};
use keylo_core::secrets::SecretInfo;
use keylo_core::{platform, refs, search, types};
use serde_json::{json, Map, Value};

use crate::Context;

/// Whether `keylo` was started by a browser for the extension (and by which).
pub fn caller(argv: &[String]) -> Option<String> {
    let first = argv.first()?;
    let expected = format!("chrome-extension://{}/", browser::CHROME_EXTENSION_ID);
    if first.starts_with("chrome-extension://") {
        return Some(first.clone()).filter(|o| *o == expected);
    }
    // Firefox: [manifest path, extension id].
    (argv.get(1).map(String::as_str) == Some(browser::FIREFOX_EXTENSION_ID)).then(|| browser::FIREFOX_EXTENSION_ID.to_string())
}

/// Chrome on Windows passes the browser window to parent prompts to: --parent-window=HWND.
fn parent_window(argv: &[String]) -> isize {
    argv.iter().find_map(|a| a.strip_prefix("--parent-window=")).and_then(|v| v.parse().ok()).unwrap_or(0)
}

pub fn serve(argv: &[String]) -> i32 {
    let owner = parent_window(argv);
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut len = [0u8; 4];
        if stdin.read_exact(&mut len).is_err() {
            return 0; // the browser closed the connection
        }
        let len = u32::from_ne_bytes(len) as usize;
        if len > 1024 * 1024 {
            return 1;
        }
        let mut body = vec![0u8; len];
        if stdin.read_exact(&mut body).is_err() {
            return 1;
        }
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let mut reply = match handle(&request, owner) {
            Ok(Value::Object(m)) => m,
            Ok(other) => Map::from_iter([("result".to_string(), other)]),
            Err(Failure { message, locked }) => {
                let mut m = Map::new();
                m.insert("error".into(), json!(message));
                if locked {
                    m.insert("locked".into(), json!(true));
                }
                m.insert("ok".into(), json!(false));
                m
            }
        };
        reply.entry("ok").or_insert(json!(true));
        reply.insert("id".into(), id);
        let out = serde_json::to_vec(&Value::Object(reply)).unwrap();
        if stdout.write_all(&(out.len() as u32).to_ne_bytes()).and_then(|_| stdout.write_all(&out)).and_then(|_| stdout.flush()).is_err() {
            return 1;
        }
    }
}

struct Failure {
    message: String,
    locked: bool,
}

impl<E: std::fmt::Display> From<E> for Failure {
    fn from(e: E) -> Self {
        Failure { message: e.to_string(), locked: false }
    }
}

fn cli(e: crate::args::CliError) -> Failure {
    match e {
        crate::args::CliError::Usage(m) => fail(m),
        crate::args::CliError::Keylo(e) => fail(e.to_string()),
    }
}

fn fail(message: impl Into<String>) -> Failure {
    Failure { message: message.into(), locked: false }
}

fn str_arg<'a>(r: &'a Value, name: &str) -> Result<&'a str, Failure> {
    r.get(name).and_then(Value::as_str).ok_or_else(|| fail(format!("Missing '{name}'.")))
}

fn handle(r: &Value, owner: isize) -> Result<Value, Failure> {
    let mut c = Context::new().map_err(cli)?;
    let locked = || Failure { message: "Keylo is locked.".into(), locked: true };
    match r.get("type").and_then(Value::as_str).unwrap_or("") {
        "status" => Ok(status(&c)),
        "unlock" => {
            c.gate.ensure(owner, "Unlock Keylo for your browser", false)?;
            Ok(status(&c))
        }
        "logins" => {
            if !c.gate.is_unlocked() {
                return Err(locked());
            }
            let url = str_arg(r, "url")?;
            let all = logins(&c)?;
            let here: Vec<Value> = all.iter().filter(|s| login_url(s).is_some_and(|u| site_matches(&u, url))).map(row).collect();
            Ok(json!({ "logins": here, "fillable": browser::fillable_page(url) }))
        }
        "search" => {
            if !c.gate.is_unlocked() {
                return Err(locked());
            }
            let query = str_arg(r, "query")?;
            let all = logins(&c)?;
            let found: Vec<Value> = search::filter(&all, Some(query), None).into_iter().take(30).map(row).collect();
            Ok(json!({ "logins": found }))
        }
        "fill" => {
            let name = str_arg(r, "name")?;
            let url = str_arg(r, "url")?;
            let info = c.store.find(name)?.ok_or_else(|| fail(format!("No login named '{name}'.")))?;
            let site = login_url(&info).ok_or_else(|| fail(format!("'{name}' has no website, so it can't be filled anywhere. Copy it instead.")))?;
            if !site_matches(&site, url) {
                return Err(fail(format!("'{name}' is for {site}, not this page. Copy it instead if you're sure.")));
            }
            c.gate.ensure(owner, &format!("Keylo: fill '{name}' in your browser"), true)?;
            let username = info.username.clone().unwrap_or_default();
            let password = c.field_value(&info, Some("password"), None).map(|v| v.to_string()).map_err(cli)?;
            let _ = Activity::default().record_use(&info.name, "filled in browser");
            Ok(json!({ "username": username, "password": password }))
        }
        "copy" => {
            let name = str_arg(r, "name")?;
            let field = str_arg(r, "field")?;
            let info = c.store.find(name)?.ok_or_else(|| fail(format!("No login named '{name}'.")))?;
            let text = match field {
                "username" => {
                    if !c.gate.is_unlocked() {
                        return Err(locked());
                    }
                    info.username.clone().ok_or_else(|| fail(format!("'{name}' has no username.")))?
                }
                "password" | "code" => {
                    c.gate.ensure(owner, &format!("Keylo: copy '{name}'"), true)?;
                    let f = if field == "code" { "totp" } else { "password" };
                    let v = c.field_value(&info, Some(f), None).map_err(cli)?.to_string();
                    let _ = Activity::default().record_use(&info.name, "copied in browser");
                    v
                }
                other => return Err(fail(format!("Can't copy '{other}'."))),
            };
            crate::copy_with_timeout(&c, &text, "Copied").map_err(cli)?;
            Ok(json!({ "seconds": c.config.clipboard_seconds }))
        }
        "generate" => {
            let length = r.get("length").and_then(Value::as_u64).unwrap_or(20) as usize;
            let symbols = r.get("symbols").and_then(Value::as_bool).unwrap_or(true);
            Ok(json!({ "password": keylo_core::password::generate(length, symbols) }))
        }
        other => Err(fail(format!("Unknown request '{other}'."))),
    }
}

fn status(c: &Context) -> Value {
    json!({
        "version": keylo_core::version::VERSION,
        "unlocked": c.gate.is_unlocked(),
        "verifier": platform::current().verifier_name(),
    })
}

/// Secrets that can sign in somewhere: logins, and any typed or linked secret with a password and a
/// website.
fn logins(c: &Context) -> Result<Vec<SecretInfo>, Failure> {
    Ok(c.store.list()?.into_iter().filter(|s| s.type_id.as_deref() == Some("login") || (login_url(s).is_some() && s.username.is_some())).collect())
}

/// The website a login is for: its url field. (A linked login's website is in its vault, read live,
/// so linked logins are found by search, not by page.)
fn login_url(s: &SecretInfo) -> Option<String> {
    if refs::is_linked(s) {
        return None;
    }
    ["url", "website", "admin_url", "login_url"].iter().find_map(|k| s.fields.get(*k)).cloned().filter(|u| !u.trim().is_empty())
}

fn row(s: &SecretInfo) -> Value {
    json!({
        "name": s.name,
        "username": s.username,
        "url": login_url(s),
        "category": s.category,
        "hasCode": s.fields.get("totp").is_some_and(|v| v == types::TOTP_MARKER),
    })
}
