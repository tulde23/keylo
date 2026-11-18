//! 1Password through its CLI (`op`), which signs in through the 1Password app (Settings →
//! Developer → Integrate with 1Password CLI).
//!
//! Linking: secrets point at items in any signed-in account; values are read with
//! `op item get --reveal` each time they're used and never stored.
//!
//! Pushing: copies Keylo secrets into a vault. Items are created from a JSON template piped on
//! stdin, so values never appear on a command line. A secret with a username becomes a Login item,
//! otherwise a Password item; it's tagged "keylo" plus its category.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use super::process::{Output, Runner};
use super::*;
use crate::types::{self, SecretTypeCatalog};

static OP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct OnePassword {
    runner: Arc<dyn Runner>,
}

/// How to install the 1Password CLI on this OS.
pub fn install_hint() -> &'static str {
    if cfg!(windows) {
        "winget install AgileBits.1Password.CLI"
    } else if cfg!(target_os = "macos") {
        "brew install 1password-cli"
    } else {
        "see https://developer.1password.com/docs/cli/get-started/"
    }
}

fn not_installed() -> String {
    format!("1Password CLI (op) isn't installed. To install it: {}", install_hint())
}

impl OnePassword {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        OnePassword { runner }
    }

    fn op(&self, args: &[&str], stdin: Option<&str>) -> Result<Output> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        // One op at a time: 1Password asks to approve the first call, and calls made while that
        // prompt is open would each ask again. Waiting lets them reuse the approval.
        let _one = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        self.runner.run("op", &args, stdin)
    }

    fn op_or_fail(&self, args: &[&str]) -> Result<String> {
        let out = self.op(args, None)?;
        match out.code {
            None => bail!("{}", not_installed()),
            Some(0) => Ok(out.stdout),
            Some(code) => bail!("1Password: {}", out.first_error_line().unwrap_or_else(|| format!("op exited with {code}."))),
        }
    }

    fn accounts(&self) -> Result<Vec<String>> {
        let out = self.op_or_fail(&["account", "list", "--format", "json"])?;
        let accounts: Vec<String> = parse(&out)?
            .as_array()
            .map(|a| a.iter().filter_map(|x| x["url"].as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        if accounts.is_empty() {
            bail!("1Password CLI isn't signed in to any account. Open 1Password → Settings → Developer → Integrate with 1Password CLI.");
        }
        Ok(accounts)
    }

    fn item(&self, target: &LinkTarget, reveal: bool) -> Result<Value> {
        let mut args = vec!["item", "get", target.item_id.as_str(), "--format", "json"];
        if let Some(v) = target.vault_id.as_deref().filter(|v| !v.is_empty()) {
            args.extend(["--vault", v]);
        }
        if let Some(a) = target.location.as_deref().filter(|v| !v.is_empty()) {
            args.extend(["--account", a]);
        }
        if reveal {
            args.push("--reveal");
        }
        parse(&self.op_or_fail(&args)?)
    }

    /// The id of a Keylo-tagged item with this title, if one was pushed before.
    fn find_pushed(&self, title: &str, vault: &str, settings: &Settings) -> Option<String> {
        let mut args = vec!["item", "list", "--vault", vault, "--tags", "keylo", "--format", "json"];
        let account = setting(settings, "account");
        if let Some(a) = account {
            args.extend(["--account", a]);
        }
        let out = self.op(&args, None).ok().filter(Output::ok)?;
        let list: Value = serde_json::from_str(&out.stdout).ok()?;
        list.as_array()?.iter().find(|i| i["title"].as_str() == Some(title))?["id"].as_str().map(str::to_string)
    }
}

fn parse(text: &str) -> Result<Value> {
    serde_json::from_str(text).map_err(|e| Error::msg(format!("1Password returned something unexpected: {e}")))
}

/// An item's fields with stable ids: username/password/notes by purpose, others from their labels
/// (de-duplicated in order), plus the primary website.
pub(crate) fn fields(item: &Value) -> Vec<(LinkedField, Option<String>)> {
    let mut out = Vec::new();
    let mut ids = UniqueIds::default();
    for f in item["fields"].as_array().into_iter().flatten() {
        let label = f["label"].as_str().unwrap_or("");
        let kind = f["type"].as_str().unwrap_or("");
        let (id, display, secret) = match f["purpose"].as_str() {
            Some("USERNAME") => ("username".to_string(), "Username".to_string(), false),
            Some("PASSWORD") => ("password".to_string(), "Password".to_string(), true),
            Some("NOTES") => ("notes".to_string(), "Notes".to_string(), true),
            // Plain text fields often hold keys and tokens, so only clearly non-secret kinds stay visible.
            _ => (
                FieldDefinition::id_for(label),
                label.to_string(),
                !matches!(kind, "URL" | "EMAIL" | "PHONE" | "DATE" | "MONTH_YEAR" | "MENU"),
            ),
        };
        if display.is_empty() {
            continue;
        }
        out.push((LinkedField { id: ids.take(&id), label: display, secret }, f["value"].as_str().map(str::to_string)));
    }
    let urls = item["urls"].as_array();
    let url = urls.and_then(|u| u.iter().find(|x| x["primary"].as_bool() == Some(true)).or(u.first()));
    if let Some(href) = url.and_then(|u| u["href"].as_str()).filter(|h| !h.is_empty()) {
        out.push((LinkedField::new(&ids.take("website"), "Website", false), Some(href.to_string())));
    }
    out
}

impl VaultProvider for OnePassword {
    fn id(&self) -> &'static str {
        "1password"
    }

    fn display_name(&self) -> &'static str {
        "1Password"
    }

    fn setting_descriptions(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("vault", "Vault to push into (required), e.g. Private"),
            ("account", "Account shorthand or sign-in address, when signed in to more than one (optional)"),
        ]
    }

    fn search(&self, query: Option<&str>, settings: &Settings) -> Result<Vec<LinkedItemSummary>> {
        let accounts = match setting(settings, "account") {
            Some(a) => vec![a.to_string()],
            None => self.accounts()?,
        };
        let mut results = Vec::new();
        for account in accounts {
            let out = self.op_or_fail(&["item", "list", "--account", &account, "--format", "json"])?;
            for item in parse(&out)?.as_array().into_iter().flatten() {
                let s = LinkedItemSummary {
                    item_id: item["id"].as_str().unwrap_or("").into(),
                    title: item["title"].as_str().unwrap_or("(untitled)").into(),
                    vault_id: item["vault"]["id"].as_str().map(str::to_string),
                    vault_name: item["vault"]["name"].as_str().map(str::to_string),
                    location: Some(account.clone()),
                    category: item["category"].as_str().map(str::to_string),
                };
                let texts = [s.title.as_str(), s.vault_name.as_deref().unwrap_or(""), s.category.as_deref().unwrap_or("")];
                if !s.item_id.is_empty() && matches_words(query, &texts) {
                    results.push(s);
                }
            }
        }
        results.sort_by_key(|r| r.title.to_lowercase());
        Ok(results)
    }

    fn describe(&self, target: &LinkTarget, _settings: &Settings) -> Result<Vec<LinkedField>> {
        Ok(fields(&self.item(target, false)?).into_iter().map(|(f, _)| f).collect())
    }

    fn resolve(&self, target: &LinkTarget, _settings: &Settings) -> Result<BTreeMap<String, String>> {
        Ok(fields(&self.item(target, true)?)
            .into_iter()
            .filter_map(|(f, v)| v.filter(|v| !v.is_empty()).map(|v| (f.id, v)))
            .collect())
    }

    fn push_configured(&self, settings: &Settings) -> bool {
        setting(settings, "vault").is_some()
    }

    fn status(&self, settings: &Settings) -> ProviderStatus {
        let Some(vault) = setting(settings, "vault") else {
            return ProviderStatus { ready: false, message: "Set a vault: keylo provider set 1password vault <name>".into() };
        };
        let mut args = vec!["vault", "get", vault, "--format", "json"];
        if let Some(a) = setting(settings, "account") {
            args.extend(["--account", a]);
        }
        match self.op(&args, None) {
            Err(e) => ProviderStatus { ready: false, message: e.to_string() },
            Ok(o) if o.code.is_none() => ProviderStatus { ready: false, message: not_installed() },
            Ok(o) if !o.ok() => ProviderStatus {
                ready: false,
                message: o.first_error_line().unwrap_or_else(|| "op couldn't open the vault. Is the 1Password app unlocked with CLI integration on?".into()),
            },
            Ok(o) => {
                let name = serde_json::from_str::<Value>(&o.stdout).ok().and_then(|v| v["name"].as_str().map(str::to_string));
                ProviderStatus { ready: true, message: format!("Ready (vault '{}')", name.as_deref().unwrap_or(vault)) }
            }
        }
    }

    fn preview(&self, secret_name: &str, settings: &Settings) -> PushPreview {
        let vault = setting(settings, "vault").unwrap_or("");
        let target = format!(
            "the “{vault}” vault ({})",
            setting(settings, "account").unwrap_or("your default 1Password account")
        );
        let exists = (!vault.is_empty()).then(|| self.find_pushed(secret_name, vault, settings).is_some());
        PushPreview { target, exists }
    }

    fn push(&self, secret: &Secret, settings: &Settings) -> PushResult {
        let info = &secret.info;
        let fail = |message: String| PushResult { name: info.name.clone(), succeeded: false, message };
        let Some(vault) = setting(settings, "vault") else { return fail("No 1Password vault configured.".into()) };

        // Typed secrets: the main field is the password; the others go along as labelled fields.
        let t = match SecretTypeCatalog::default().find(info.type_id.as_deref()) {
            Ok(t) => t,
            Err(e) => return fail(e.to_string()),
        };
        let typed = t.as_ref().map(|t| types::read_fields(t, info, &secret.value, true));
        // One-time code fields go as the setup key (1Password makes the codes), not today's code.
        let raw = t.as_ref().map(|t| types::read_fields(t, info, &secret.value, false));
        let value = match (&t, &typed) {
            (Some(t), Some(f)) => Some(t.primary().and_then(|p| f.get(&p.id)).cloned().unwrap_or_default()),
            _ => types::decode_text(&secret.value),
        };
        let Some(value) = value else { return fail("Binary values can't be stored in a 1Password field.".into()) };

        let mut item_fields = Vec::new();
        if let Some(u) = &info.username {
            item_fields.push(json!({"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username", "value": u}));
        }
        item_fields.push(json!({"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": value}));
        item_fields.push(json!({"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": info.notes.clone().unwrap_or_default()}));
        if let (Some(t), Some(typed)) = (&t, &typed) {
            let primary = t.primary().map(|p| p.id.clone());
            for f in t.fields.iter().filter(|f| Some(&f.id) != primary.as_ref() && f.kind != FieldKind::Username) {
                if f.kind == FieldKind::Totp {
                    let key = raw.as_ref().and_then(|r| r.get(&f.id)).and_then(|k| crate::totp::Totp::parse(k).ok());
                    if let Some(totp) = key {
                        item_fields.push(json!({"id": f.id, "type": "OTP", "label": f.label, "value": totp.to_uri(&info.name)}));
                    }
                    continue;
                }
                if let Some(text) = typed.get(&f.id) {
                    let kind = if f.is_secret() { "CONCEALED" } else if f.kind == FieldKind::Url { "URL" } else { "STRING" };
                    item_fields.push(json!({"id": f.id, "type": kind, "label": f.label, "value": text}));
                }
            }
        }
        let mut tags = vec!["keylo".to_string()];
        if let Some(c) = &info.category {
            tags.push(c.clone());
        }
        let item = zeroize::Zeroizing::new(
            json!({
                "title": info.name,
                "category": if info.username.is_none() { "PASSWORD" } else { "LOGIN" },
                "tags": tags,
                "fields": item_fields,
            })
            .to_string(),
        );

        let existing = self.find_pushed(&info.name, vault, settings);
        let mut args = match &existing {
            None => vec!["item", "create", "--vault", vault, "--format", "json"],
            Some(id) => vec!["item", "edit", id.as_str(), "--vault", vault, "--format", "json"],
        };
        if let Some(a) = setting(settings, "account") {
            args.extend(["--account", a]);
        }
        args.push("-");
        match self.op(&args, Some(&item)) {
            Err(e) => fail(e.to_string()),
            Ok(o) if o.code.is_none() => fail(not_installed()),
            Ok(o) if !o.ok() => fail(o.first_error_line().unwrap_or_else(|| format!("op exited with {}.", o.code.unwrap()))),
            Ok(_) => PushResult {
                name: info.name.clone(),
                succeeded: true,
                message: if existing.is_none() { format!("Created in '{vault}'") } else { format!("Updated in '{vault}'") },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_by_purpose_and_label() {
        let item = json!({
            "fields": [
                {"purpose": "USERNAME", "label": "username", "value": "me"},
                {"purpose": "PASSWORD", "label": "password", "value": "pw", "type": "CONCEALED"},
                {"label": "API key", "type": "STRING", "value": "k1"},
                {"label": "API key", "type": "STRING", "value": "k2"},
                {"label": "Email", "type": "EMAIL", "value": "a@b"},
                {"purpose": "NOTES", "label": "notesPlain", "value": ""}
            ],
            "urls": [{"href": "https://a"}, {"href": "https://b", "primary": true}]
        });
        let f = fields(&item);
        let ids: Vec<&str> = f.iter().map(|(f, _)| f.id.as_str()).collect();
        assert_eq!(ids, ["username", "password", "api_key", "api_key_2", "email", "notes", "website"]);
        assert!(f[2].0.secret && !f[4].0.secret && !f[0].0.secret);
        assert_eq!(f[6].1.as_deref(), Some("https://b"));
    }
}
