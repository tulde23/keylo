//! Exports secrets as a CSV another password manager can import: the counterpart of pm_import.
//!
//! - **Bitwarden** (`bitwarden`): Bitwarden's own CSV. Logins keep their folder (Keylo's category),
//!   one-time code and extra fields; keys, notes and other multi-line secrets become secure notes.
//! - **Browser** (`browser`): `name,url,username,password,note`, the file Chrome, Edge and Brave
//!   export, which they, Firefox, Apple Passwords and most password managers import. Logins only;
//!   anything else that doesn't fit goes in the note.
//!
//! The file holds every exported value in plain text. Linked secrets (1Password, AWS) are left out:
//! their values live in that vault.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::refs::is_linked;
use crate::secrets::SecretInfo;
use crate::store::SecretStore;
use crate::types::{decode_text, read_fields, FieldKind, SecretTypeCatalog, SecretTypeDefinition};
use crate::{bail, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Bitwarden,
    Browser,
}

impl ExportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bitwarden" => Some(Self::Bitwarden),
            "browser" | "chrome" | "csv" => Some(Self::Browser),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Bitwarden => "Bitwarden",
            Self::Browser => "Browser",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSkip {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordExport {
    pub path: String,
    pub format: String,
    pub exported: usize,
    pub skipped: Vec<ExportSkip>,
}

/// One secret, laid out for export. Values are wiped when it's dropped.
#[derive(Default)]
struct Item {
    name: String,
    folder: String,
    /// A secure note rather than a login (Bitwarden), for secrets whose main value is multi-line.
    note_only: bool,
    url: String,
    username: String,
    password: Zeroizing<String>,
    totp: Zeroizing<String>,
    notes: Zeroizing<String>,
    /// Single-line extras: (label, value).
    extras: Vec<(String, Zeroizing<String>)>,
}

/// Writes every secret (or those in `category`) to `path` in `format`. Overwrites `path`.
pub fn export(path: &Path, format: ExportFormat, category: Option<&str>, store: &SecretStore, types: &SecretTypeCatalog) -> Result<PasswordExport> {
    let category = category.map(str::trim).filter(|c| !c.is_empty());
    let mut skipped = Vec::new();
    let mut items = Vec::new();
    for info in store.list()? {
        if category.is_some_and(|c| !info.category.as_deref().is_some_and(|ic| ic.eq_ignore_ascii_case(c))) {
            continue;
        }
        if is_linked(&info) {
            skipped.push(ExportSkip { name: info.name, reason: "Linked to another vault; export it from there".into() });
            continue;
        }
        let secret = store.get(&info.name)?;
        let t = types.find(info.type_id.as_deref())?;
        match item_for(&info, t.as_ref(), &secret.value) {
            Ok(item) => items.push(item),
            Err(reason) => skipped.push(ExportSkip { name: info.name, reason }),
        }
    }
    if let Some(c) = category {
        if items.is_empty() && skipped.is_empty() {
            bail!("No secrets in the category '{c}'.");
        }
    }

    let mut rows: Vec<Vec<Zeroizing<String>>> = Vec::new();
    let header: &[&str] = match format {
        ExportFormat::Bitwarden => &["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"],
        ExportFormat::Browser => &["name", "url", "username", "password", "note"],
    };
    for item in items {
        match format {
            ExportFormat::Bitwarden => rows.push(bitwarden_row(&item)),
            ExportFormat::Browser => match browser_row(&item) {
                Some(row) => rows.push(row),
                None => skipped.push(ExportSkip {
                    name: item.name.clone(),
                    reason: "A key or note, not a password: browsers can't store it (use the Bitwarden format)".into(),
                }),
            },
        }
    }

    // Built in memory (wiped afterwards), then written to a file only you can read.
    let mut buffer = Zeroizing::new(Vec::new());
    {
        let mut w = csv::WriterBuilder::new().terminator(csv::Terminator::CRLF).from_writer(&mut *buffer);
        w.write_record(header).map_err(csv_err)?;
        for row in &rows {
            w.write_record(row.iter().map(|v| v.as_str())).map_err(csv_err)?;
        }
        w.flush().map_err(|e| Error::msg(e.to_string()))?;
    }
    write_private(path, &buffer)?;

    Ok(PasswordExport { path: path.display().to_string(), format: format.label().into(), exported: rows.len(), skipped })
}

fn csv_err(e: csv::Error) -> Error {
    Error::msg(format!("Couldn't write the export: {e}"))
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| Error::msg(format!("Couldn't write {}: {e}", path.display())))?;
    file.write_all(data).map_err(|e| Error::msg(format!("Couldn't write {}: {e}", path.display())))?;
    Ok(())
}

/// How a secret maps onto a password manager's item, or why it can't be exported.
fn item_for(info: &SecretInfo, t: Option<&SecretTypeDefinition>, value: &[u8]) -> std::result::Result<Item, String> {
    let mut item = Item {
        name: info.name.clone(),
        folder: info.category.clone().unwrap_or_default(),
        notes: Zeroizing::new(info.notes.clone().unwrap_or_default()),
        ..Default::default()
    };

    let Some(t) = t else {
        // A plain secret: its value is the password.
        let text = decode_text(value).ok_or("Not text (a binary file); export it with a Keylo backup instead")?;
        item.username = info.username.clone().unwrap_or_default();
        if text.contains('\n') {
            item.note_only = true;
            item.extras.push(("Value".into(), Zeroizing::new(text)));
        } else {
            item.password = Zeroizing::new(text);
        }
        return Ok(item);
    };

    let fields: BTreeMap<String, String> = read_fields(t, info, value, false);
    let primary = t.primary().map(|p| p.id.clone());
    let mut multi_line: Vec<(String, Zeroizing<String>)> = Vec::new();
    for f in &t.fields {
        let Some(v) = fields.get(&f.id).filter(|v| !v.trim().is_empty()) else { continue };
        let v = Zeroizing::new(v.clone());
        match f.kind {
            FieldKind::Username if item.username.is_empty() => item.username = v.to_string(),
            FieldKind::Url if item.url.is_empty() => item.url = v.to_string(),
            FieldKind::Totp if item.totp.is_empty() => item.totp = v,
            _ if Some(&f.id) == primary.as_ref() && f.kind == FieldKind::Password => item.password = v,
            FieldKind::SecretText => multi_line.push((f.label.clone(), v)),
            _ => item.extras.push((f.label.clone(), v)),
        }
    }
    if item.password.is_empty() && !multi_line.is_empty() {
        // A key, certificate or note: a secure note holding its text.
        item.note_only = true;
    }
    item.extras.extend(multi_line);
    if item.password.is_empty() && item.totp.is_empty() && item.extras.is_empty() {
        return Err("No value to export".into());
    }
    Ok(item)
}

/// "Label: value" lines, multi-line values on their own lines under their label.
fn describe(extras: &[(String, Zeroizing<String>)]) -> String {
    let mut out = String::new();
    for (label, v) in extras {
        let multi = v.contains('\n');
        if !out.is_empty() {
            // Single-line fields one per line; a multi-line block gets a blank line around it.
            out.push_str(if multi || out.ends_with("\n\n") { "\n\n" } else { "\n" });
        }
        if multi {
            out.push_str(&format!("{label}:\n{}\n", v.as_str()));
        } else {
            out.push_str(&format!("{label}: {}", v.as_str()));
        }
    }
    out.trim_end().to_string()
}

fn join_notes(parts: &[&str]) -> Zeroizing<String> {
    Zeroizing::new(parts.iter().map(|p| p.trim()).filter(|p| !p.is_empty()).collect::<Vec<_>>().join("\n\n"))
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn bitwarden_row(item: &Item) -> Vec<Zeroizing<String>> {
    // Bitwarden's `fields` column is "name: value" lines, so only single-line extras fit there.
    let (single, multi): (Vec<_>, Vec<_>) = item.extras.iter().cloned().partition(|(_, v)| !v.contains('\n'));
    let fields = Zeroizing::new(single.iter().map(|(l, v)| format!("{}: {}", l.replace(':', " "), v.as_str())).collect::<Vec<_>>().join("\n"));
    let extra_notes = Zeroizing::new(describe(&multi));
    let notes = join_notes(&[&item.notes, &extra_notes]);
    if item.note_only {
        let all = join_notes(&[&notes, &if item.username.is_empty() { String::new() } else { format!("Username: {}", item.username) }]);
        return vec![z(&item.folder), z(""), z("note"), z(&item.name), all, fields, z("0"), z(""), z(""), z(""), z("")];
    }
    vec![
        z(&item.folder),
        z(""),
        z("login"),
        z(&item.name),
        notes,
        fields,
        z("0"),
        z(&item.url),
        z(&item.username),
        item.password.clone(),
        item.totp.clone(),
    ]
}

fn browser_row(item: &Item) -> Option<Vec<Zeroizing<String>>> {
    if item.note_only || item.password.is_empty() {
        return None;
    }
    let totp = if item.totp.is_empty() { String::new() } else { format!("One-time code setup: {}", item.totp.as_str()) };
    let extras = Zeroizing::new(describe(&item.extras));
    let note = join_notes(&[&item.notes, &extras, &totp]);
    Some(vec![z(&item.name), z(&item.url), z(&item.username), item.password.clone(), note])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::StorageKind;

    fn info(name: &str, type_id: Option<&str>, fields: &[(&str, &str)]) -> SecretInfo {
        SecretInfo {
            name: name.into(),
            category: Some("Work".into()),
            username: None,
            notes: Some("note text".into()),
            updated_at: chrono::Utc::now(),
            size: 0,
            storage: StorageKind::CredentialManager,
            icon: None,
            color: None,
            type_id: type_id.map(str::to_string),
            fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    fn type_of(id: &str) -> SecretTypeDefinition {
        crate::types::built_in().into_iter().find(|t| t.id == id).unwrap()
    }

    #[test]
    fn a_plain_secret_is_a_password() {
        let item = item_for(&info("token", None, &[]), None, b"abc123").unwrap();
        assert_eq!(item.password.as_str(), "abc123");
        let row = browser_row(&item).unwrap();
        assert_eq!(row[0].as_str(), "token");
        assert_eq!(row[3].as_str(), "abc123");
        assert_eq!(row[4].as_str(), "note text");
    }

    #[test]
    fn a_binary_value_is_skipped() {
        assert!(item_for(&info("blob", None, &[]), None, &[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn a_login_keeps_its_parts() {
        let t = type_of("login");
        let mut i = info("github", Some("login"), &[("url", "https://github.com")]);
        i.username = Some("octocat".into());
        let value = serde_json::to_vec(&serde_json::json!({"password": "hunter22"})).unwrap();
        let item = item_for(&i, Some(&t), &value).unwrap();
        assert_eq!(item.username, "octocat");
        assert_eq!(item.url, "https://github.com");
        assert_eq!(item.password.as_str(), "hunter22");
        let row = bitwarden_row(&item);
        assert_eq!(row[0].as_str(), "Work");
        assert_eq!(row[2].as_str(), "login");
        assert_eq!(row[7].as_str(), "https://github.com");
        assert_eq!(row[8].as_str(), "octocat");
        assert_eq!(row[9].as_str(), "hunter22");
    }

    #[test]
    fn a_multi_line_secret_is_a_note_and_not_for_browsers() {
        let item = item_for(&info("key", None, &[]), None, b"-----BEGIN KEY-----\nabc\n-----END KEY-----").unwrap();
        assert!(item.note_only);
        assert!(browser_row(&item).is_none());
        let row = bitwarden_row(&item);
        assert_eq!(row[2].as_str(), "note");
        assert!(row[4].contains("-----BEGIN KEY-----\nabc"));
        assert!(row[4].contains("note text"));
    }

    #[test]
    fn extras_are_one_per_line_and_blocks_stand_apart() {
        let e = |l: &str, v: &str| (l.to_string(), Zeroizing::new(v.to_string()));
        assert_eq!(describe(&[e("Host", "h"), e("Port", "1")]), "Host: h\nPort: 1");
        assert_eq!(describe(&[e("Host", "h"), e("Key", "a\nb"), e("Port", "1")]), "Host: h\n\nKey:\na\nb\n\nPort: 1");
    }

    #[test]
    fn formats_parse() {
        assert_eq!(ExportFormat::parse("Bitwarden"), Some(ExportFormat::Bitwarden));
        assert_eq!(ExportFormat::parse("browser"), Some(ExportFormat::Browser));
        assert_eq!(ExportFormat::parse("chrome"), Some(ExportFormat::Browser));
        assert_eq!(ExportFormat::parse("xml"), None);
    }
}
