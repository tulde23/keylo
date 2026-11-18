//! Imports another password manager's CSV export: Chrome / Edge / Brave, Firefox, Bitwarden,
//! 1Password, LastPass, KeePassXC and Apple Passwords. The format is recognised from the column
//! names, and each row becomes a login (with its one-time code when the export has one) or, for
//! secure notes, a note. Folders and groups become categories.
//!
//! Exports are plain text with every password in it: the preview never returns passwords, and
//! the CLI and app offer to delete the file afterwards.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Serialize;

use crate::store::{SecretStore, MAX_CATEGORY_LENGTH, MAX_NAME_LENGTH, MAX_NOTES_LENGTH};
use crate::types::{typed_draft, SecretTypeCatalog};
use crate::{bail, Error, Result};

/// One row, as read.
#[derive(Clone, Default)]
struct Entry {
    title: String,
    url: String,
    username: String,
    password: zeroize::Zeroizing<String>,
    totp: zeroize::Zeroizing<String>,
    notes: zeroize::Zeroizing<String>,
    folder: String,
    note_only: bool,
    row: usize,
}

/// What a row becomes (no passwords).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedLogin {
    pub name: String,
    /// "login" or "note".
    #[serde(rename = "type")]
    pub type_id: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub category: Option<String>,
    pub has_one_time_code: bool,
    /// A secret with this name already exists (skipped unless overwriting).
    pub exists: bool,
    /// Things changed or dropped on the way in.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedRow {
    /// 1-based row number in the file, after the header.
    pub row: usize,
    pub title: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordImport {
    /// The app the export came from: "Bitwarden", "Chrome, Edge or Brave"…
    pub format: String,
    pub items: Vec<ImportedLogin>,
    pub skipped: Vec<SkippedRow>,
    /// After an import: how many were written.
    pub imported: usize,
}

/// What importing `path` would do, without touching the store.
pub fn plan(path: &Path, category: Option<&str>, store: &SecretStore) -> Result<PasswordImport> {
    run(path, category, false, store, false)
}

/// Imports `path`. Existing secrets with the same name are skipped unless `overwrite`.
pub fn import(path: &Path, category: Option<&str>, overwrite: bool, store: &SecretStore) -> Result<PasswordImport> {
    run(path, category, overwrite, store, true)
}

/// Whether a file looks like a password manager's CSV export (by its header), and from which app.
pub fn detect(path: &Path) -> Option<String> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_path(path).ok()?;
    let headers = reader.headers().ok()?.clone();
    let columns = Columns::from(&headers);
    columns.password.map(|_| columns.format)
}

fn run(path: &Path, category: Option<&str>, overwrite: bool, store: &SecretStore, write: bool) -> Result<PasswordImport> {
    let (format, entries, mut skipped) = read(path)?;
    let types = SecretTypeCatalog::default();
    let login = types.find(Some("login"))?.ok_or_else(|| Error::msg("The login type is missing."))?;
    let note = types.find(Some("note"))?.ok_or_else(|| Error::msg("The note type is missing."))?;
    let default_category = category.map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);

    let existing: HashSet<String> = store.list()?.into_iter().map(|s| s.name.to_lowercase()).collect();
    let mut used: HashSet<String> = HashSet::new();
    let mut items = Vec::new();
    let mut imported = 0;

    for e in entries {
        let mut warnings = Vec::new();
        let base = name_for(&e);
        let name = unique(&base, &e.username, &mut used);
        let category = clean_category(&e.folder).or_else(|| default_category.clone());
        let exists = existing.contains(&name.to_lowercase());

        let (type_def, fields) = if e.note_only {
            if e.notes.trim().is_empty() {
                skipped.push(SkippedRow { row: e.row, title: e.title.clone(), reason: "An empty note".into() });
                continue;
            }
            (&note, HashMap::from([("note".to_string(), e.notes.to_string())]))
        } else {
            if e.password.is_empty() && e.totp.trim().is_empty() {
                skipped.push(SkippedRow { row: e.row, title: name.clone(), reason: "No password".into() });
                continue;
            }
            let mut f = HashMap::new();
            if !e.username.is_empty() {
                f.insert("username".to_string(), e.username.clone());
            }
            if !e.password.is_empty() {
                f.insert("password".to_string(), e.password.to_string());
            }
            if let Some(u) = fit_url(&e.url) {
                if u != e.url.trim() {
                    warnings.push("The web address was shortened to its site (too long to store).".into());
                }
                f.insert("url".to_string(), u);
            }
            if !e.totp.trim().is_empty() {
                match crate::totp::Totp::parse(&e.totp) {
                    Ok(_) => {
                        f.insert("totp".to_string(), e.totp.trim().to_string());
                    }
                    Err(_) => warnings.push("Its one-time code setup isn't one Keylo can use (it was left out).".into()),
                }
            }
            (&login, f)
        };

        // A login's notes are stored with the item (255 characters at most); longer ones are cut.
        let notes = if e.note_only {
            None
        } else {
            let n = e.notes.trim();
            if n.encode_utf16().count() > MAX_NOTES_LENGTH {
                warnings.push(format!("Notes were cut to {MAX_NOTES_LENGTH} characters."));
                Some(n.chars().take(MAX_NOTES_LENGTH - 1).collect::<String>() + "…")
            } else {
                Some(n.to_string()).filter(|n| !n.is_empty())
            }
        };

        let item = ImportedLogin {
            name: name.clone(),
            type_id: type_def.id.clone(),
            url: fields.get("url").cloned(),
            username: fields.get("username").cloned(),
            category: category.clone(),
            has_one_time_code: fields.contains_key("totp"),
            exists,
            warnings,
        };

        if write && (!exists || overwrite) {
            let ordered: std::collections::BTreeMap<String, String> = fields.into_iter().collect();
            let result = typed_draft(type_def, &name, &ordered, category, notes, None, None).and_then(|draft| {
                let original = if exists { store.find(&name)?.map(|s| s.name) } else { None };
                store.save(&draft, original.as_deref())
            });
            match result {
                Ok(_) => imported += 1,
                Err(err) => {
                    skipped.push(SkippedRow { row: e.row, title: name, reason: err.to_string() });
                    continue;
                }
            }
        }
        items.push(item);
    }
    Ok(PasswordImport { format, items, skipped, imported })
}

/// Which column holds what, from the header.
struct Columns {
    format: String,
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    totp: Option<usize>,
    notes: Option<usize>,
    folder: Option<usize>,
    kind: Option<usize>,
}

impl Columns {
    fn from(headers: &csv::StringRecord) -> Columns {
        let names: Vec<String> = headers.iter().map(|h| h.trim().trim_start_matches('\u{feff}').to_lowercase()).collect();
        let find = |options: &[&str]| options.iter().find_map(|o| names.iter().position(|n| n == o));
        let has = |n: &str| names.iter().any(|x| x == n);
        let format = if has("login_password") {
            "Bitwarden"
        } else if has("grouping") && has("extra") {
            "LastPass"
        } else if has("httprealm") || has("formactionorigin") {
            "Firefox"
        } else if has("group") && has("title") {
            "KeePassXC"
        } else if has("otpauth") && has("archived") {
            "1Password"
        } else if has("otpauth") && has("title") {
            "Apple Passwords"
        } else if has("name") && has("url") && has("username") && has("password") {
            "Chrome, Edge or Brave"
        } else {
            "CSV"
        };
        Columns {
            format: format.into(),
            title: find(&["title", "name"]),
            url: find(&["url", "login_uri", "website", "web site", "uri"]),
            username: find(&["username", "login_username", "user name", "login name", "email"]),
            password: find(&["password", "login_password"]),
            totp: find(&["otpauth", "totp", "login_totp", "one-time password", "otp"]),
            notes: find(&["notes", "note", "extra", "comments", "comment"]),
            folder: find(&["folder", "grouping", "group", "tags"]),
            kind: (format == "Bitwarden").then(|| find(&["type"])).flatten(),
        }
    }
}

fn read(path: &Path) -> Result<(String, Vec<Entry>, Vec<SkippedRow>)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|e| Error::msg(format!("Couldn't open {}: {e}", path.display())))?;
    let headers = reader.headers().map_err(|e| Error::msg(format!("Couldn't read {}: {e}", path.display())))?.clone();
    let c = Columns::from(&headers);
    if c.password.is_none() {
        bail!(
            "{} doesn't look like a password export: it has no password column. Export \"CSV\" from Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass, KeePassXC or Apple Passwords.",
            path.display()
        );
    }

    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    for (i, record) in reader.records().enumerate() {
        let row = i + 1;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                skipped.push(SkippedRow { row, title: String::new(), reason: format!("Unreadable row: {e}") });
                continue;
            }
        };
        let get = |col: Option<usize>| col.and_then(|i| record.get(i)).unwrap_or("").to_string();
        let mut e = Entry {
            title: get(c.title).trim().to_string(),
            url: get(c.url).trim().to_string(),
            username: get(c.username).trim().to_string(),
            password: zeroize::Zeroizing::new(get(c.password)),
            totp: zeroize::Zeroizing::new(get(c.totp)),
            notes: zeroize::Zeroizing::new(get(c.notes)),
            folder: get(c.folder),
            note_only: false,
            row,
        };
        match get(c.kind).trim().to_lowercase().as_str() {
            "" | "login" => {}
            "note" => e.note_only = true,
            other => {
                skipped.push(SkippedRow { row, title: e.title, reason: format!("Not imported: it's a {other}, and only logins and notes are") });
                continue;
            }
        }
        // LastPass marks secure notes with the address http://sn.
        if e.url.eq_ignore_ascii_case("http://sn") {
            e.note_only = true;
            e.url.clear();
        }
        if c.format == "1Password" || c.format == "Bitwarden" {
            // Tags/folders: the first one.
            e.folder = e.folder.split(',').next().unwrap_or("").to_string();
        }
        entries.push(e);
    }
    Ok((c.format, entries, skipped))
}

/// A name from the title, else the site, else the username.
fn name_for(e: &Entry) -> String {
    let raw = if !e.title.is_empty() {
        e.title.clone()
    } else if let Some(host) = host_of(&e.url) {
        host
    } else if !e.username.is_empty() {
        e.username.clone()
    } else {
        "imported login".into()
    };
    let cleaned: String = raw.chars().map(|c| if c == '*' || c.is_control() { ' ' } else { c }).collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    cleaned.chars().take(MAX_NAME_LENGTH - 24).collect::<String>().trim().to_string()
}

/// Two rows with the same name: "github (octocat)", then "github 2", "github 3"…
fn unique(base: &str, username: &str, used: &mut HashSet<String>) -> String {
    let mut candidates = vec![base.to_string()];
    if !username.is_empty() {
        let u: String = username.chars().filter(|c| *c != '*' && !c.is_control()).take(20).collect();
        candidates.push(format!("{base} ({u})"));
    }
    for n in 2.. {
        if let Some(c) = candidates.iter().find(|c| !used.contains(&c.to_lowercase())) {
            used.insert(c.to_lowercase());
            return c.clone();
        }
        candidates = vec![format!("{base} {n}")];
    }
    unreachable!()
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?.split(':').next()?;
    let host = host.trim_start_matches("www.");
    (!host.is_empty() && host.contains('.')).then(|| host.to_lowercase())
}

/// Web addresses are stored as item attributes (256 bytes on Windows): a long one keeps its site.
fn fit_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    if url.len() <= 250 {
        return Some(url.to_string());
    }
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let site = rest.split(['/', '?', '#']).next().unwrap_or("");
    Some(format!("{scheme}://{site}/")).filter(|u| u.len() <= 250)
}

/// A folder, group or tag as a category: KeePass "Root/Work/Cloud" → "Cloud"; "Root" alone → none.
fn clean_category(folder: &str) -> Option<String> {
    let last = folder.split(['/', '\\']).map(str::trim).filter(|p| !p.is_empty()).last()?;
    if last.eq_ignore_ascii_case("root") {
        return None;
    }
    let c: String = last.chars().filter(|c| !c.is_control()).take(MAX_CATEGORY_LENGTH).collect();
    Some(c.trim().to_string()).filter(|c| !c.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    fn csv_file(content: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("keylo-pm-{}.csv", uuid::Uuid::new_v4().simple()));
        std::fs::write(&p, content).unwrap();
        p
    }

    fn store() -> SecretStore {
        let dir = testing::setup();
        SecretStore::new(Some(&dir), Some(&testing::prefix()))
    }

    #[test]
    fn chrome_exports_become_logins() {
        let s = store();
        let f = csv_file("name,url,username,password,note\ngithub.com,https://github.com/login,octocat,pw1,\n,https://accounts.example.com/x,me@example.com,pw2,\"two\nlines\"\nnopass.com,https://nopass.com,u,,\n");
        let p = plan(&f, Some("imported"), &s).unwrap();
        assert_eq!(p.format, "Chrome, Edge or Brave");
        assert_eq!(p.items.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["github.com", "accounts.example.com"]);
        assert_eq!(p.skipped.len(), 1);
        assert!(s.list().unwrap().is_empty(), "a plan writes nothing");

        let r = import(&f, Some("imported"), false, &s).unwrap();
        assert_eq!(r.imported, 2);
        let secret = s.get("github.com").unwrap();
        assert_eq!(secret.info.username.as_deref(), Some("octocat"));
        assert_eq!(secret.info.category.as_deref(), Some("imported"));
        assert_eq!(secret.info.fields["url"], "https://github.com/login");
        assert!(String::from_utf8_lossy(&secret.value).contains("pw1"));
        assert_eq!(s.find("accounts.example.com").unwrap().unwrap().notes.as_deref(), Some("two\nlines"));

        // Again: they exist now, so nothing is overwritten unless asked.
        let r = import(&f, None, false, &s).unwrap();
        assert_eq!(r.imported, 0);
        assert!(r.items.iter().all(|i| i.exists));
    }

    #[test]
    fn bitwarden_exports_keep_folders_codes_and_notes() {
        let s = store();
        let f = csv_file(concat!(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
            "Work,,login,GitHub,,,0,https://github.com,octo,pw,otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n",
            "Work,,login,GitHub,,,0,https://github.com,second,pw2,\n",
            ",,note,Wifi at home,the password is in the drawer,,0,,,,\n",
            ",,card,Visa,,,0,,,,\n",
            ",,login,Broken code,,,0,https://x.io,u,pw,not-a-key\n",
        ));
        let r = import(&f, None, false, &s).unwrap();
        assert_eq!(r.format, "Bitwarden");
        assert_eq!(r.imported, 4);
        let gh = s.find("GitHub").unwrap().unwrap();
        assert_eq!((gh.category.as_deref(), gh.fields.get("totp").map(String::as_str)), (Some("Work"), Some("on")));
        assert!(s.exists("GitHub (second)").unwrap(), "same title, different user");
        assert_eq!(s.find("Wifi at home").unwrap().unwrap().type_id.as_deref(), Some("note"));
        assert!(r.skipped.iter().any(|x| x.reason.contains("card")), "{:?}", r.skipped.iter().map(|x| &x.reason).collect::<Vec<_>>());
        let broken = r.items.iter().find(|i| i.name == "Broken code").unwrap();
        assert!(!broken.has_one_time_code && broken.warnings.iter().any(|w| w.contains("one-time code")));
    }

    #[test]
    fn other_formats_are_recognised() {
        for (header, format) in [
            ("url,username,password,totp,extra,name,grouping,fav", "LastPass"),
            ("\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"", "Firefox"),
            ("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"", "KeePassXC"),
            ("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes", "1Password"),
            ("Title,URL,Username,Password,Notes,OTPAuth", "Apple Passwords"),
        ] {
            assert_eq!(detect(&csv_file(&format!("{header}\n"))).as_deref(), Some(format));
        }
        assert_eq!(detect(&csv_file("a,b,c\n1,2,3\n")), None);
        assert!(plan(&csv_file("a,b\n1,2\n"), None, &store()).is_err());
    }

    #[test]
    fn keepass_groups_and_lastpass_notes() {
        let s = store();
        let f = csv_file("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\"Root/Work/Cloud\",\"AWS\",\"admin\",\"pw\",\"https://aws.amazon.com\",\"\",\"\"\n\"Root\",\"Home\",\"me\",\"pw\",\"\",\"\",\"\"\n");
        import(&f, None, false, &s).unwrap();
        assert_eq!(s.find("AWS").unwrap().unwrap().category.as_deref(), Some("Cloud"));
        assert_eq!(s.find("Home").unwrap().unwrap().category, None);

        let f = csv_file("url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,secret note text,My note,Personal,0\n");
        let r = import(&f, None, false, &s).unwrap();
        assert_eq!(r.imported, 1);
        assert_eq!(s.find("My note").unwrap().unwrap().type_id.as_deref(), Some("note"));
    }

    #[test]
    fn long_notes_and_addresses_are_shortened_with_a_warning() {
        let s = store();
        let long_url = format!("https://example.com/{}", "a".repeat(300));
        let f = csv_file(&format!("name,url,username,password,note\nex,{long_url},u,pw,{}\n", "n".repeat(400)));
        let r = import(&f, None, false, &s).unwrap();
        assert_eq!(r.items[0].warnings.len(), 2);
        let info = s.find("ex").unwrap().unwrap();
        assert_eq!(info.fields["url"], "https://example.com/");
        assert_eq!(info.notes.unwrap().encode_utf16().count(), MAX_NOTES_LENGTH);
    }
}
