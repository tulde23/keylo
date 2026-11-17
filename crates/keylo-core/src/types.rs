//! Secret types (login, API key, database…) with named fields, built-in plus the user's own from
//! types.json. Secret fields live in the encrypted value as a JSON object; the others are item
//! attributes, so they can be searched and shown without unlocking.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secrets::{Secret, SecretDraft, SecretInfo};
use crate::{bail, eq_ic, paths, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FieldKind {
    /// Plain text, readable without unlocking (an attribute, max 256 bytes).
    #[default]
    Text,
    /// The account name / key id; stored as the item's own user name. At most one per type.
    Username,
    Url,
    Number,
    /// Secret, single line. The first secret field is the type's main value.
    Password,
    /// Secret, multi-line (private keys, notes, certificates).
    SecretText,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FieldDefinition {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub kind: FieldKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

impl FieldDefinition {
    fn new(id: &str, label: &str, kind: FieldKind) -> Self {
        FieldDefinition { id: id.into(), label: label.into(), kind, options: None }
    }

    pub fn is_secret(&self) -> bool {
        matches!(self.kind, FieldKind::Password | FieldKind::SecretText)
    }

    /// "Host name" → "host_name".
    pub fn id_for(label: &str) -> String {
        let mut id: String = label
            .trim()
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        while id.contains("__") {
            id = id.replace("__", "_");
        }
        id.trim_matches('_').to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecretTypeDefinition {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldDefinition>,
    #[serde(skip)]
    pub is_built_in: bool,
}

impl SecretTypeDefinition {
    pub fn primary(&self) -> Option<&FieldDefinition> {
        self.fields.iter().find(|f| f.is_secret())
    }

    pub fn username_field(&self) -> Option<&FieldDefinition> {
        self.fields.iter().find(|f| f.kind == FieldKind::Username)
    }

    pub fn field(&self, id: &str) -> Option<&FieldDefinition> {
        self.fields.iter().find(|f| eq_ic(&f.id, id))
    }

    /// Checks a custom type before saving.
    pub fn problem(&self) -> Option<String> {
        let n = &self.name;
        if n.trim().is_empty() {
            return Some("A type needs a name.".into());
        }
        if self.fields.is_empty() {
            return Some(format!("'{n}' needs at least one field."));
        }
        if self.primary().is_none() {
            return Some(format!("'{n}' needs at least one secret field (Password or Secret text)."));
        }
        if self.fields.iter().filter(|f| f.kind == FieldKind::Username).count() > 1 {
            return Some(format!("'{n}' can have only one Username field."));
        }
        if self.fields.len() > 40 {
            return Some(format!("'{n}' has too many fields (max 40)."));
        }
        if let Some(f) = self.fields.iter().find(|f| f.id.is_empty()) {
            let hint = if f.label.is_empty() { String::new() } else { format!(" ('{}' has no letters or digits)", f.label) };
            return Some(format!("Every field in '{n}' needs a label{hint}."));
        }
        for (i, f) in self.fields.iter().enumerate() {
            if self.fields[..i].iter().any(|g| g.id == f.id) {
                return Some(format!("'{n}' has two fields called '{}'.", f.id));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Style {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

pub fn built_in() -> Vec<SecretTypeDefinition> {
    use FieldKind::*;
    let t = |id: &str, name: &str, icon: &str, fields: Vec<FieldDefinition>| SecretTypeDefinition {
        id: id.into(),
        name: name.into(),
        icon: Some(icon.into()),
        color: None,
        fields,
        is_built_in: true,
    };
    let f = FieldDefinition::new;
    let mut engine = f("engine", "Engine", Text);
    engine.options = Some(["postgres", "mysql", "sqlserver", "mongodb", "redis", "other"].map(String::from).to_vec());
    vec![
        t("login", "Login", "Person24", vec![f("username", "Username", Username), f("password", "Password", Password), f("url", "Website", Url)]),
        t("api_key", "API key", "Key24", vec![f("key_id", "Key ID", Username), f("secret", "Secret", Password), f("endpoint", "Endpoint", Url)]),
        t(
            "database",
            "Database",
            "Database24",
            vec![
                engine,
                f("host", "Host", Text),
                f("port", "Port", Number),
                f("database", "Database", Text),
                f("username", "Username", Username),
                f("password", "Password", Password),
                f("connection_string", "Connection string", SecretText),
            ],
        ),
        t(
            "ssh_key",
            "SSH key",
            "Server24",
            vec![
                f("username", "Username", Username),
                f("private_key", "Private key", SecretText),
                f("passphrase", "Passphrase", Password),
                f("host", "Host", Text),
                f("public_key", "Public key", Text),
            ],
        ),
        t("note", "Secure note", "Note24", vec![f("note", "Note", SecretText)]),
    ]
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TypesFile {
    #[serde(default)]
    custom: Vec<SecretTypeDefinition>,
    #[serde(default)]
    built_in_styles: BTreeMap<String, Style>,
}

/// Built-in types plus the user's own (types.json, which also holds styles for built-in types).
pub struct SecretTypeCatalog {
    path: PathBuf,
}

impl Default for SecretTypeCatalog {
    fn default() -> Self {
        SecretTypeCatalog { path: paths::data_dir().join("types.json") }
    }
}

impl SecretTypeCatalog {
    pub fn in_dir(dir: &std::path::Path) -> Self {
        SecretTypeCatalog { path: dir.join("types.json") }
    }

    fn read(&self) -> Result<TypesFile> {
        if !self.path.exists() {
            return Ok(TypesFile::default());
        }
        serde_json::from_str(&fs::read_to_string(&self.path)?).map_err(|e| Error::msg(format!("types.json is invalid: {e}")))
    }

    fn write(&self, file: &TypesFile) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&self.path, serde_json::to_string_pretty(file).unwrap())?;
        Ok(())
    }

    pub fn custom(&self) -> Result<Vec<SecretTypeDefinition>> {
        Ok(self.read()?.custom)
    }

    /// Built-in types with the user's icon and colour applied.
    pub fn built_in_styled(&self) -> Result<Vec<SecretTypeDefinition>> {
        let styles = self.read()?.built_in_styles;
        Ok(built_in()
            .into_iter()
            .map(|mut b| {
                if let Some((_, s)) = styles.iter().find(|(k, _)| eq_ic(k, &b.id)) {
                    if s.icon.is_some() {
                        b.icon = s.icon.clone();
                    }
                    b.color = s.color.clone();
                }
                b
            })
            .collect())
    }

    pub fn all(&self) -> Result<Vec<SecretTypeDefinition>> {
        let mut all = self.built_in_styled()?;
        all.extend(self.custom()?);
        Ok(all)
    }

    /// Icon and colour for built-in types (their fields are fixed).
    pub fn save_built_in_styles(&self, styles: &BTreeMap<String, Style>) -> Result<()> {
        let defaults = built_in();
        let mut file = self.read()?;
        file.built_in_styles = styles
            .iter()
            .filter_map(|(id, s)| {
                let b = defaults.iter().find(|b| &b.id == id)?;
                (s.color.is_some() || s.icon != b.icon).then(|| (id.clone(), s.clone()))
            })
            .collect();
        self.write(&file)
    }

    pub fn find(&self, id: Option<&str>) -> Result<Option<SecretTypeDefinition>> {
        let Some(id) = id else { return Ok(None) };
        Ok(self.all()?.into_iter().find(|t| eq_ic(&t.id, id)))
    }

    /// Find by id or display name ("login", "API key").
    pub fn resolve(&self, id_or_name: &str) -> Result<Option<SecretTypeDefinition>> {
        Ok(self.all()?.into_iter().find(|t| eq_ic(&t.id, id_or_name) || eq_ic(&t.name, id_or_name)))
    }

    /// Replaces the custom types. Ids are derived from names and must not clash with built-ins.
    pub fn save_custom(&self, mut types: Vec<SecretTypeDefinition>) -> Result<()> {
        let defaults = built_in();
        for t in types.iter_mut() {
            t.name = t.name.trim().to_string();
            if t.id.is_empty() {
                t.id = FieldDefinition::id_for(&t.name);
            }
            for f in t.fields.iter_mut() {
                f.label = f.label.trim().to_string();
                // Ids are fixed once set (secrets store data under them); relabeling keeps the id.
                if f.id.is_empty() {
                    f.id = FieldDefinition::id_for(&f.label);
                }
                if f.options.as_ref().is_some_and(Vec::is_empty) {
                    f.options = None;
                }
            }
            if let Some(p) = t.problem() {
                return Err(Error::Keylo(p));
            }
            if t.id.is_empty() {
                bail!("'{}' needs letters or digits in its name.", t.name);
            }
            if let Some(b) = defaults.iter().find(|b| b.id == t.id) {
                bail!("'{}' clashes with the built-in type '{}'.", t.name, b.name);
            }
        }
        for (i, t) in types.iter().enumerate() {
            if types[..i].iter().any(|u| u.id == t.id) {
                bail!("Two types are called '{}'.", t.name);
            }
        }
        let mut file = self.read()?;
        file.custom = types;
        self.write(&file)
    }
}

/// Builds the draft for a typed secret: the Username field becomes the item's user name, other
/// non-secret fields attributes, secret fields the (JSON) value. Empty fields are dropped.
pub fn typed_draft(
    t: &SecretTypeDefinition,
    name: &str,
    fields: &BTreeMap<String, String>,
    category: Option<String>,
    notes: Option<String>,
    icon: Option<String>,
    color: Option<String>,
) -> Result<SecretDraft> {
    if let Some(unknown) = fields.keys().find(|k| t.field(k).is_none()) {
        let ids: Vec<&str> = t.fields.iter().map(|f| f.id.as_str()).collect();
        bail!("'{}' has no field '{unknown}'. Fields: {}.", t.name, ids.join(", "));
    }

    let mut username = None;
    let mut visible = BTreeMap::new();
    let mut secret = BTreeMap::new();
    for f in &t.fields {
        let Some(v) = fields.iter().find(|(k, _)| eq_ic(k, &f.id)).map(|(_, v)| v).filter(|v| !v.is_empty()) else {
            continue;
        };
        if f.kind == FieldKind::Username {
            username = Some(v.trim().to_string());
        } else if f.is_secret() {
            secret.insert(f.id.clone(), v.clone());
        } else {
            visible.insert(f.id.clone(), v.trim().to_string());
        }
    }

    Ok(SecretDraft {
        name: name.to_string(),
        value: Zeroizing::new(serde_json::to_vec(&secret).unwrap()),
        category,
        username,
        notes,
        icon,
        color,
        type_id: Some(t.id.clone()),
        fields: visible,
    })
}

/// Every field's value: attributes plus the decrypted secret fields, and (with `derive`) a database
/// connection string built from the other fields when none is stored.
pub fn read_fields(t: &SecretTypeDefinition, info: &SecretInfo, value: &[u8], derive: bool) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    if let (Some(u), Some(name)) = (t.username_field(), &info.username) {
        fields.insert(u.id.clone(), name.clone());
    }
    for (k, v) in &info.fields {
        fields.insert(k.clone(), v.clone());
    }
    match serde_json::from_slice::<BTreeMap<String, String>>(value) {
        Ok(secret) => fields.extend(secret),
        Err(_) => {
            // A value that isn't JSON (a plain secret whose type was set by hand) is the main field.
            if let (Some(p), Ok(raw)) = (t.primary(), std::str::from_utf8(value)) {
                if !raw.is_empty() {
                    fields.insert(p.id.clone(), raw.to_string());
                }
            }
        }
    }
    if derive && t.id == "database" && !fields.contains_key("connection_string") {
        if let Some(c) = connection_string(&fields) {
            fields.insert("connection_string".into(), c);
        }
    }
    fields
}

/// The main value of a secret as text: the primary field for typed secrets, the value otherwise.
pub fn main_value(t: Option<&SecretTypeDefinition>, secret: &Secret) -> Option<String> {
    match t {
        None => decode_text(&secret.value),
        Some(t) => Some(
            t.primary()
                .and_then(|p| read_fields(t, &secret.info, &secret.value, true).remove(&p.id))
                .unwrap_or_default(),
        ),
    }
}

pub fn decode_text(value: &[u8]) -> Option<String> {
    std::str::from_utf8(value).ok().map(str::to_string)
}

/// .NET's Uri.EscapeDataString: everything but unreserved characters is percent-encoded.
fn escape_data(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A connection string built from a database secret's fields, for engines with a standard form.
pub fn connection_string(f: &BTreeMap<String, String>) -> Option<String> {
    let host = f.get("host")?;
    let port = f.get("port");
    let db = f.get("database").map(String::as_str).unwrap_or("");
    let user = f.get("username");
    let pass = f.get("password");
    let url = |scheme: &str| {
        let auth = match user {
            None => String::new(),
            Some(u) => format!("{}{}@", escape_data(u), pass.map(|p| format!(":{}", escape_data(p))).unwrap_or_default()),
        };
        format!("{scheme}://{auth}{host}{}/{db}", port.map(|p| format!(":{p}")).unwrap_or_default())
    };
    match f.get("engine")?.to_lowercase().as_str() {
        "postgres" | "postgresql" => Some(url("postgresql")),
        "mysql" | "mariadb" => Some(url("mysql")),
        "mongodb" => Some(url("mongodb")),
        "redis" => Some(url("redis")),
        "sqlserver" | "mssql" => Some(format!(
            "Server={host}{};Database={db};User Id={};Password={};TrustServerCertificate=True;",
            port.map(|p| format!(",{p}")).unwrap_or_default(),
            user.map(String::as_str).unwrap_or(""),
            pass.map(String::as_str).unwrap_or("")
        )),
        _ => None,
    }
}
