//! Secrets that point at an item in another vault (1Password, AWS Secrets Manager). Keylo stores
//! only the reference (as attributes, type "link"); values are read from the vault through its CLI
//! whenever the secret is used, so they're never copied and changes there apply at once. Access
//! keys, approvals, redaction and the audit log apply exactly as for Keylo's own secrets.
//!

pub mod aws;
pub mod onepassword;
pub mod process;

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::KeyloConfig;
use crate::secrets::{Secret, SecretDraft, SecretInfo};
use crate::store::MAX_CATEGORY_LENGTH;
use crate::types::{FieldDefinition, FieldKind, SecretTypeDefinition};
use crate::{bail, eq_ic, Error, Result};

pub use crate::refs::LINK_TYPE as TYPE_ID;
use process::{Runner, SystemRunner};

/// A provider's settings from config.json ("providers": { "aws": { ... } }).
pub type Settings = BTreeMap<String, String>;

/// [`LinkTarget::location`] of a link made per environment: its item id is the secret's name, and
/// the environment it's used in (name@env, else the default) picks the account.
pub const PER_ENVIRONMENT: &str = "@env";
/// Set in the settings handed to a provider for a per-environment link: the environment to read.
pub const ENVIRONMENT_SETTING: &str = "environment";
/// Set alongside [`ENVIRONMENT_SETTING`] when the secret has another name in that environment.
pub const SECRET_ID_SETTING: &str = "secret_id";

const PROVIDER_KEY: &str = "link_provider";
const ITEM_KEY: &str = "link_item";
const VAULT_KEY: &str = "link_vault";
const LOCATION_KEY: &str = "link_location";
const TITLE_KEY: &str = "link_title";
const WHERE_KEY: &str = "link_where";
const FIELDS_KEY: &str = "link_fields";
const ONLY_FIELD_KEY: &str = "link_field";
const ENV_NAMES_KEY: &str = "link_env_names";

/// A setting, trimmed, when it's there and not blank (keys match case-insensitively).
pub fn setting<'a>(settings: &'a Settings, key: &str) -> Option<&'a str> {
    settings
        .iter()
        .find(|(k, _)| eq_ic(k, key))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------- items and fields

/// An item found in a linked vault (no values).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedItemSummary {
    pub item_id: String,
    pub title: String,
    pub vault_id: Option<String>,
    pub vault_name: Option<String>,
    /// Provider-specific scope such as a 1Password account or an AWS region.
    pub location: Option<String>,
    pub category: Option<String>,
}

/// A field of a linked item. `id` is stable between describing and resolving an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedField {
    pub id: String,
    pub label: String,
    pub secret: bool,
}

impl LinkedField {
    pub fn new(id: &str, label: &str, secret: bool) -> Self {
        LinkedField { id: id.into(), label: label.into(), secret }
    }
}

/// Where a linked secret lives in its vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkTarget {
    pub provider: String,
    pub item_id: String,
    pub vault_id: Option<String>,
    pub location: Option<String>,
}

/// Field ids made unique in order: "token", "token_2", ...
#[derive(Default)]
pub(crate) struct UniqueIds(std::collections::HashSet<String>);

impl UniqueIds {
    pub fn take(&mut self, id: &str) -> String {
        let id = if id.is_empty() { "field" } else { id };
        let mut candidate = id.to_string();
        let mut n = 2;
        while !self.0.insert(candidate.to_lowercase()) {
            candidate = format!("{id}_{n}");
            n += 1;
        }
        candidate
    }
}

/// Fields of linked items count as secret unless they're plainly identity or address fields:
/// vaults often keep keys in ordinary text fields, and a wrongly visible key is worse than a masked
/// hostname.
pub fn looks_public(field_id: &str) -> bool {
    field_id == "username"
        || field_id == "website"
        || field_id.starts_with("website_")
        || field_id.contains("email")
        || field_id.contains("url")
}

/// Every word of `query` is in one of `texts` (case-insensitive); an empty query matches all.
pub(crate) fn matches_words(query: Option<&str>, texts: &[&str]) -> bool {
    let Some(q) = query.map(str::trim).filter(|q| !q.is_empty()) else { return true };
    let texts: Vec<String> = texts.iter().map(|t| t.to_lowercase()).collect();
    q.split_whitespace().all(|w| {
        let w = w.to_lowercase();
        texts.iter().any(|t| t.contains(&w))
    })
}

// ---------------------------------------------------------------------------- environments

/// A named environment of a vault (dev, uat, prod…): which profile and region to read it with on
/// this computer. `always_ask` makes every use from it ask the user, whatever an access key covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEnvironment {
    pub name: String,
    pub profile: Option<String>,
    pub region: Option<String>,
    pub always_ask: bool,
}

/// Environments live in a provider's settings (config.json, so per computer: each machine maps
/// "prod" to its own profile) as "env:NAME" = "profile|region|ask", plus "default_environment".
pub mod environments {
    use super::*;

    pub const PREFIX: &str = "env:";
    pub const DEFAULT_KEY: &str = "default_environment";

    pub fn read(settings: &Settings) -> Vec<VaultEnvironment> {
        let mut all: Vec<VaultEnvironment> = settings
            .iter()
            .filter(|(k, _)| k.len() > PREFIX.len() && k[..PREFIX.len()].eq_ignore_ascii_case(PREFIX))
            .map(|(k, v)| {
                let parts: Vec<&str> = v.split('|').collect();
                let part = |i: usize| parts.get(i).map(|p| p.trim()).filter(|p| !p.is_empty()).map(str::to_string);
                VaultEnvironment {
                    name: k[PREFIX.len()..].to_string(),
                    profile: part(0),
                    region: part(1),
                    always_ask: part(2).as_deref() == Some("ask"),
                }
            })
            .collect();
        all.sort_by_key(|e| e.name.to_lowercase());
        all
    }

    pub fn find(settings: &Settings, name: &str) -> Option<VaultEnvironment> {
        read(settings).into_iter().find(|e| eq_ic(&e.name, name))
    }

    /// The configured default, else the only environment, else None.
    pub fn default(settings: &Settings) -> Option<String> {
        let all = read(settings);
        if let Some(name) = setting(settings, DEFAULT_KEY) {
            if let Some(e) = all.iter().find(|e| eq_ic(&e.name, name)) {
                return Some(e.name.clone());
            }
        }
        (all.len() == 1).then(|| all[0].name.clone())
    }

    /// Replaces the environments in `settings`.
    pub fn write(settings: &mut Settings, environments: &[VaultEnvironment], default: Option<&str>) -> Result<()> {
        settings.retain(|k, _| !(k.len() >= PREFIX.len() && k[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)));
        for e in environments {
            if !is_valid_name(&e.name) {
                bail!("'{}' isn't a valid environment name: use letters, digits, '-' and '_'.", e.name);
            }
            settings.insert(
                format!("{PREFIX}{}", e.name),
                format!(
                    "{}|{}|{}",
                    e.profile.as_deref().unwrap_or("").trim(),
                    e.region.as_deref().unwrap_or("").trim(),
                    if e.always_ask { "ask" } else { "" }
                ),
            );
        }
        settings.retain(|k, _| !eq_ic(k, DEFAULT_KEY));
        if let Some(d) = default.map(str::trim).filter(|d| !d.is_empty()) {
            settings.insert(DEFAULT_KEY.into(), d.into());
        }
        Ok(())
    }

    pub fn is_valid_name(name: &str) -> bool {
        crate::refs::is_valid_environment_name(name)
    }

    /// New environments named like production start as "always ask".
    pub fn looks_like_production(name: &str) -> bool {
        let n = name.to_lowercase();
        n == "prod" || n == "production" || n == "prd" || n.starts_with("prod-")
    }
}

// ---------------------------------------------------------------------------- links

/// A link as stored with a secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    pub target: LinkTarget,
    pub title: String,
    /// Where the item lives, for display ("Private · my.1password.com").
    pub r#where: Option<String>,
    pub fields: Vec<LinkedField>,
    /// When set, the link exposes just this field of the item.
    pub only_field: Option<String>,
    /// For a per-environment link, the secret's name in environments where it differs.
    pub environment_names: BTreeMap<String, String>,
}

impl Link {
    pub fn is_per_environment(&self) -> bool {
        self.target.location.as_deref() == Some(PER_ENVIRONMENT)
    }

    pub fn visible_fields(&self) -> Vec<&LinkedField> {
        match &self.only_field {
            None => self.fields.iter().collect(),
            Some(only) => self.fields.iter().filter(|f| &f.id == only).collect(),
        }
    }

    /// The field used when no field is named: the chosen one, else the first secret field.
    pub fn main_field(&self) -> Option<String> {
        if let Some(o) = &self.only_field {
            return Some(o.clone());
        }
        let visible = self.visible_fields();
        visible.iter().find(|f| f.secret).or(visible.first()).map(|f| f.id.clone())
    }

    /// The secret's name in `environment`, when it has its own there.
    pub fn name_in(&self, environment: &str) -> Option<&str> {
        self.environment_names.iter().find(|(k, _)| eq_ic(k, environment)).map(|(_, v)| v.as_str())
    }
}

pub fn is_linked(info: &SecretInfo) -> bool {
    crate::refs::is_linked(info)
}

fn field<'a>(info: &'a SecretInfo, key: &str) -> Option<&'a str> {
    info.fields.iter().find(|(k, _)| eq_ic(k, key)).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

pub fn read(info: &SecretInfo) -> Option<Link> {
    if !is_linked(info) {
        return None;
    }
    let provider = field(info, PROVIDER_KEY)?;
    let item = field(info, ITEM_KEY)?;
    Some(Link {
        target: LinkTarget {
            provider: provider.into(),
            item_id: item.into(),
            vault_id: field(info, VAULT_KEY).map(str::to_string),
            location: field(info, LOCATION_KEY).map(str::to_string),
        },
        title: field(info, TITLE_KEY).unwrap_or(&info.name).to_string(),
        r#where: field(info, WHERE_KEY).map(str::to_string),
        fields: decode_fields(field(info, FIELDS_KEY)),
        only_field: field(info, ONLY_FIELD_KEY).map(str::to_string),
        environment_names: decode_environment_names(field(info, ENV_NAMES_KEY)),
    })
}

/// A draft that stores `link` (no value: the stored value is an empty JSON object).
pub fn draft(name: &str, link: &Link, category: Option<&str>, notes: Option<&str>, icon: Option<&str>, color: Option<&str>) -> SecretDraft {
    let mut f = BTreeMap::new();
    f.insert(PROVIDER_KEY.to_string(), link.target.provider.clone());
    f.insert(ITEM_KEY.to_string(), link.target.item_id.clone());
    f.insert(TITLE_KEY.to_string(), fit(&link.title));
    f.insert(FIELDS_KEY.to_string(), encode_fields(&link.fields));
    if let Some(v) = link.target.vault_id.as_deref().filter(|v| !v.is_empty()) {
        f.insert(VAULT_KEY.into(), v.into());
    }
    if let Some(l) = link.target.location.as_deref().filter(|v| !v.is_empty()) {
        f.insert(LOCATION_KEY.into(), l.into());
    }
    if let Some(w) = link.r#where.as_deref().filter(|v| !v.is_empty()) {
        f.insert(WHERE_KEY.into(), fit(w));
    }
    if let Some(o) = link.only_field.as_deref().filter(|v| !v.is_empty()) {
        f.insert(ONLY_FIELD_KEY.into(), o.into());
    }
    if !link.environment_names.is_empty() {
        let text: Vec<String> = link.environment_names.iter().map(|(k, v)| format!("{k}={v}")).collect();
        f.insert(ENV_NAMES_KEY.into(), fit(&text.join(";")));
    }
    SecretDraft {
        name: name.into(),
        value: zeroize::Zeroizing::new(b"{}".to_vec()),
        category: category.map(str::to_string),
        username: None,
        notes: notes.map(str::to_string),
        icon: icon.map(str::to_string),
        color: color.map(str::to_string),
        type_id: Some(TYPE_ID.into()),
        fields: f,
    }
}

/// A type describing the link's fields, so linked secrets show and behave like typed ones.
pub fn as_type(link: &Link, provider_name: &str) -> SecretTypeDefinition {
    SecretTypeDefinition {
        id: TYPE_ID.into(),
        name: if link.is_per_environment() {
            format!("Linked · {provider_name} · per environment")
        } else {
            format!("Linked · {provider_name}")
        },
        icon: Some("Link24".into()),
        color: None,
        is_built_in: true,
        fields: link
            .visible_fields()
            .into_iter()
            .map(|f| FieldDefinition {
                id: f.id.clone(),
                label: f.label.clone(),
                kind: if f.secret { FieldKind::Password } else { FieldKind::Text },
                options: None,
            })
            .collect(),
    }
}

/// The suggested category for an item: "1Password · Private", plus the account when items come
/// from several (vaults of the same name in two accounts shouldn't merge).
pub fn default_category(provider_name: &str, item: &LinkedItemSummary, several_locations: bool) -> String {
    let mut category = match item.vault_name.as_deref().filter(|v| !v.is_empty()) {
        Some(v) => format!("{provider_name} · {v}"),
        None => provider_name.to_string(),
    };
    if several_locations {
        if let Some(l) = item.location.as_deref().filter(|l| !l.is_empty()) {
            let host = l.split('.').next().unwrap_or(l);
            category += &format!(" ({})", if host.eq_ignore_ascii_case("my") { "personal" } else { host });
        }
    }
    category.chars().take(MAX_CATEGORY_LENGTH).collect()
}

/// The environment a use of `info` reads from: `requested`, else the provider's default. None for
/// an ordinary link (naming an environment for one is an error).
pub fn environment_for(info: &SecretInfo, config: &KeyloConfig, requested: Option<&str>) -> Result<Option<VaultEnvironment>> {
    let link = match read(info) {
        Some(l) if l.is_per_environment() => l,
        _ => {
            return match requested {
                None => Ok(None),
                Some(r) => bail!("'{}' isn't linked per environment, so '@{r}' doesn't apply.", info.name),
            }
        }
    };
    let settings = provider_settings(config, &link.target.provider);
    let all = environments::read(&settings);
    let names = if all.is_empty() {
        "none yet".to_string()
    } else {
        all.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join(", ")
    };
    let name = match requested.map(str::to_string).or_else(|| environments::default(&settings)) {
        Some(n) => n,
        None => bail!(
            "'{}' is linked per environment and no default is set. Use {}@ENV with one of: {names}.",
            info.name,
            info.name
        ),
    };
    match environments::find(&settings, &name) {
        Some(e) => Ok(Some(e)),
        None => bail!("There's no environment '{name}'. Environments: {names} (Settings → Vault providers)."),
    }
}

/// A provider's settings from config (empty when there are none).
pub fn provider_settings(config: &KeyloConfig, provider: &str) -> Settings {
    config
        .providers
        .iter()
        .find(|(k, _)| eq_ic(k, provider))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// The linked item's current values (only the chosen field, for a single-field link), read from
/// its vault; for a per-environment link, from `environment` (else the default one).
pub fn resolve(info: &SecretInfo, config: &KeyloConfig, environment: Option<&str>) -> Result<BTreeMap<String, String>> {
    let link = read(info).ok_or_else(|| Error::msg(format!("'{}' isn't a valid link.", info.name)))?;
    let provider = find(&link.target.provider).ok_or_else(|| {
        Error::msg(format!("'{}' is linked to '{}', which this build of Keylo doesn't know.", info.name, link.target.provider))
    })?;
    resolve_with(provider.as_ref(), info, &link, config, environment)
}

pub fn resolve_with(
    provider: &dyn VaultProvider,
    info: &SecretInfo,
    link: &Link,
    config: &KeyloConfig,
    environment: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut settings = provider_settings(config, provider.id());
    // Per environment: tell the provider which environment, and the secret's name there if it differs.
    if let Some(env) = environment_for(info, config, environment)? {
        if let Some(other) = link.name_in(&env.name) {
            settings.insert(SECRET_ID_SETTING.into(), other.into());
        }
        settings.insert(ENVIRONMENT_SETTING.into(), env.name);
    }

    let values = provider.resolve(&link.target, &settings)?;
    let mut result = BTreeMap::new();
    for f in link.visible_fields() {
        if let Some(v) = values.iter().find(|(k, _)| eq_ic(k, &f.id)).map(|(_, v)| v).filter(|v| !v.is_empty()) {
            result.insert(f.id.clone(), v.clone());
        }
    }
    // Fields added to the item after linking still come through (unless the link is to one field).
    if link.only_field.is_none() {
        for (id, v) in values {
            if !v.is_empty() && !result.keys().any(|k| eq_ic(k, &id)) {
                result.insert(id, v);
            }
        }
    }
    Ok(result)
}

/// One field of resolved values: the link's main field by default; "key" means username.
pub fn pick(info: &SecretInfo, link: &Link, values: &BTreeMap<String, String>, field: Option<&str>) -> Result<String> {
    let lower = field.map(str::to_lowercase);
    let id = match lower.as_deref() {
        None | Some("value") => link.main_field(),
        Some("key") => Some("username".into()),
        Some(f) => Some(f.to_string()),
    };
    if let Some(v) = id.as_deref().and_then(|id| values.iter().find(|(k, _)| eq_ic(k, id))).map(|(_, v)| v) {
        return Ok(v.clone());
    }
    let what = match field {
        None => "value".to_string(),
        Some(f) => format!("field '{f}'"),
    };
    let keys: Vec<&str> = values.keys().map(String::as_str).collect();
    bail!("'{}' has no {what} in {}. Fields: {}.", info.name, link.title, keys.join(", "))
}

// Fields are stored as "id|label|1;id|label|0" (1 = secret), trimmed to fit a 256-byte attribute.
fn encode_fields(fields: &[LinkedField]) -> String {
    let clean = |s: &str| s.replace('|', "/").replace(';', ",");
    let mut text = String::new();
    for f in fields {
        let part = format!("{}|{}|{}", clean(&f.id), clean(&f.label), if f.secret { 1 } else { 0 });
        if text.len() + 1 + part.len() > 250 {
            break;
        }
        if !text.is_empty() {
            text.push(';');
        }
        text.push_str(&part);
    }
    text
}

fn decode_fields(text: Option<&str>) -> Vec<LinkedField> {
    text.unwrap_or("")
        .split(';')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let parts: Vec<&str> = p.split('|').collect();
            (parts.len() == 3).then(|| LinkedField::new(parts[0], parts[1], parts[2] == "1" || !looks_public(parts[0])))
        })
        .collect()
}

fn decode_environment_names(text: Option<&str>) -> BTreeMap<String, String> {
    text.unwrap_or("")
        .split(';')
        .filter_map(|p| p.split_once('='))
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fit(s: &str) -> String {
    let mut s = s.to_string();
    while s.len() > 250 {
        s.pop();
    }
    s
}

// ---------------------------------------------------------------------------- providers

/// Whether a provider can be used right now, and if not, what to do.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderStatus {
    pub ready: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushResult {
    pub name: String,
    pub succeeded: bool,
    pub message: String,
}

/// Where a push would go, shown before it happens.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PushPreview {
    /// E.g. "the “Private” vault (my.1password.com)".
    pub target: String,
    /// Whether it would update an item pushed before; None when unknown.
    pub exists: Option<bool>,
}

/// A vault Keylo links secrets to and pushes secrets into, through its CLI. Values never travel on
/// a command line: they're read from the CLI's stdout and written to its stdin (or a temporary
/// file Keylo deletes).
pub trait VaultProvider: Send + Sync {
    /// Stable id stored in links and config, e.g. "1password".
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    /// Settings read from config ("providers.{id}"), with a description of each.
    fn setting_descriptions(&self) -> Vec<(&'static str, &'static str)>;
    /// Named environments (dev, uat, prod…) in its settings; see [`environments`].
    fn has_environments(&self) -> bool {
        false
    }
    /// Suggested values for a setting (any text is still accepted), or None for free text.
    fn setting_options(&self, _key: &str) -> Option<Vec<String>> {
        None
    }

    /// Items whose title (or vault/category) contains every word of `query`; all when it's empty.
    fn search(&self, query: Option<&str>, settings: &Settings) -> Result<Vec<LinkedItemSummary>>;
    /// The item's fields, without values.
    fn describe(&self, target: &LinkTarget, settings: &Settings) -> Result<Vec<LinkedField>>;
    /// The item's current non-empty field values, by field id.
    fn resolve(&self, target: &LinkTarget, settings: &Settings) -> Result<BTreeMap<String, String>>;

    /// Whether pushing is set up (cheap, no I/O).
    fn push_configured(&self, settings: &Settings) -> bool;
    fn status(&self, settings: &Settings) -> ProviderStatus;
    fn preview(&self, secret_name: &str, settings: &Settings) -> PushPreview;
    fn push(&self, secret: &Secret, settings: &Settings) -> PushResult;
}

/// The built-in providers, sorted by name.
pub fn providers() -> Vec<Box<dyn VaultProvider>> {
    let runner: Arc<dyn Runner> = Arc::new(SystemRunner::default());
    vec![Box::new(onepassword::OnePassword::new(runner.clone())), Box::new(aws::Aws::new(runner))]
}

pub fn find(id: &str) -> Option<Box<dyn VaultProvider>> {
    providers().into_iter().find(|p| eq_ic(p.id(), id))
}

/// A provider's display name, or its id when this build doesn't know it.
pub fn provider_name(id: &str) -> String {
    find(id).map(|p| p.display_name().to_string()).unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::StorageKind;

    pub(crate) fn info_from(draft: &SecretDraft) -> SecretInfo {
        SecretInfo {
            name: draft.name.clone(),
            category: draft.category.clone(),
            username: None,
            notes: None,
            updated_at: chrono::Utc::now(),
            size: 2,
            storage: StorageKind::CredentialManager,
            icon: None,
            color: None,
            type_id: draft.type_id.clone(),
            fields: draft.fields.clone(),
        }
    }

    fn sample() -> Link {
        Link {
            target: LinkTarget { provider: "aws".into(), item_id: "orders/db".into(), vault_id: None, location: Some(PER_ENVIRONMENT.into()) },
            title: "orders/db".into(),
            r#where: Some("per environment".into()),
            fields: vec![LinkedField::new("username", "username", false), LinkedField::new("password", "password", true)],
            only_field: None,
            environment_names: [("prod".to_string(), "orders/db-prod".to_string())].into(),
        }
    }

    #[test]
    fn draft_round_trips_in_the_stored_format() {
        let d = draft("orders-db", &sample(), Some("AWS"), None, None, None);
        assert_eq!(d.fields["link_fields"], "username|username|0;password|password|1");
        assert_eq!(d.fields["link_env_names"], "prod=orders/db-prod");
        let link = read(&info_from(&d)).unwrap();
        assert!(link.is_per_environment());
        assert_eq!(link.main_field().as_deref(), Some("password"));
        assert_eq!(link.name_in("PROD"), Some("orders/db-prod"));
        assert_eq!(link.fields, sample().fields);
    }

    #[test]
    fn environments_read_write_and_default() {
        let mut s = Settings::new();
        s.insert("profile".into(), "x".into());
        let envs = vec![
            VaultEnvironment { name: "dev".into(), profile: Some("dev-p".into()), region: Some("us-east-1".into()), always_ask: false },
            VaultEnvironment { name: "prod".into(), profile: Some("prod-p".into()), region: None, always_ask: true },
        ];
        environments::write(&mut s, &envs, Some("dev")).unwrap();
        assert_eq!(s["env:prod"], "prod-p||ask");
        assert_eq!(environments::read(&s), envs);
        assert_eq!(environments::default(&s).as_deref(), Some("dev"));
        environments::write(&mut s, &envs[1..], None).unwrap();
        assert_eq!(environments::default(&s).as_deref(), Some("prod"));
        assert_eq!(s["profile"], "x");
        assert!(environments::write(&mut s, &[VaultEnvironment { name: "a b".into(), profile: None, region: None, always_ask: false }], None).is_err());
    }

    #[test]
    fn environment_for_checks_the_link_kind() {
        let mut config = KeyloConfig::default();
        let mut s = Settings::new();
        environments::write(&mut s, &[VaultEnvironment { name: "uat".into(), profile: None, region: None, always_ask: false }], None).unwrap();
        config.providers.insert("aws".into(), s);
        let info = info_from(&draft("orders-db", &sample(), None, None, None, None));
        assert_eq!(environment_for(&info, &config, None).unwrap().unwrap().name, "uat");
        assert!(environment_for(&info, &config, Some("prod")).is_err());
        let mut plain = sample();
        plain.target.location = Some("us-east-1".into());
        let info = info_from(&draft("x", &plain, None, None, None, None));
        assert!(environment_for(&info, &config, None).unwrap().is_none());
        assert!(environment_for(&info, &config, Some("uat")).is_err());
    }

    #[test]
    fn default_category_names_the_account_when_there_are_several() {
        let item = LinkedItemSummary {
            item_id: "1".into(),
            title: "t".into(),
            vault_id: None,
            vault_name: Some("Private".into()),
            location: Some("my.1password.com".into()),
            category: None,
        };
        assert_eq!(default_category("1Password", &item, false), "1Password · Private");
        assert_eq!(default_category("1Password", &item, true), "1Password · Private (personal)");
    }
}
