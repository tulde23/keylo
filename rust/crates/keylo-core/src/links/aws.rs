//! AWS Secrets Manager through the AWS CLI (`aws secretsmanager ...`), with its usual credentials
//! (profiles in ~/.aws, SSO, environment variables). Keylo keeps no AWS credentials.
//!
//! Linking: a secret points at a secret by ARN, with the profile and region it was found with; the
//! value is read each time it's used, so rotated secrets are always current. A JSON object becomes
//! one field per key ("prod-db:password"), anything else a single "value" field.
//!
//! Pushing: copies Keylo secrets to "{prefix}{name}" ("keylo/" by default) as JSON for typed
//! secrets and text otherwise, tagged keylo:managed so later pushes update them. Secrets Keylo
//! didn't create are never overwritten. Values reach the CLI in a temporary file (it has no stdin
//! option for them), which is zeroed and deleted straight after.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use serde::Serialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::process::{Output, Runner};
use super::*;
use crate::types::{self, SecretTypeCatalog};

pub const DEFAULT_PREFIX: &str = "keylo/";
const MANAGED_TAG: &str = "keylo:managed";
const NAME_TAG: &str = "keylo:name";
const CATEGORY_TAG: &str = "keylo:category";
const NOT_INSTALLED: &str = "The AWS CLI (aws) isn't installed. Install it with: winget install Amazon.AWSCLI";

/// A secret in Secrets Manager, without its value.
#[derive(Debug, Clone, Serialize)]
pub struct AwsSecretSummary {
    pub arn: String,
    pub name: String,
    pub description: Option<String>,
    pub tags: BTreeMap<String, String>,
}

/// A secret's value: text (SecretString) or bytes (SecretBinary).
pub(crate) enum AwsValue {
    Text(Zeroizing<String>),
    Binary(Zeroizing<Vec<u8>>),
}

pub struct Aws {
    runner: Arc<dyn Runner>,
}

/// The profile and region a call uses (either may be None: the CLI's defaults).
#[derive(Debug, Clone, Default)]
struct Scope {
    profile: Option<String>,
    region: Option<String>,
}

impl Aws {
    pub fn new(runner: Arc<dyn Runner>) -> Self {
        Aws { runner }
    }

    /// Runs `aws secretsmanager <command> ...` and returns its JSON output.
    fn call(&self, scope: &Scope, command: &str, args: &[String]) -> Result<Value> {
        let region = region_for(scope)?;
        let mut all = vec!["secretsmanager".to_string(), command.to_string()];
        all.extend(args.iter().cloned());
        all.extend(["--output".into(), "json".into(), "--region".into(), region]);
        if let Some(p) = &scope.profile {
            all.extend(["--profile".into(), p.clone()]);
        }
        let out = self.runner.run("aws", &all, None)?;
        if !out.ok() {
            return Err(explain(&out, scope.profile.as_deref()));
        }
        if out.stdout.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&out.stdout).map_err(|e| Error::msg(format!("AWS returned something unexpected: {e}")))
    }

    /// Secrets (names, descriptions and tags; never values) in a profile and region, and the region used.
    pub fn list_secrets(&self, profile: Option<&str>, region: Option<&str>, query: Option<&str>) -> Result<(String, Vec<AwsSecretSummary>)> {
        let scope = Scope { profile: profile.map(str::to_string), region: region.map(str::to_string) };
        let used = region_for(&scope)?;
        let mut secrets: Vec<AwsSecretSummary> = self.list(&scope, None)?.into_iter().filter(|s| matches(s, query)).collect();
        secrets.sort_by_key(|s| s.name.to_lowercase());
        Ok((used, secrets))
    }

    fn list(&self, scope: &Scope, limit: Option<usize>) -> Result<Vec<AwsSecretSummary>> {
        let max = limit.unwrap_or(5000).to_string();
        let v = self.call(scope, "list-secrets", &["--max-items".into(), max])?;
        Ok(v["SecretList"].as_array().into_iter().flatten().map(summary).collect())
    }

    fn describe_secret(&self, scope: &Scope, id: &str) -> Result<Option<AwsSecretSummary>> {
        match self.call(scope, "describe-secret", &["--secret-id".into(), id.into()]) {
            Ok(v) => Ok(Some(summary(&v))),
            Err(e) if e.to_string().contains("ResourceNotFoundException") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_value(&self, scope: &Scope, id: &str) -> Result<AwsValue> {
        let v = self.call(scope, "get-secret-value", &["--secret-id".into(), id.into()])?;
        if let Some(s) = v["SecretString"].as_str() {
            return Ok(AwsValue::Text(Zeroizing::new(s.to_string())));
        }
        let b64 = v["SecretBinary"].as_str().unwrap_or("");
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
        Ok(AwsValue::Binary(Zeroizing::new(bytes)))
    }

    fn value_args(value: &AwsValue, file: &TempValue) -> Vec<String> {
        match value {
            AwsValue::Text(_) => vec!["--secret-string".into(), format!("file://{}", file.path.display())],
            AwsValue::Binary(_) => vec!["--secret-binary".into(), format!("fileb://{}", file.path.display())],
        }
    }

    fn scope_for_target(&self, target: &LinkTarget, settings: &Settings) -> Result<(Scope, String)> {
        if target.location.as_deref() == Some(PER_ENVIRONMENT) {
            // Per environment: the item is the secret's name; the environment (else the default) picks the account.
            let mut scoped = settings.clone();
            if setting(&scoped, ENVIRONMENT_SETTING).is_none() {
                let d = environments::default(settings).ok_or_else(|| {
                    Error::msg("This secret is linked per environment; choose one (name@env), or set a default environment.")
                })?;
                scoped.insert(ENVIRONMENT_SETTING.into(), d);
            }
            let id = setting(settings, SECRET_ID_SETTING).unwrap_or(&target.item_id).to_string();
            Ok((scope_for(&scoped)?, id))
        } else {
            // An ordinary link uses the profile and region it was made with, whatever the settings say now.
            let scope = Scope {
                profile: target.vault_id.clone().filter(|v| !v.is_empty()),
                region: target.location.clone().filter(|v| !v.is_empty()),
            };
            Ok((scope, target.item_id.clone()))
        }
    }
}

/// The profile and region to use: the environment's when settings name one (searching for a
/// per-environment link, or reading one), else the configured profile and region.
fn scope_for(settings: &Settings) -> Result<Scope> {
    let Some(name) = setting(settings, ENVIRONMENT_SETTING) else {
        return Ok(Scope {
            profile: setting(settings, "profile").map(str::to_string),
            region: setting(settings, "region").map(str::to_string),
        });
    };
    let env = environments::find(settings, name)
        .ok_or_else(|| Error::msg(format!("There's no AWS environment '{name}'. Add it in Settings → Vault providers.")))?;
    Ok(Scope { profile: env.profile, region: env.region })
}

/// The region a call goes to, as the CLI would choose it: the given one, else AWS_REGION /
/// AWS_DEFAULT_REGION, else the profile's. Keylo passes it explicitly so it can say where it looked.
fn region_for(scope: &Scope) -> Result<String> {
    if let Some(r) = &scope.region {
        return Ok(r.clone());
    }
    if let Some(r) = environment_region() {
        return Ok(r);
    }
    let name = scope.profile.clone().or_else(|| std::env::var("AWS_PROFILE").ok()).unwrap_or_else(|| "default".into());
    let all = profiles();
    match all.iter().find(|p| p.name == name) {
        Some(p) if p.region.is_some() => return Ok(p.region.clone().unwrap()),
        None if scope.profile.is_some() => {
            bail!("AWS: there's no profile named '{name}' in ~/.aws/config or ~/.aws/credentials.")
        }
        _ => {}
    }
    bail!("AWS: no region chosen. Pick one, or set it in Settings → Vault providers (keylo provider set aws region us-east-1).")
}

fn summary(s: &Value) -> AwsSecretSummary {
    AwsSecretSummary {
        arn: s["ARN"].as_str().unwrap_or("").into(),
        name: s["Name"].as_str().unwrap_or("").into(),
        description: s["Description"].as_str().map(str::to_string),
        tags: s["Tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| Some((t["Key"].as_str()?.to_string(), t["Value"].as_str().unwrap_or("").to_string())))
            .collect(),
    }
}

fn matches(s: &AwsSecretSummary, query: Option<&str>) -> bool {
    let mut texts = vec![s.name.as_str(), s.description.as_deref().unwrap_or("")];
    texts.extend(s.tags.values().map(String::as_str));
    matches_words(query, &texts)
}

/// An AWS CLI failure as a message, with the fix for the usual causes (no credentials, an expired
/// SSO session).
fn explain(out: &Output, profile: Option<&str>) -> Error {
    if out.code.is_none() {
        return Error::msg(NOT_INSTALLED);
    }
    let text = out.stderr.trim();
    let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("the aws command failed");
    let login = match profile {
        Some(p) => format!("aws sso login --profile {p}"),
        None => "aws sso login".into(),
    };
    // "An error occurred (Code) when calling the X operation: message"
    let code = line.find("error occurred (").and_then(|i| {
        let rest = &line[i + "error occurred (".len()..];
        rest.find(')').map(|j| &rest[..j])
    });
    let message = line.split_once("operation: ").map(|(_, m)| m).unwrap_or(line);
    match code {
        Some("AccessDeniedException") => Error::msg(format!("AWS denied access: {message}")),
        Some("ResourceNotFoundException") => Error::msg(format!("AWS: {message} (ResourceNotFoundException)")),
        Some("UnrecognizedClientException" | "InvalidClientTokenId" | "ExpiredTokenException" | "InvalidSignatureException") => {
            Error::msg(format!("AWS: {message} Check your credentials, or sign in again (for SSO: {login})."))
        }
        Some(_) => Error::msg(format!("AWS: {message}")),
        None => {
            let lower = text.to_lowercase();
            if lower.contains("could not be found") && lower.contains("profile") {
                Error::msg(format!(
                    "AWS: there's no profile named '{}' in ~/.aws/config or ~/.aws/credentials.",
                    profile.unwrap_or("default")
                ))
            } else if lower.contains("specify a region") {
                Error::msg("AWS: no region chosen. Pick one, or set it in Settings → Vault providers (keylo provider set aws region us-east-1).")
            } else if lower.contains("credential") || lower.contains("token") || lower.contains("sso") {
                Error::msg(format!("AWS: {line} Sign in (for SSO: {login}) or choose a profile in Settings → Vault providers."))
            } else {
                Error::msg(format!("AWS: {line}"))
            }
        }
    }
}

/// A value's fields with stable ids: each key of a JSON object (nested values as JSON), else one
/// "value" field (bytes as base64).
pub(crate) fn fields(value: &AwsValue) -> Vec<(LinkedField, Zeroizing<String>)> {
    let text = match value {
        AwsValue::Binary(b) => {
            return vec![(
                LinkedField::new("value", "Value (base64)", true),
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(b.as_slice())),
            )]
        }
        AwsValue::Text(t) => t,
    };
    let object = text
        .trim_start()
        .starts_with('{')
        .then(|| serde_json::from_str::<Map<String, Value>>(text).ok())
        .flatten();
    let Some(object) = object else {
        return vec![(LinkedField::new("value", "Value", true), text.clone())];
    };
    let mut ids = UniqueIds::default();
    object
        .iter()
        .map(|(key, v)| {
            let id = ids.take(&FieldDefinition::id_for(key));
            let text = match v {
                Value::Null => String::new(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let secret = !looks_public(&id);
            (LinkedField { id, label: key.clone(), secret }, Zeroizing::new(text))
        })
        .collect()
}

/// Typed secrets as a JSON object of their fields; a plain secret with a username as
/// {"username","password"} (the shape RDS uses); otherwise its text, or its bytes.
pub(crate) fn value_for(secret: &Secret) -> Result<AwsValue> {
    let info = &secret.info;
    if let Some(t) = SecretTypeCatalog::default().find(info.type_id.as_deref())? {
        let fields = types::read_fields(&t, info, &secret.value, false);
        let object: Map<String, Value> = fields.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
        return Ok(AwsValue::Text(Zeroizing::new(Value::Object(object).to_string())));
    }
    let Some(text) = types::decode_text(&secret.value) else {
        return Ok(AwsValue::Binary(Zeroizing::new(secret.value.to_vec())));
    };
    Ok(AwsValue::Text(Zeroizing::new(match &info.username {
        None => text,
        Some(u) => json!({"username": u, "password": text}).to_string(),
    })))
}

/// "{prefix}{name}", with characters Secrets Manager doesn't allow in names replaced by '-'.
pub fn aws_name(secret_name: &str, settings: &Settings) -> String {
    let prefix = setting(settings, "prefix").unwrap_or(DEFAULT_PREFIX);
    format!("{prefix}{secret_name}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "/_+=.@-".contains(c) { c } else { '-' })
        .collect()
}

/// Tag values allow letters, digits, spaces and _ . : / = + - @ (max 256).
fn tag_value(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_alphanumeric() || " _.:/=+-@".contains(c) { c } else { '-' })
        .take(256)
        .collect()
}

/// A value in a temporary file for `file://` arguments; zeroed and deleted when dropped.
struct TempValue {
    path: PathBuf,
    len: usize,
}

impl TempValue {
    fn new(value: &AwsValue) -> Result<Self> {
        let bytes: &[u8] = match value {
            AwsValue::Text(t) => t.as_bytes(),
            AwsValue::Binary(b) => b,
        };
        let path = std::env::temp_dir().join(format!("keylo-{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        Ok(TempValue { path, len: bytes.len() })
    }
}

impl Drop for TempValue {
    fn drop(&mut self) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
            let _ = f.write_all(&vec![0u8; self.len]);
            let _ = f.sync_all();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl VaultProvider for Aws {
    fn id(&self) -> &'static str {
        "aws"
    }

    fn display_name(&self) -> &'static str {
        "AWS Secrets Manager"
    }

    fn setting_descriptions(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("profile", "AWS profile from ~/.aws (optional; the default credentials otherwise)"),
            ("region", "Region, e.g. us-east-1 (optional; the profile's region otherwise)"),
            ("prefix", "Name prefix for pushed secrets (optional; keylo/ otherwise)"),
            ("kms_key_id", "KMS key for pushed secrets (optional; the account's default key otherwise)"),
        ]
    }

    fn has_environments(&self) -> bool {
        true
    }

    fn setting_options(&self, key: &str) -> Option<Vec<String>> {
        match key {
            "profile" => Some(profiles().into_iter().map(|p| p.name).collect()),
            "region" => Some(REGIONS.iter().map(|r| r.to_string()).collect()),
            _ => None,
        }
    }

    fn search(&self, query: Option<&str>, settings: &Settings) -> Result<Vec<LinkedItemSummary>> {
        let scope = scope_for(settings)?;
        let region = region_for(&scope)?;
        let mut found: Vec<LinkedItemSummary> = self
            .list(&scope, None)?
            .into_iter()
            .filter(|s| matches(s, query))
            .map(|s| LinkedItemSummary {
                item_id: s.arn,
                title: s.name,
                vault_id: scope.profile.clone(),
                vault_name: scope.profile.clone(),
                location: Some(region.clone()),
                category: None,
            })
            .collect();
        found.sort_by_key(|s| s.title.to_lowercase());
        Ok(found)
    }

    fn describe(&self, target: &LinkTarget, settings: &Settings) -> Result<Vec<LinkedField>> {
        let (scope, id) = self.scope_for_target(target, settings)?;
        Ok(fields(&self.get_value(&scope, &id)?).into_iter().map(|(f, _)| f).collect())
    }

    fn resolve(&self, target: &LinkTarget, settings: &Settings) -> Result<BTreeMap<String, String>> {
        let (scope, id) = self.scope_for_target(target, settings)?;
        Ok(fields(&self.get_value(&scope, &id)?)
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(f, v)| (f.id, v.to_string()))
            .collect())
    }

    /// Pushing is offered once a profile or region is chosen, so AWS isn't offered to everyone.
    fn push_configured(&self, settings: &Settings) -> bool {
        setting(settings, "profile").is_some() || setting(settings, "region").is_some()
    }

    fn status(&self, settings: &Settings) -> ProviderStatus {
        let scope = Scope { profile: setting(settings, "profile").map(str::to_string), region: setting(settings, "region").map(str::to_string) };
        let result = region_for(&scope).and_then(|r| self.list(&scope, Some(1)).map(|_| r));
        match result {
            Ok(region) => ProviderStatus {
                ready: true,
                message: format!("Ready ({region}, {})", scope.profile.as_deref().unwrap_or("default credentials")),
            },
            Err(e) => ProviderStatus { ready: false, message: e.to_string() },
        }
    }

    fn preview(&self, secret_name: &str, settings: &Settings) -> PushPreview {
        let scope = Scope { profile: setting(settings, "profile").map(str::to_string), region: setting(settings, "region").map(str::to_string) };
        let name = aws_name(secret_name, settings);
        let who = scope.profile.clone().unwrap_or_else(|| "default credentials".into());
        match region_for(&scope).and_then(|r| self.describe_secret(&scope, &name).map(|e| (r, e))) {
            Ok((region, existing)) => {
                PushPreview { target: format!("AWS Secrets Manager as “{name}” ({region} · {who})"), exists: Some(existing.is_some()) }
            }
            Err(_) => PushPreview { target: format!("AWS Secrets Manager as “{name}” ({who})"), exists: None },
        }
    }

    fn push(&self, secret: &Secret, settings: &Settings) -> PushResult {
        let info = &secret.info;
        let result = (|| -> Result<String> {
            let scope = Scope { profile: setting(settings, "profile").map(str::to_string), region: setting(settings, "region").map(str::to_string) };
            let region = region_for(&scope)?;
            let name = aws_name(&info.name, settings);
            let value = value_for(secret)?;
            let file = TempValue::new(&value)?;
            if let Some(existing) = self.describe_secret(&scope, &name)? {
                if !existing.tags.contains_key(MANAGED_TAG) {
                    bail!("“{name}” already exists in {region} and wasn't created by Keylo, so it was left alone.");
                }
                let mut args = vec!["--secret-id".to_string(), existing.arn];
                args.extend(Self::value_args(&value, &file));
                self.call(&scope, "put-secret-value", &args)?;
                return Ok(format!("Updated “{name}” in {region}"));
            }
            let mut tags = vec![json!({"Key": MANAGED_TAG, "Value": "true"}), json!({"Key": NAME_TAG, "Value": tag_value(&info.name)})];
            if let Some(c) = &info.category {
                tags.push(json!({"Key": CATEGORY_TAG, "Value": tag_value(c)}));
            }
            let mut args = vec![
                "--name".to_string(),
                name.clone(),
                "--description".into(),
                "Pushed from Keylo".into(),
                "--tags".into(),
                Value::Array(tags).to_string(),
            ];
            if let Some(k) = setting(settings, "kms_key_id") {
                args.extend(["--kms-key-id".into(), k.into()]);
            }
            args.extend(Self::value_args(&value, &file));
            self.call(&scope, "create-secret", &args)?;
            Ok(format!("Created “{name}” in {region}"))
        })();
        match result {
            Ok(message) => PushResult { name: info.name.clone(), succeeded: true, message },
            Err(e) => PushResult { name: info.name.clone(), succeeded: false, message: e.to_string() },
        }
    }
}

// ---------------------------------------------------------------------------- what's set up

/// A profile from ~/.aws/config or ~/.aws/credentials: its name, region and how it signs in (never its keys).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AwsProfile {
    pub name: String,
    pub region: Option<String>,
    pub sign_in: String,
}

fn aws_file(variable: &str, name: &str) -> Option<PathBuf> {
    std::env::var_os(variable).map(PathBuf::from).or_else(|| dirs::home_dir().map(|h| h.join(".aws").join(name)))
}

/// The profiles set up on this computer, read from the files (no CLI needed).
pub fn profiles() -> Vec<AwsProfile> {
    let config = aws_file("AWS_CONFIG_FILE", "config").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    let credentials = aws_file("AWS_SHARED_CREDENTIALS_FILE", "credentials").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    profiles_from(&config, &credentials)
}

pub(crate) fn profiles_from(config: &str, credentials: &str) -> Vec<AwsProfile> {
    let mut all: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (section, keys) in ini(config) {
        let name = if section == "default" {
            Some("default".to_string())
        } else {
            section.strip_prefix("profile ").map(|n| n.trim().to_string())
        };
        if let Some(n) = name {
            all.entry(n).or_default().extend(keys);
        }
    }
    for (section, keys) in ini(credentials) {
        let entry = all.entry(section).or_default();
        for (k, v) in keys {
            entry.entry(k).or_insert(v);
        }
    }
    let mut list: Vec<AwsProfile> = all
        .into_iter()
        .map(|(name, keys)| {
            let has = |k: &str| keys.get(k).is_some_and(|v| !v.is_empty());
            let sign_in = if has("sso_session") || has("sso_start_url") {
                "sso"
            } else if has("role_arn") {
                "assume role"
            } else if has("credential_process") {
                "credential process"
            } else if has("web_identity_token_file") {
                "web identity"
            } else if has("aws_access_key_id") {
                "access keys"
            } else {
                "other"
            };
            AwsProfile { region: keys.get("region").filter(|r| !r.is_empty()).cloned(), name, sign_in: sign_in.into() }
        })
        .collect();
    list.sort_by_key(|p| p.name.to_lowercase());
    list
}

/// Sections of an INI file and their keys (lowercase).
fn ini(text: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            sections.push((line[1..line.len() - 1].trim().to_string(), BTreeMap::new()));
        } else if let (Some((k, v)), Some(last)) = (line.split_once('='), sections.last_mut()) {
            last.1.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    sections
}

/// AWS_REGION or AWS_DEFAULT_REGION, if set.
pub fn environment_region() -> Option<String> {
    ["AWS_REGION", "AWS_DEFAULT_REGION"].iter().find_map(|v| std::env::var(v).ok().filter(|r| !r.is_empty()))
}

/// Whether the aws CLI is on PATH.
pub fn cli_installed() -> bool {
    process::which("aws").is_some()
}

/// Regions with Secrets Manager (any other name is accepted too).
pub const REGIONS: &[&str] = &[
    "af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-south-2",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7", "ca-central-1",
    "ca-west-1", "cn-north-1", "cn-northwest-1", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "il-central-1", "me-central-1", "me-south-1", "mx-central-1", "sa-east-1",
    "us-east-1", "us-east-2", "us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers `aws` calls from a table and records the arguments.
    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        answer: fn(&[String]) -> Output,
    }

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[String], stdin: Option<&str>) -> Result<Output> {
            assert_eq!(program, "aws");
            assert!(stdin.is_none());
            self.calls.lock().unwrap().push(args.to_vec());
            Ok((self.answer)(args))
        }
    }

    fn ok(stdout: &str) -> Output {
        Output { code: Some(0), stdout: stdout.into(), stderr: String::new() }
    }

    fn answer(args: &[String]) -> Output {
        match args[1].as_str() {
            "list-secrets" => ok(r#"{"SecretList":[{"ARN":"arn:1","Name":"orders/db","Tags":[{"Key":"team","Value":"core"}]},{"ARN":"arn:2","Name":"web/key"}]}"#),
            "get-secret-value" if args.contains(&"orders/db-prod".to_string()) => ok(r#"{"SecretString":"{\"username\":\"p\",\"password\":\"prodpw\",\"port\":5432}"}"#),
            "get-secret-value" => ok(r#"{"SecretString":"{\"username\":\"u\",\"password\":\"pw\",\"port\":5432}"}"#),
            "describe-secret" => Output {
                code: Some(254),
                stdout: String::new(),
                stderr: "\nAn error occurred (ResourceNotFoundException) when calling the DescribeSecret operation: Secrets Manager can't find the specified secret.\n".into(),
            },
            _ => ok("{}"),
        }
    }

    fn fake() -> (Arc<Fake>, Aws) {
        let f = Arc::new(Fake { calls: Mutex::new(vec![]), answer });
        (f.clone(), Aws::new(f))
    }

    #[test]
    fn search_and_resolve_with_explicit_region_and_profile() {
        let (calls, aws) = fake();
        let mut s = Settings::new();
        s.insert("profile".into(), "dev".into());
        s.insert("region".into(), "eu-west-1".into());
        let found = aws.search(Some("core"), &s).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].item_id.as_str(), found[0].location.as_deref()), ("arn:1", Some("eu-west-1")));

        let target = LinkTarget { provider: "aws".into(), item_id: "arn:1".into(), vault_id: Some("dev".into()), location: Some("eu-west-1".into()) };
        let values = aws.resolve(&target, &Settings::new()).unwrap();
        assert_eq!(values["password"], "pw");
        assert_eq!(values["port"], "5432");
        let last = calls.calls.lock().unwrap().last().unwrap().clone();
        assert!(last.windows(2).any(|w| w == ["--profile", "dev"]) && last.windows(2).any(|w| w == ["--region", "eu-west-1"]));
    }

    #[test]
    fn per_environment_links_use_the_environment_and_its_name() {
        let (calls, aws) = fake();
        let mut s = Settings::new();
        environments::write(
            &mut s,
            &[VaultEnvironment { name: "prod".into(), profile: Some("prod-p".into()), region: Some("us-east-2".into()), always_ask: true }],
            None,
        )
        .unwrap();
        s.insert(ENVIRONMENT_SETTING.into(), "prod".into());
        s.insert(SECRET_ID_SETTING.into(), "orders/db-prod".into());
        let target = LinkTarget { provider: "aws".into(), item_id: "orders/db".into(), vault_id: None, location: Some(PER_ENVIRONMENT.into()) };
        assert_eq!(aws.resolve(&target, &s).unwrap()["password"], "prodpw");
        let last = calls.calls.lock().unwrap().last().unwrap().clone();
        assert!(last.windows(2).any(|w| w == ["--profile", "prod-p"]) && last.windows(2).any(|w| w == ["--region", "us-east-2"]));
    }

    #[test]
    fn errors_explain_the_fix() {
        let out = Output {
            code: Some(255),
            stdout: String::new(),
            stderr: "\nAn error occurred (ExpiredTokenException) when calling the ListSecrets operation: The security token included in the request is expired\n".into(),
        };
        let e = explain(&out, Some("dev")).to_string();
        assert!(e.contains("aws sso login --profile dev"), "{e}");
        assert!(explain(&Output::default(), None).to_string().contains("isn't installed"));
    }

    #[test]
    fn profiles_say_how_they_sign_in_without_keys() {
        let config = "[default]\nregion = us-east-1\n\n[profile work]\nsso_session = corp\nregion=eu-west-1\n[sso-session corp]\nsso_start_url = https://x\n";
        let credentials = "[default]\naws_access_key_id = AKIA\naws_secret_access_key = s\n[ci]\naws_access_key_id = AKIB\n";
        let p = profiles_from(config, credentials);
        assert_eq!(
            p,
            vec![
                AwsProfile { name: "ci".into(), region: None, sign_in: "access keys".into() },
                AwsProfile { name: "default".into(), region: Some("us-east-1".into()), sign_in: "access keys".into() },
                AwsProfile { name: "work".into(), region: Some("eu-west-1".into()), sign_in: "sso".into() },
            ]
        );
    }

    #[test]
    fn non_json_values_are_one_field() {
        let f = fields(&AwsValue::Text(Zeroizing::new("plain".into())));
        assert_eq!((f[0].0.id.as_str(), f[0].1.as_str()), ("value", "plain"));
        assert_eq!(aws_name("my key", &Settings::new()), "keylo/my-key");
    }
}
