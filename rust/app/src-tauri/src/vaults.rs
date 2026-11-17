//! Linked vaults for the app: linking secrets to 1Password and AWS Secrets Manager items, the
//! providers' settings and environments, and pushing secrets into them. The vault CLIs can take a
//! while (or wait for the user to unlock 1Password), so their calls run on a blocking thread.

use std::collections::{BTreeMap, HashSet};

use keylo_core::config::KeyloConfig;
use keylo_core::links::{self, aws, environments, LinkTarget, LinkedField, LinkedItemSummary, ProviderStatus, PushPreview, PushResult, Settings, VaultEnvironment};
use keylo_core::secrets::SecretInfo;
use keylo_core::store::SecretStore;
use keylo_core::{eq_ic, Error};
use serde::{Deserialize, Serialize};
use tauri::{State, WebviewWindow};

use crate::commands::{ensure, err, require_unlocked, Res};
use crate::AppState;

/// Runs vault CLI work off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Res<T> + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?
}

fn provider(id: &str) -> Res<Box<dyn links::VaultProvider>> {
    links::find(id).ok_or_else(|| format!("No vault '{id}'."))
}

fn config() -> Res<KeyloConfig> {
    KeyloConfig::load().map_err(err)
}

// ---------------------------------------------------------------------------- what a link shows

/// A linked secret's link, for the detail view (no values).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkDto {
    provider: String,
    provider_name: String,
    title: String,
    r#where: Option<String>,
    per_environment: bool,
    fields: Vec<LinkedField>,
    main_field: Option<String>,
    /// For a per-environment link: the provider's environments and which is the default.
    environments: Vec<VaultEnvironment>,
    default_environment: Option<String>,
}

pub fn link_dto(info: &SecretInfo, config: &KeyloConfig) -> Option<LinkDto> {
    let link = links::read(info)?;
    let settings = links::provider_settings(config, &link.target.provider);
    let per_environment = link.is_per_environment();
    Some(LinkDto {
        provider_name: links::provider_name(&link.target.provider),
        provider: link.target.provider.clone(),
        title: link.title.clone(),
        r#where: link.r#where.clone(),
        per_environment,
        fields: link.visible_fields().into_iter().cloned().collect(),
        main_field: link.main_field(),
        environments: if per_environment { environments::read(&settings) } else { vec![] },
        default_environment: if per_environment { environments::default(&settings) } else { None },
    })
}

/// A linked secret's values, read from its vault (in `environment`, for a per-environment link).
pub fn resolve(info: &SecretInfo, environment: Option<&str>) -> Res<BTreeMap<String, String>> {
    links::resolve(info, &config()?, environment).map_err(err)
}

// ---------------------------------------------------------------------------- providers and settings

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingDto {
    key: &'static str,
    description: &'static str,
    value: Option<String>,
    options: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDto {
    id: &'static str,
    name: &'static str,
    has_environments: bool,
    /// Whether pushing is set up (cheap check, no CLI call).
    push_configured: bool,
    settings: Vec<SettingDto>,
    environments: Vec<VaultEnvironment>,
    default_environment: Option<String>,
}

fn provider_dtos(config: &KeyloConfig) -> Vec<ProviderDto> {
    links::providers()
        .iter()
        .map(|p| {
            let s = links::provider_settings(config, p.id());
            ProviderDto {
                id: p.id(),
                name: p.display_name(),
                has_environments: p.has_environments(),
                push_configured: p.push_configured(&s),
                settings: p
                    .setting_descriptions()
                    .into_iter()
                    .map(|(key, description)| SettingDto {
                        key,
                        description,
                        value: links::setting(&s, key).map(str::to_string),
                        options: p.setting_options(key),
                    })
                    .collect(),
                environments: environments::read(&s),
                default_environment: environments::default(&s),
            }
        })
        .collect()
}

#[tauri::command]
pub fn vault_providers(state: State<'_, AppState>) -> Res<Vec<ProviderDto>> {
    require_unlocked(&state)?;
    Ok(provider_dtos(&config()?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInput {
    settings: BTreeMap<String, String>,
    environments: Vec<VaultEnvironment>,
    default_environment: Option<String>,
}

/// Saves a provider's settings (and environments). It asks for the identity check, since "always
/// ask" environments decide what agents can use without approval.
#[tauri::command]
pub async fn save_vault_provider(window: WebviewWindow, state: State<'_, AppState>, id: String, input: ProviderInput) -> Res<Vec<ProviderDto>> {
    let p = provider(&id)?;
    for e in &input.environments {
        if !environments::is_valid_name(&e.name) {
            return Err(format!("'{}' isn't a valid environment name: use letters, digits, '-' and '_'.", e.name));
        }
    }
    let mut seen = HashSet::new();
    if let Some(dup) = input.environments.iter().find(|e| !seen.insert(e.name.to_lowercase())) {
        return Err(format!("There are two environments named '{}'.", dup.name));
    }
    ensure(&window, &state, &format!("Keylo: change {} settings", p.display_name()), true).await?;

    let mut config = config()?;
    let key = config.providers.keys().find(|k| eq_ic(k, p.id())).cloned().unwrap_or_else(|| p.id().to_string());
    let settings: &mut Settings = config.providers.entry(key).or_default();
    for (k, _) in p.setting_descriptions() {
        settings.retain(|existing, _| !eq_ic(existing, k));
        if let Some(v) = input.settings.get(k).map(|v| v.trim()).filter(|v| !v.is_empty()) {
            settings.insert(k.to_string(), v.to_string());
        }
    }
    if p.has_environments() {
        environments::write(settings, &input.environments, input.default_environment.as_deref()).map_err(err)?;
    }
    if settings.is_empty() {
        config.providers.retain(|k, _| !eq_ic(k, p.id()));
    }
    config.save().map_err(err)?;
    Ok(provider_dtos(&config))
}

/// Checks the provider can be used for pushing (calls its CLI).
#[tauri::command]
pub async fn vault_status(state: State<'_, AppState>, id: String) -> Res<ProviderStatus> {
    require_unlocked(&state)?;
    let p = provider(&id)?;
    let settings = links::provider_settings(&config()?, p.id());
    blocking(move || Ok(p.status(&settings))).await
}

// ---------------------------------------------------------------------------- linking

/// Where to search: an AWS environment (links made then are per environment), or a profile and
/// region (None: the default credentials / the profile's region). Ignored for 1Password.
#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LinkScope {
    environment: Option<String>,
    profile: Option<String>,
    region: Option<String>,
}

fn scoped_settings(config: &KeyloConfig, p: &dyn links::VaultProvider, scope: &LinkScope) -> Settings {
    let mut s = links::provider_settings(config, p.id());
    if !p.has_environments() {
        return s;
    }
    if let Some(e) = scope.environment.as_deref().filter(|e| !e.is_empty()) {
        s.insert(links::ENVIRONMENT_SETTING.into(), e.to_string());
        return s;
    }
    s.retain(|k, _| !eq_ic(k, "profile") && !eq_ic(k, "region"));
    if let Some(p) = scope.profile.as_deref().filter(|v| !v.is_empty()) {
        s.insert("profile".into(), p.into());
    }
    if let Some(r) = scope.region.as_deref().filter(|v| !v.is_empty()) {
        s.insert("region".into(), r.into());
    }
    s
}

fn per_environment(scope: &LinkScope) -> Option<&str> {
    scope.environment.as_deref().filter(|e| !e.is_empty())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsChoice {
    label: String,
    profile: Option<String>,
    region: Option<String>,
    environment: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsChoices {
    choices: Vec<AwsChoice>,
    regions: Vec<String>,
    /// The choice to start with: the default environment, else the configured profile, else the default credentials.
    initial: usize,
    initial_region: Option<String>,
    cli_installed: bool,
}

/// The Link panel's AWS pickers: the environments, the default credentials, then every profile in ~/.aws.
#[tauri::command]
pub fn aws_choices(state: State<'_, AppState>) -> Res<AwsChoices> {
    require_unlocked(&state)?;
    let settings = links::provider_settings(&config()?, "aws");
    let mut choices: Vec<AwsChoice> = environments::read(&settings)
        .into_iter()
        .map(|e| AwsChoice {
            label: [Some(format!("{} environment", e.name)), e.profile.clone(), e.region.clone()].into_iter().flatten().collect::<Vec<_>>().join(" · "),
            profile: e.profile,
            region: e.region,
            environment: Some(e.name),
        })
        .collect();
    let default_index = choices.len();
    choices.push(AwsChoice { label: "Default credentials".into(), profile: None, region: aws::environment_region(), environment: None });
    for p in aws::profiles() {
        choices.push(AwsChoice {
            label: [Some(p.name.clone()), Some(p.sign_in.clone()), p.region.clone()].into_iter().flatten().collect::<Vec<_>>().join(" · "),
            profile: Some(p.name),
            region: p.region,
            environment: None,
        });
    }
    let configured_profile = links::setting(&settings, "profile");
    let initial = environments::default(&settings)
        .and_then(|d| choices.iter().position(|c| c.environment.as_deref() == Some(d.as_str())))
        .or_else(|| configured_profile.and_then(|p| choices.iter().position(|c| c.environment.is_none() && c.profile.as_deref() == Some(p))))
        .unwrap_or(default_index);
    let initial_region = match &choices[initial] {
        c if c.environment.is_some() => c.region.clone(),
        c => links::setting(&settings, "region").map(str::to_string).or_else(|| c.region.clone()).or_else(aws::environment_region),
    };
    Ok(AwsChoices {
        choices,
        regions: aws::REGIONS.iter().map(|r| r.to_string()).collect(),
        initial,
        initial_region,
        cli_installed: aws::cli_installed(),
    })
}

#[tauri::command]
pub async fn link_search(state: State<'_, AppState>, provider_id: String, query: String, scope: LinkScope) -> Res<Vec<LinkedItemSummary>> {
    require_unlocked(&state)?;
    let p = provider(&provider_id)?;
    let settings = scoped_settings(&config()?, p.as_ref(), &scope);
    blocking(move || p.search(Some(&query), &settings).map_err(err)).await
}

fn target_for(p: &dyn links::VaultProvider, item: &LinkedItemSummary, scope: &LinkScope) -> LinkTarget {
    match per_environment(scope) {
        Some(_) => LinkTarget { provider: p.id().into(), item_id: item.title.clone(), vault_id: None, location: Some(links::PER_ENVIRONMENT.into()) },
        None => LinkTarget { provider: p.id().into(), item_id: item.item_id.clone(), vault_id: item.vault_id.clone(), location: item.location.clone() },
    }
}

/// An item's fields (no values), and the suggested name and category for linking it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkProposal {
    fields: Vec<LinkedField>,
    name: String,
    category: String,
}

#[tauri::command]
pub async fn link_describe(
    state: State<'_, AppState>,
    provider_id: String,
    item: LinkedItemSummary,
    scope: LinkScope,
    several_locations: bool,
) -> Res<LinkProposal> {
    require_unlocked(&state)?;
    let p = provider(&provider_id)?;
    let settings = scoped_settings(&config()?, p.as_ref(), &scope);
    blocking(move || {
        let fields = p.describe(&target_for(p.as_ref(), &item, &scope), &settings).map_err(err)?;
        let name = suggest_name(&item.title, &HashSet::new());
        let category = default_category(p.as_ref(), &item, &scope, several_locations);
        Ok(LinkProposal { fields, name, category })
    })
    .await
}

fn default_category(p: &dyn links::VaultProvider, item: &LinkedItemSummary, scope: &LinkScope, several_locations: bool) -> String {
    match per_environment(scope) {
        Some(_) => p.display_name().to_string(),
        None => links::default_category(p.display_name(), item, several_locations),
    }
}

/// "GitHub (work)" → "github-work", unique among existing secrets and `taken`.
fn suggest_name(title: &str, taken: &HashSet<String>) -> String {
    let mut name: String = title
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' })
        .collect();
    while name.contains("--") {
        name = name.replace("--", "-");
    }
    let mut name = name.trim_matches('-').chars().take(100).collect::<String>();
    if name.is_empty() {
        name = "linked".into();
    }
    let store = SecretStore::default();
    let mut candidate = name.clone();
    let mut n = 2;
    while taken.contains(&candidate.to_lowercase()) || store.exists(&candidate).unwrap_or(false) {
        candidate = format!("{name}-{n}");
        n += 1;
    }
    candidate
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkInput {
    provider_id: String,
    scope: LinkScope,
    items: Vec<LinkedItemSummary>,
    /// For one item: its name, and optionally just one of its fields.
    name: Option<String>,
    only_field: Option<String>,
    /// None: each item's suggested category.
    category: Option<String>,
    several_locations: bool,
}

#[derive(Serialize)]
pub struct LinkOutcome {
    created: Vec<String>,
    failed: Vec<String>,
}

/// Creates a linked secret for each item (only references are stored, never values).
#[tauri::command]
pub async fn create_links(window: WebviewWindow, state: State<'_, AppState>, input: LinkInput) -> Res<LinkOutcome> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let p = provider(&input.provider_id)?;
    let settings = scoped_settings(&config()?, p.as_ref(), &input.scope);
    blocking(move || {
        let store = SecretStore::default();
        let single = input.items.len() == 1;
        let mut taken = HashSet::new();
        let (mut created, mut failed) = (vec![], vec![]);
        for item in &input.items {
            let result = (|| -> Result<String, Error> {
                let name = match (&input.name, single) {
                    (Some(n), true) => keylo_core::store::normalize_name(n)?,
                    _ => suggest_name(&item.title, &taken),
                };
                if store.exists(&name)? {
                    return Err(Error::Exists(name));
                }
                let target = target_for(p.as_ref(), item, &input.scope);
                let fields = p.describe(&target, &settings)?;
                if fields.is_empty() {
                    return Err(Error::msg("This item has no fields."));
                }
                let only = if single { input.only_field.clone().filter(|o| fields.iter().any(|f| &f.id == o)) } else { None };
                let r#where = match per_environment(&input.scope) {
                    Some(_) => "per environment".to_string(),
                    None => [item.vault_name.as_deref(), item.location.as_deref()].into_iter().flatten().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · "),
                };
                let link = links::Link {
                    target,
                    title: item.title.clone(),
                    r#where: Some(r#where).filter(|w| !w.is_empty()),
                    fields,
                    only_field: only,
                    environment_names: BTreeMap::new(),
                };
                let category = input
                    .category
                    .clone()
                    .filter(|c| !c.trim().is_empty())
                    .unwrap_or_else(|| default_category(p.as_ref(), item, &input.scope, input.several_locations));
                store.save(&links::draft(&name, &link, Some(category.trim()).filter(|c| !c.is_empty()), None, None, None), None)?;
                Ok(name)
            })();
            match result {
                Ok(name) => {
                    taken.insert(name.to_lowercase());
                    created.push(name);
                }
                Err(e) => failed.push(format!("{}: {e}", item.title)),
            }
        }
        Ok(LinkOutcome { created, failed })
    })
    .await
}

// ---------------------------------------------------------------------------- pushing

/// Where a push of `name` would go, before anything is read or sent.
#[tauri::command]
pub async fn push_preview(state: State<'_, AppState>, provider_id: String, name: String) -> Res<PushPreview> {
    require_unlocked(&state)?;
    let p = provider(&provider_id)?;
    let settings = links::provider_settings(&config()?, p.id());
    blocking(move || Ok(p.preview(&name, &settings))).await
}

/// Copies a secret into the vault (creating it, or updating the item Keylo pushed before).
#[tauri::command]
pub async fn push_secret(window: WebviewWindow, state: State<'_, AppState>, provider_id: String, name: String) -> Res<PushResult> {
    let p = provider(&provider_id)?;
    ensure(&window, &state, &format!("Keylo: push '{name}' to {}", p.display_name()), true).await?;
    let secret = SecretStore::default().get(&name).map_err(err)?;
    if links::is_linked(&secret.info) {
        return Err("A linked secret already lives in a vault; push the original instead.".into());
    }
    let settings = links::provider_settings(&config()?, p.id());
    blocking(move || Ok(p.push(&secret, &settings))).await
}
