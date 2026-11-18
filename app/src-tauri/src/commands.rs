//! The commands the React front end calls. Values only cross into the web view when the user
//! reveals them (after the identity check); copying happens here, on the secure clipboard.

use std::collections::BTreeMap;

use keylo_core::access::{self, KeyScope};
use keylo_core::activity::{Activity, RecentUse};
use keylo_core::approval;
use keylo_core::categories::{CategoryCatalog, CategorySummary};
use keylo_core::claude_code;
use keylo_core::config::{HelloMode, KeyloConfig};
use keylo_core::gate::AccessGate;
use keylo_core::links;
use keylo_core::secrets::{SecretDraft, SecretInfo, StorageKind};
use keylo_core::store::SecretStore;
use keylo_core::types::{self, FieldKind, SecretTypeCatalog, SecretTypeDefinition};
use keylo_core::{eq_ic, paths, platform, Error};
use serde::{Deserialize, Serialize};

use tauri::{AppHandle, State, WebviewWindow};
use zeroize::Zeroizing;

use crate::vaults::{self, LinkDto};
use crate::AppState;

pub type Res<T> = Result<T, String>;

const LOCKED: &str = "locked";

pub fn err(e: Error) -> String {
    e.to_string()
}

/// The native window handle, to parent the identity prompt to.
fn owner(window: &WebviewWindow) -> isize {
    #[cfg(windows)]
    {
        window.hwnd().map(|h| h.0 as isize).unwrap_or(0)
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        0
    }
}

/// One identity prompt at a time. Separate from the gate: quick commands (status, touch, lock, the
/// secret list) lock the gate on the UI thread, so it must never be held while a prompt is open, or
/// the window stops responding until the prompt is answered.
static PROMPT: tauri::async_runtime::Mutex<()> = tauri::async_runtime::Mutex::const_new(());

/// Shows the identity prompt on a blocking thread and waits for it without holding anything else.
async fn prompt(window: &WebviewWindow, message: &str) -> Res<()> {
    let hwnd = owner(window);
    let message = message.to_string();
    tauri::async_runtime::spawn_blocking(move || AccessGate::verify(hwnd, &message))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)
}

/// Runs the identity check (or uses the session).
pub async fn ensure(window: &WebviewWindow, state: &State<'_, AppState>, message: &str, value_access: bool) -> Res<()> {
    let _turn = PROMPT.lock().await;
    // Checked after waiting our turn: a prompt that just finished may have unlocked it.
    let needed = state.gate.lock().unwrap().needs_verification(value_access);
    if !needed {
        return Ok(());
    }
    prompt(window, message).await?;
    let result = state.gate.lock().unwrap().mark_verified().map_err(err);
    result
}

/// Always prompts (ignoring any session) unless the check is off.
pub async fn confirm(window: &WebviewWindow, message: &str) -> Res<()> {
    let config = KeyloConfig::load().map_err(err)?;
    if config.hello == HelloMode::Never {
        return Ok(());
    }
    let _turn = PROMPT.lock().await;
    prompt(window, message).await
}

pub fn require_unlocked(state: &State<'_, AppState>) -> Res<()> {
    if state.gate.lock().unwrap().is_unlocked() { Ok(()) } else { Err(LOCKED.into()) }
}

// ---------------------------------------------------------------------------- app and session

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    platform: String,
    verifier_name: String,
    store_name: String,
    file_protection: String,
    version: String,
    data_dir: String,
    keylo_path: String,
}

// ---------------------------------------------------------------------------- appearance

/// The colour theme and light/dark mode, kept in ui.json with the C# app's window layout (same
/// names, so both apps share them): Theme = Twilight | QuietViolet | Aurora, Mode = System | Light | Dark.
#[derive(Serialize)]
pub struct UiTheme {
    theme: String,
    mode: String,
}

const THEMES: &[&str] = &["Twilight", "QuietViolet", "Aurora"];
const MODES: &[&str] = &["System", "Light", "Dark"];

fn ui_json() -> serde_json::Map<String, serde_json::Value> {
    std::fs::read_to_string(paths::data_dir().join("ui.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(t.trim_start_matches('\u{feff}')).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn pick(value: Option<&str>, choices: &[&str]) -> String {
    let v = value.unwrap_or("");
    choices.iter().find(|c| c.eq_ignore_ascii_case(v)).unwrap_or(&choices[0]).to_string()
}

#[tauri::command]
pub async fn ui_theme() -> UiTheme {
    let ui = ui_json();
    UiTheme {
        theme: pick(ui.get("Theme").and_then(|v| v.as_str()), THEMES),
        mode: pick(ui.get("Mode").and_then(|v| v.as_str()), MODES),
    }
}

/// Saves the appearance at once (it's cosmetic: no identity check, not part of Save settings).
#[tauri::command]
pub async fn set_ui_theme(theme: String, mode: String) -> Res<UiTheme> {
    let mut ui = ui_json();
    ui.insert("Theme".into(), pick(Some(&theme), THEMES).into());
    ui.insert("Mode".into(), pick(Some(&mode), MODES).into());
    let dir = paths::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ui.json"), serde_json::to_string(&ui).unwrap()).map_err(|e| e.to_string())?;
    Ok(ui_theme().await)
}

/// The keylo command installed next to the app.
fn keylo_path() -> String {
    std::env::current_exe()
        .ok()
        .as_ref()
        .and_then(|e| e.parent())
        .map(|d| d.join(if cfg!(windows) { "keylo.exe" } else { "keylo" }))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "keylo".into())
}

#[tauri::command]
pub async fn app_info() -> AppInfo {
    let p = platform::current();
    let keylo = keylo_path();
    AppInfo {
        platform: p.name().into(),
        verifier_name: p.verifier_name(),
        store_name: p.store_name(),
        file_protection: p.file_protection_name(),
        version: keylo_core::build_version!(),
        data_dir: paths::data_dir().display().to_string(),
        keylo_path: keylo,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    unlocked: bool,
    mode: HelloMode,
    session_expires: Option<String>,
}

#[tauri::command]
pub async fn status(state: State<'_, AppState>) -> Res<Status> {
    let g = state.gate.lock().unwrap();
    Ok(Status { unlocked: g.is_unlocked(), mode: g.mode(), session_expires: g.session_expires_at().map(|t| t.to_rfc3339()) })
}

#[tauri::command]
pub async fn unlock(window: WebviewWindow, state: State<'_, AppState>) -> Res<()> {
    ensure(&window, &state, "Unlock Keylo", false).await
}

#[tauri::command]
pub async fn lock(state: State<'_, AppState>) -> Res<()> {
    state.gate.lock().unwrap().lock();
    Ok(())
}

/// User activity: slides the session so it lasts while someone is at the keyboard.
#[tauri::command]
pub async fn touch(state: State<'_, AppState>) -> Res<()> {
    let _ = state.gate.lock().unwrap().extend_session();
    Ok(())
}

// ---------------------------------------------------------------------------- secrets

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRow {
    #[serde(flatten)]
    info: SecretInfo,
    pinned: bool,
    linked: bool,
    /// For a linked secret: where it points and its fields (no values).
    link: Option<LinkDto>,
    file_backed: bool,
}

#[tauri::command]
pub async fn secrets(state: State<'_, AppState>) -> Res<Vec<SecretRow>> {
    require_unlocked(&state)?;
    let activity = Activity::default();
    let pins = activity.pins();
    let config = KeyloConfig::load().map_err(err)?;
    Ok(SecretStore::default()
        .list()
        .map_err(err)?
        .into_iter()
        .map(|info| SecretRow {
            pinned: pins.iter().any(|p| eq_ic(p, &info.name)),
            linked: links::is_linked(&info),
            link: vaults::link_dto(&info, &config),
            file_backed: info.storage == StorageKind::EncryptedFile,
            info,
        })
        .collect())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDto {
    id: String,
    label: String,
    kind: FieldKind,
    secret: bool,
    main: bool,
    options: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeDto {
    id: String,
    name: String,
    icon: Option<String>,
    color: Option<String>,
    built_in: bool,
    fields: Vec<FieldDto>,
}

fn type_dto(t: &SecretTypeDefinition) -> TypeDto {
    let primary = t.primary().map(|p| p.id.clone());
    TypeDto {
        id: t.id.clone(),
        name: t.name.clone(),
        icon: t.icon.clone(),
        color: t.color.clone(),
        built_in: t.is_built_in,
        fields: t
            .fields
            .iter()
            .map(|f| FieldDto {
                id: f.id.clone(),
                label: f.label.clone(),
                kind: f.kind,
                secret: f.is_secret(),
                main: Some(&f.id) == primary.as_ref(),
                options: f.options.clone(),
            })
            .collect(),
    }
}

#[tauri::command]
pub async fn secret_types() -> Res<Vec<TypeDto>> {
    Ok(SecretTypeCatalog::default().all().map_err(err)?.iter().map(type_dto).collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldInput {
    /// Empty for a new field (derived from the label); fixed once saved, since secrets store data under it.
    id: String,
    label: String,
    kind: FieldKind,
    options: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeInput {
    name: String,
    icon: Option<String>,
    color: Option<String>,
    fields: Vec<FieldInput>,
}

/// Adds a custom type (`id` None) or changes one. For a built-in type only the icon and colour change.
#[tauri::command]
pub async fn save_type(state: State<'_, AppState>, id: Option<String>, input: TypeInput) -> Res<Vec<TypeDto>> {
    require_unlocked(&state)?;
    let catalog = SecretTypeCatalog::default();
    let icon = keylo_core::store::normalize_icon(input.icon.as_deref()).map_err(err)?;
    let color = keylo_core::store::normalize_color(input.color.as_deref()).map_err(err)?;

    if let Some(built_in) = id.as_deref().and_then(|id| types::built_in().into_iter().find(|t| t.id == id)) {
        let mut styles: BTreeMap<String, types::Style> = catalog
            .built_in_styled()
            .map_err(err)?
            .into_iter()
            .map(|t| (t.id.clone(), types::Style { icon: t.icon, color: t.color }))
            .collect();
        styles.insert(built_in.id.clone(), types::Style { icon: icon.or(built_in.icon), color });
        catalog.save_built_in_styles(&styles).map_err(err)?;
        return secret_types().await;
    }

    let fields = input
        .fields
        .into_iter()
        .map(|f| types::FieldDefinition {
            id: f.id,
            label: f.label,
            kind: f.kind,
            options: f.options.map(|o| o.into_iter().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        })
        .collect();
    let edited = SecretTypeDefinition { id: id.clone().unwrap_or_default(), name: input.name, icon, color, fields, is_built_in: false };
    let mut custom = catalog.custom().map_err(err)?;
    match id.as_deref().and_then(|id| custom.iter().position(|t| t.id == id)) {
        Some(i) => custom[i] = edited,
        None if id.is_some() => return Err("That type no longer exists.".into()),
        None => custom.push(edited),
    }
    catalog.save_custom(custom).map_err(err)?;
    secret_types().await
}

#[tauri::command]
pub async fn delete_type(state: State<'_, AppState>, id: String) -> Res<Vec<TypeDto>> {
    require_unlocked(&state)?;
    let catalog = SecretTypeCatalog::default();
    let mut custom = catalog.custom().map_err(err)?;
    let Some(i) = custom.iter().position(|t| t.id == id) else { return Err("Built-in types can't be deleted.".into()) };
    let used = SecretStore::default().list().map_err(err)?.iter().filter(|s| s.type_id.as_deref().is_some_and(|t| eq_ic(t, &id))).count();
    if used > 0 {
        let name = &custom[i].name;
        return Err(format!("{used} secret{} use{} '{name}'. Change their type first.", if used == 1 { "" } else { "s" }, if used == 1 { "s" } else { "" }));
    }
    custom.remove(i);
    catalog.save_custom(custom).map_err(err)?;
    secret_types().await
}

/// Every field's value (typed) or the value (plain). Needs the identity check.
#[tauri::command]
/// `for_edit`: only stored fields (no derived connection string), to save back. A linked secret's
/// values are read from its vault (`environment` picks one of a per-environment link).
pub async fn reveal(
    window: WebviewWindow,
    state: State<'_, AppState>,
    name: String,
    for_edit: bool,
    environment: Option<String>,
) -> Res<BTreeMap<String, String>> {
    ensure(&window, &state, &format!("Keylo: show '{name}'"), true).await?;
    let fields = tauri::async_runtime::spawn_blocking({
        let name = name.clone();
        move || read_fields(&name, !for_edit, environment.as_deref())
    })
    .await
    .map_err(|e| e.to_string())??;
    let _ = Activity::default().record_use(&name, "viewed");
    Ok(fields)
}

fn read_fields(name: &str, derive: bool, environment: Option<&str>) -> Res<BTreeMap<String, String>> {
    let store = SecretStore::default();
    let info = store.find(name).map_err(err)?.ok_or_else(|| err(Error::NotFound(name.to_string())))?;
    if links::is_linked(&info) {
        return vaults::resolve(&info, environment);
    }
    let secret = store.get(name).map_err(err)?;
    let mut out = BTreeMap::new();
    match SecretTypeCatalog::default().find(secret.info.type_id.as_deref()).map_err(err)? {
        Some(t) => out = types::read_fields(&t, &secret.info, &secret.value, derive),
        None => {
            if let Some(u) = &secret.info.username {
                out.insert("username".into(), u.clone());
            }
            match types::decode_text(&secret.value) {
                Some(v) => out.insert("value".into(), v),
                None => return Err(format!("'{name}' is binary; it can't be shown as text.")),
            };
        }
    }
    Ok(out)
}

/// Copies one field (default: the main value) to the secure clipboard; it clears itself later.
#[tauri::command]
pub async fn copy_field(
    window: WebviewWindow,
    state: State<'_, AppState>,
    name: String,
    field: Option<String>,
    environment: Option<String>,
) -> Res<i64> {
    let info = SecretStore::default().find(&name).map_err(err)?.ok_or_else(|| err(Error::NotFound(name.clone())))?;
    let link = links::read(&info);
    let t = match &link {
        Some(_) => None,
        None => SecretTypeCatalog::default().find(info.type_id.as_deref()).map_err(err)?,
    };
    let field = field.unwrap_or_else(|| match &link {
        Some(l) => l.main_field().unwrap_or_else(|| "value".into()),
        None => t.as_ref().and_then(|t| t.primary()).map(|p| p.id.clone()).unwrap_or_else(|| "value".into()),
    });
    // Non-secret fields (host, url, username) copy without the identity check.
    let is_secret = match (&link, &t) {
        (Some(l), _) => l.fields.iter().find(|f| f.id == field).is_none_or(|f| f.secret),
        (None, Some(t)) => t.field(&field).is_some_and(|f| f.is_secret()),
        (None, None) => field != "username",
    };
    if is_secret {
        ensure(&window, &state, &format!("Keylo: copy '{name}'"), true).await?;
    } else {
        require_unlocked(&state)?;
    }
    let fields = tauri::async_runtime::spawn_blocking({
        let name = name.clone();
        move || read_fields(&name, true, environment.as_deref())
    })
    .await
    .map_err(|e| e.to_string())??;
    let Some(text) = fields.get(&field).map(|v| Zeroizing::new(v.clone())) else {
        return Err(format!("'{name}' has no {field}."));
    };
    let token = platform::current().clipboard().set_text(&text).map_err(err)?;
    let seconds = KeyloConfig::load().map(|c| c.clipboard_seconds).unwrap_or(30);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(seconds as u64));
        platform::current().clipboard().clear_if_unchanged(token);
    });
    if is_secret {
        let _ = Activity::default().record_use(&name, "copied");
    }
    Ok(seconds)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveInput {
    /// The secret being edited (None: a new one).
    original_name: Option<String>,
    name: String,
    type_id: Option<String>,
    /// Typed: every field by id. Plain: "value" (absent keeps the stored value) and "username".
    fields: BTreeMap<String, String>,
    category: Option<String>,
    notes: Option<String>,
    icon: Option<String>,
    color: Option<String>,
}

#[tauri::command]
pub async fn save_secret(window: WebviewWindow, state: State<'_, AppState>, input: SaveInput) -> Res<SecretInfo> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let store = SecretStore::default();
    let catalog = SecretTypeCatalog::default();
    let non_empty = |v: &Option<String>| v.clone().filter(|s| !s.trim().is_empty());

    // A linked secret: only its name and details change; the link stays as it is.
    let original_link = match &input.original_name {
        Some(o) => store.find(o).map_err(err)?.and_then(|i| links::read(&i)),
        None => None,
    };
    let draft = match input.type_id.as_deref().filter(|t| !t.is_empty()) {
        Some(links::TYPE_ID) => {
            let link = original_link.ok_or("Link secrets with Link, not Add.")?;
            links::draft(
                &input.name,
                &link,
                non_empty(&input.category).as_deref(),
                non_empty(&input.notes).as_deref(),
                non_empty(&input.icon).as_deref(),
                non_empty(&input.color).as_deref(),
            )
        }
        Some(type_id) => {
            let t = catalog.find(Some(type_id)).map_err(err)?.ok_or_else(|| format!("No type '{type_id}'."))?;
            let fields: BTreeMap<String, String> = input.fields.into_iter().filter(|(_, v)| !v.is_empty()).collect();
            types::typed_draft(&t, &input.name, &fields, non_empty(&input.category), non_empty(&input.notes), non_empty(&input.icon), non_empty(&input.color))
                .map_err(err)?
        }
        None => {
            let value = match input.fields.get("value") {
                Some(v) => Zeroizing::new(v.as_bytes().to_vec()),
                None => match &input.original_name {
                    Some(original) => store.get(original).map_err(err)?.value,
                    None => return Err("A value is required.".into()),
                },
            };
            if value.is_empty() {
                return Err("A value is required.".into());
            }
            SecretDraft {
                name: input.name.clone(),
                value,
                category: non_empty(&input.category),
                username: input.fields.get("username").cloned().filter(|u| !u.trim().is_empty()),
                notes: non_empty(&input.notes),
                icon: non_empty(&input.icon),
                color: non_empty(&input.color),
                ..Default::default()
            }
        }
    };
    let saved = store.save(&draft, input.original_name.as_deref()).map_err(err)?;
    if let Some(original) = &input.original_name {
        let _ = Activity::default().renamed(original, &saved.name);
    }
    Ok(saved)
}

#[tauri::command]
pub async fn delete_secret(window: WebviewWindow, state: State<'_, AppState>, name: String) -> Res<()> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    SecretStore::default().delete(&name).map_err(err)?;
    let _ = Activity::default().removed(&[name]);
    Ok(())
}

#[tauri::command]
pub async fn set_pinned(state: State<'_, AppState>, name: String, pinned: bool) -> Res<()> {
    require_unlocked(&state)?;
    Activity::default().set_pinned(&name, pinned).map_err(err)
}

#[tauri::command]
pub async fn recent(state: State<'_, AppState>) -> Res<Vec<RecentUse>> {
    require_unlocked(&state)?;
    Ok(Activity::default().recent(12))
}

#[tauri::command]
pub async fn generate_password(length: usize, symbols: bool) -> String {
    keylo_core::password::generate(length, symbols)
}

// ---------------------------------------------------------------------------- icon images

const MAX_DOWNLOAD: u64 = 5 * 1024 * 1024;

/// Downloads an image for an icon; returns it as a data: URL for the app to resize. http(s) only,
/// at most 5 MB, an image content type, 15 seconds.
#[tauri::command]
pub async fn fetch_image(url: String) -> Res<String> {
    use base64::Engine;
    let url = url.trim().to_string();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Paste an image address starting with https://.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(15)))
            .user_agent("Keylo")
            .build()
            .into();
        let mut response = agent.get(&url).call().map_err(|e| format!("Couldn't download it: {e}"))?;
        let mime = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if !mime.starts_with("image/") {
            return Err(format!("That address isn't an image ({}).", if mime.is_empty() { "no content type" } else { &mime }));
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_DOWNLOAD)
            .read_to_vec()
            .map_err(|_| "That image is too large (the most is 5 MB).".to_string())?;
        Ok(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(bytes)))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Stores an icon image (a PNG the app made, base64); returns its icon name ("img" + hash).
#[tauri::command]
pub async fn save_icon_image(state: State<'_, AppState>, png: String) -> Res<String> {
    use base64::Engine;
    require_unlocked(&state)?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(png.trim()).map_err(|_| "That image couldn't be read.".to_string())?;
    keylo_core::icons::save_png(&bytes).map_err(err)
}

/// A stored icon image as a data: URL, or None.
#[tauri::command]
pub async fn icon_image(name: String) -> Option<String> {
    use base64::Engine;
    keylo_core::icons::load(&name).map(|png| format!("data:image/png;base64,{}", base64::engine::general_purpose::STANDARD.encode(png)))
}

// ---------------------------------------------------------------------------- categories

#[tauri::command]
pub async fn categories(state: State<'_, AppState>) -> Res<Vec<CategorySummary>> {
    require_unlocked(&state)?;
    Ok(CategoryCatalog::default().all(&SecretStore::default().list().map_err(err)?))
}

#[tauri::command]
pub async fn create_category(state: State<'_, AppState>, name: String, icon: Option<String>, color: Option<String>) -> Res<Vec<CategorySummary>> {
    require_unlocked(&state)?;
    CategoryCatalog::default().create(&name, icon.as_deref(), color.as_deref()).map_err(err)?;
    categories(state).await
}

#[tauri::command]
pub async fn set_category_style(state: State<'_, AppState>, name: String, icon: Option<String>, color: Option<String>) -> Res<Vec<CategorySummary>> {
    require_unlocked(&state)?;
    CategoryCatalog::default().set_style(&name, icon.as_deref(), color.as_deref()).map_err(err)?;
    categories(state).await
}

/// Renames a category on every secret in it; onto an existing name, merges the two.
#[tauri::command]
pub async fn rename_category(window: WebviewWindow, state: State<'_, AppState>, from: String, to: String) -> Res<Vec<CategorySummary>> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    CategoryCatalog::default().rename(&SecretStore::default(), &from, &to).map_err(err)?;
    categories(state).await
}

/// Deletes a category: its secrets move to `move_to` (None: uncategorized) or, with
/// `delete_secrets`, are deleted (which always asks for the identity check).
#[tauri::command]
pub async fn delete_category(
    window: WebviewWindow,
    state: State<'_, AppState>,
    name: String,
    move_to: Option<String>,
    delete_secrets: bool,
) -> Res<Vec<CategorySummary>> {
    if delete_secrets {
        confirm(&window, &format!("Keylo: delete every secret in '{name}'")).await?;
    } else {
        ensure(&window, &state, "Unlock Keylo", false).await?;
    }
    let store = SecretStore::default();
    let doomed: Vec<String> = if delete_secrets {
        store.list().map_err(err)?.into_iter().filter(|s| s.category.as_deref().is_some_and(|c| eq_ic(c, &name))).map(|s| s.name).collect()
    } else {
        vec![]
    };
    CategoryCatalog::default().delete(&store, &name, move_to.as_deref().filter(|m| !m.trim().is_empty()), delete_secrets).map_err(err)?;
    if !doomed.is_empty() {
        let _ = Activity::default().removed(&doomed);
    }
    categories(state).await
}

// ---------------------------------------------------------------------------- settings

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    hello: HelloMode,
    session_minutes: i64,
    clipboard_seconds: i64,
    audit_retention_days: i64,
}

#[tauri::command]
pub async fn settings() -> Res<SettingsDto> {
    let c = KeyloConfig::load().map_err(err)?;
    Ok(SettingsDto {
        hello: c.hello,
        session_minutes: c.session_minutes,
        clipboard_seconds: c.clipboard_seconds,
        audit_retention_days: c.audit_retention_days,
    })
}

/// These settings decide when verification happens, so changing them always verifies.
#[tauri::command]
pub async fn save_settings(window: WebviewWindow, state: State<'_, AppState>, settings: SettingsDto) -> Res<SettingsDto> {
    confirm(&window, "Keylo: change settings").await?;
    let mut c = KeyloConfig::load().map_err(err)?;
    c.hello = settings.hello;
    c.session_minutes = settings.session_minutes;
    c.clipboard_seconds = settings.clipboard_seconds;
    c.audit_retention_days = settings.audit_retention_days;
    c.save().map_err(err)?;
    let mut gate = AccessGate::new(&c);
    // The identity check just passed: keep the app open under the new settings.
    gate.mark_verified().map_err(err)?;
    *state.gate.lock().unwrap() = gate;
    self::settings().await
}

// ---------------------------------------------------------------------------- access keys

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDto {
    id: String,
    name: String,
    scope: KeyScope,
    categories: Vec<String>,
    secrets: Vec<String>,
    created: String,
    expires: Option<String>,
    expired: bool,
}

#[tauri::command]
pub async fn access_keys(state: State<'_, AppState>) -> Res<Vec<KeyDto>> {
    require_unlocked(&state)?;
    let now = chrono::Local::now().fixed_offset();
    Ok(KeyloConfig::load()
        .map_err(err)?
        .access_keys
        .iter()
        .map(|k| KeyDto {
            id: k.id.clone(),
            name: k.name.clone(),
            scope: k.scope,
            categories: k.categories.clone(),
            secrets: k.secrets.clone(),
            created: k.created.to_rfc3339(),
            expires: k.expires.map(|e| e.to_rfc3339()),
            expired: k.is_expired(now),
        })
        .collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInput {
    name: String,
    scope: KeyScope,
    categories: Vec<String>,
    secrets: Vec<String>,
    expires_days: Option<i64>,
}

/// Returns the key's token: shown once, never stored.
#[tauri::command]
pub async fn create_key(window: WebviewWindow, input: KeyInput) -> Res<String> {
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err("Give the key a name, e.g. 'Claude Code'.".into());
    }
    let mut c = KeyloConfig::load().map_err(err)?;
    if c.access_keys.iter().any(|k| eq_ic(&k.name, &name)) {
        return Err(format!("There's already a key called '{name}'."));
    }
    confirm(&window, &format!("Keylo: create access key '{name}'")).await?;
    let (mut key, token) = access::create(&name, input.expires_days.filter(|d| *d > 0));
    key.scope = input.scope;
    key.categories = input.categories;
    key.secrets = input.secrets;
    c.access_keys.push(key);
    c.save().map_err(err)?;
    Ok(token)
}

#[tauri::command]
pub async fn update_key(window: WebviewWindow, id: String, input: KeyInput) -> Res<()> {
    let mut c = KeyloConfig::load().map_err(err)?;
    let Some(key) = c.access_keys.iter_mut().find(|k| k.id == id) else { return Err("That key no longer exists.".into()) };
    let name = key.name.clone();
    confirm(&window, &format!("Keylo: change what '{name}' can use")).await?;
    key.scope = input.scope;
    key.categories = input.categories;
    key.secrets = input.secrets;
    c.save().map_err(err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeStatus {
    #[serde(flatten)]
    registration: claude_code::Registration,
    summary: String,
    cli_installed: bool,
}

/// Whether Claude Code has Keylo's MCP server, and with which access key (never the key itself).
#[tauri::command]
pub async fn claude_status(state: State<'_, AppState>) -> Res<ClaudeStatus> {
    require_unlocked(&state)?;
    let registration = claude_code::inspect(&KeyloConfig::load().map_err(err)?, &keylo_path());
    Ok(ClaudeStatus { summary: registration.describe(), registration, cli_installed: claude_code::find_cli().is_some() })
}

/// Registers Keylo's MCP server with Claude Code (user scope) using a key just created.
#[tauri::command]
pub async fn add_to_claude(state: State<'_, AppState>, token: String) -> Res<()> {
    require_unlocked(&state)?;
    let token = Zeroizing::new(token);
    tauri::async_runtime::spawn_blocking(move || claude_code::register(&keylo_path(), &token).map_err(err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn revoke_key(window: WebviewWindow, id: String) -> Res<()> {
    let mut c = KeyloConfig::load().map_err(err)?;
    let Some(pos) = c.access_keys.iter().position(|k| k.id == id) else { return Ok(()) };
    let name = c.access_keys[pos].name.clone();
    confirm(&window, &format!("Keylo: revoke access key '{name}'")).await?;
    c.access_keys.remove(pos);
    c.save().map_err(err)
}

// ---------------------------------------------------------------------------- audit log

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRow {
    time: String,
    operation: String,
    secrets: Vec<String>,
    key: Option<String>,
    via: String,
    chain: Vec<String>,
}

#[tauri::command]
pub async fn audit_log(state: State<'_, AppState>, limit: usize) -> Res<Vec<AuditRow>> {
    require_unlocked(&state)?;
    let text = std::fs::read_to_string(access::audit_path_in(&paths::data_dir())).unwrap_or_default();
    let strs = |v: &serde_json::Value| -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect()).unwrap_or_default()
    };
    Ok(text
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .take(limit.clamp(1, 2000))
        .map(|v| AuditRow {
            time: v["time"].as_str().unwrap_or("").into(),
            operation: v["operation"].as_str().unwrap_or("").into(),
            secrets: strs(&v["secrets"]),
            key: v["key"].as_str().map(str::to_string),
            via: v["via"].as_str().unwrap_or("").into(),
            chain: strs(&v["chain"]),
        })
        .collect())
}

// ---------------------------------------------------------------------------- approvals

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalDto {
    operation: String,
    secrets: Vec<String>,
    key_name: Option<String>,
    reason: Option<String>,
    command: Option<String>,
    can_always_allow: bool,
    grant_only: bool,
    verifier_name: String,
}

#[tauri::command]
pub async fn approval_request(state: State<'_, AppState>) -> Res<Option<ApprovalDto>> {
    Ok(state.approval.as_ref().map(|r| ApprovalDto {
        operation: r.op().as_str().into(),
        secrets: r.secrets.clone(),
        key_name: r.key_name.clone(),
        reason: r.reason.clone(),
        command: r.command.clone(),
        can_always_allow: r.can_always_allow && r.key_id.is_some() && !r.grant_only,
        grant_only: r.grant_only,
        verifier_name: platform::current().verifier_name(),
    }))
}

/// "deny", "once" or "always": verifies the user for an allow, grants for always, then exits with
/// the answer for `keylo mcp`.
#[tauri::command]
pub async fn answer_approval(window: WebviewWindow, app: AppHandle, state: State<'_, AppState>, choice: String) -> Res<()> {
    let Some(request) = state.approval.clone() else { return Err("No approval is pending.".into()) };
    if choice == "deny" {
        app.exit(approval::DENIED);
        return Ok(());
    }
    let always = choice == "always" || request.grant_only;
    let agent = request.key_name.clone().unwrap_or_else(|| "an agent".into());
    confirm(&window, &format!("Keylo: allow '{agent}' to use {}", request.secrets.join(", "))).await?;
    let mut code = approval::ALLOWED_ONCE;
    if always {
        let mut c = KeyloConfig::load().map_err(err)?;
        if access::grant(&mut c, request.key_id.as_deref().unwrap_or(""), &request.secrets) && c.save().is_ok() {
            code = approval::ALLOWED_ALWAYS;
        }
    }
    app.exit(code);
    Ok(())
}
