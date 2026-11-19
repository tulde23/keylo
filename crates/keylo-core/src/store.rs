//! Secrets stored as OS store items named "{prefix}{name}".
//!
//! Each item's blob starts with a one-byte kind tag:
//!   0x01 inline: the remaining bytes are the value.
//!   0x02 file:   a 16-byte id (GUID, mixed-endian byte order) and a 4-byte little-endian length; the value
//!                is an encrypted file blobs/{id}.bin, for values too large for the OS store.
//! Username and notes use the item's own user name and comment; category, icon, colour, type and
//! non-secret fields are attributes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::platform::{self, CredentialStore, RawCredential};
use crate::secrets::{Secret, SecretDraft, SecretInfo, StorageKind};
use crate::{bail, eq_ic, paths, Error, Result};

pub const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NAME_LENGTH: usize = 128;
pub const MAX_CATEGORY_LENGTH: usize = 64;
pub const MAX_USERNAME_LENGTH: usize = 512;
pub const MAX_NOTES_LENGTH: usize = 255;

const KIND_INLINE: u8 = 0x01;
const KIND_FILE: u8 = 0x02;
const CATEGORY_ATTRIBUTE: &str = "KeyloCategory";
const ICON_ATTRIBUTE: &str = "KeyloIcon";
const COLOR_ATTRIBUTE: &str = "KeyloColor";
const TYPE_ATTRIBUTE: &str = "KeyloType";
const FIELD_ATTRIBUTE_PREFIX: &str = "KeyloField:";

fn creds() -> &'static dyn CredentialStore {
    platform::current().credentials()
}

pub struct SecretStore {
    prefix: String,
    blob_dir: PathBuf,
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl SecretStore {
    pub fn new(data_dir: Option<&Path>, prefix: Option<&str>) -> Self {
        SecretStore {
            prefix: prefix.map(str::to_string).unwrap_or_else(paths::credential_prefix),
            blob_dir: data_dir.map(Path::to_path_buf).unwrap_or_else(paths::data_dir).join("blobs"),
        }
    }

    /// Values up to this size live in the OS store itself (one byte of the blob is the kind tag).
    pub fn max_inline_bytes() -> usize {
        creds().max_blob_bytes() - 1
    }

    pub fn list(&self) -> Result<Vec<SecretInfo>> {
        let mut list: Vec<SecretInfo> = creds()
            .enumerate(&self.prefix)?
            .iter()
            .filter_map(|raw| self.to_info(raw))
            .collect();
        list.sort_by_key(|s| s.name.to_lowercase());
        Ok(list)
    }

    pub fn categories(&self) -> Result<Vec<String>> {
        let mut cats: Vec<String> = Vec::new();
        for c in self.list()?.into_iter().filter_map(|s| s.category) {
            if !cats.iter().any(|x| eq_ic(x, &c)) {
                cats.push(c);
            }
        }
        cats.sort_by_key(|c| c.to_lowercase());
        Ok(cats)
    }

    pub fn find(&self, name: &str) -> Result<Option<SecretInfo>> {
        Ok(creds().read(&self.target(name))?.and_then(|raw| self.to_info(&raw)))
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.find(name)?.is_some())
    }

    pub fn get(&self, name: &str) -> Result<Secret> {
        let raw = creds().read(&self.target(name))?.ok_or_else(|| Error::NotFound(name.to_string()))?;
        let info = self
            .to_info(&raw)
            .ok_or_else(|| Error::msg(format!("'{name}' is not a Keylo secret or is corrupt.")))?;

        if raw.blob[0] == KIND_INLINE {
            return Ok(Secret { info, value: Zeroizing::new(raw.blob[1..].to_vec()) });
        }

        let (id, length) = read_file_reference(&raw.blob);
        let path = self.blob_path(id);
        if !path.exists() {
            bail!("The encrypted file for '{name}' is missing ({}).", path.display());
        }
        let value = platform::current().data_protector().unprotect(&fs::read(&path)?, &entropy(id))?;
        if value.len() != length {
            bail!("The encrypted file for '{name}' does not match its entry.");
        }
        Ok(Secret { info, value })
    }

    /// Adds a secret, or updates one when `original_name` is given (which may differ from the draft's
    /// name, renaming it). Adding fails if the name is taken; so does renaming onto another secret.
    pub fn save(&self, draft: &SecretDraft, original_name: Option<&str>) -> Result<SecretInfo> {
        let name = normalize_name(&draft.name)?;
        let category = normalize_optional(draft.category.as_deref(), MAX_CATEGORY_LENGTH, "Category", false)?;
        let username = normalize_optional(draft.username.as_deref(), MAX_USERNAME_LENGTH, "Username", false)?;
        let notes = normalize_optional(draft.notes.as_deref(), MAX_NOTES_LENGTH, "Notes", true)?;

        if draft.value.len() > MAX_VALUE_BYTES {
            bail!("Value is larger than {} MB.", MAX_VALUE_BYTES / (1024 * 1024));
        }

        let mut previous: Option<RawCredential> = None;
        let mut renaming = false;
        if let Some(original) = original_name {
            previous = Some(
                creds()
                    .read(&self.target(original))?
                    .ok_or_else(|| Error::NotFound(original.to_string()))?,
            );
            renaming = original != name;
            let case_only = renaming && eq_ic(original, &name);
            if renaming && !case_only && self.exists(&name)? {
                return Err(Error::Exists(name));
            }
        } else if self.exists(&name)? {
            return Err(Error::Exists(name));
        }

        let mut new_file_id: Option<Uuid> = None;
        let blob: Zeroizing<Vec<u8>> = if draft.value.len() <= Self::max_inline_bytes() {
            let mut b = Zeroizing::new(Vec::with_capacity(draft.value.len() + 1));
            b.push(KIND_INLINE);
            b.extend_from_slice(&draft.value);
            b
        } else {
            let id = Uuid::new_v4();
            self.write_blob_file(id, &draft.value)?;
            new_file_id = Some(id);
            let mut b = Zeroizing::new(Vec::with_capacity(21));
            b.push(KIND_FILE);
            b.extend_from_slice(&id.to_bytes_le());
            b.extend_from_slice(&(draft.value.len() as i32).to_le_bytes());
            b
        };

        let mut attributes = base_attributes(
            category.as_deref(),
            normalize_icon(draft.icon.as_deref())?,
            normalize_color(draft.color.as_deref())?,
        );
        add_type_attributes(&mut attributes, draft.type_id.as_deref(), &draft.fields)?;

        let write = (|| -> Result<()> {
            // Credential Manager names are case-insensitive, so a case-only rename has to remove the
            // old entry first or the write lands on it and keeps the old spelling.
            if let (true, Some(original)) = (renaming, original_name) {
                if eq_ic(original, &name) {
                    creds().delete(&self.target(original))?;
                }
            }
            creds().write(&self.target(&name), &blob, username.as_deref(), notes.as_deref(), &attributes)
        })();

        if let Err(e) = write {
            if let Some(orphan) = new_file_id {
                let _ = fs::remove_file(self.blob_path(orphan));
            }
            if let Some(prev) = &previous {
                if matches!(creds().read(&prev.target), Ok(None)) {
                    let _ = creds().write(
                        &prev.target,
                        &prev.blob,
                        prev.user_name.as_deref(),
                        prev.comment.as_deref(),
                        &prev.attributes,
                    );
                }
            }
            return Err(e);
        }

        if let (true, Some(original)) = (renaming, original_name) {
            if !eq_ic(original, &name) {
                creds().delete(&self.target(original))?;
            }
        }

        if let Some(prev) = &previous {
            if prev.blob.first() == Some(&KIND_FILE) && prev.blob.len() == 21 {
                let (old_id, _) = read_file_reference(&prev.blob);
                if Some(old_id) != new_file_id {
                    let _ = fs::remove_file(self.blob_path(old_id));
                }
            }
        }

        self.find(&name)?.ok_or_else(|| Error::msg(format!("'{name}' wasn't saved.")))
    }

    /// Changes category, icon and/or colour without reading the value. `None` keeps the current
    /// setting; `Some("")` clears it.
    pub fn update_details(
        &self,
        name: &str,
        category: Option<&str>,
        icon: Option<&str>,
        color: Option<&str>,
    ) -> Result<SecretInfo> {
        let raw = creds().read(&self.target(name))?.ok_or_else(|| Error::NotFound(name.to_string()))?;
        let info = self
            .to_info(&raw)
            .ok_or_else(|| Error::msg(format!("'{name}' is not a Keylo secret or is corrupt.")))?;

        let category = match category {
            None => info.category.clone(),
            Some(c) => normalize_optional(Some(c), MAX_CATEGORY_LENGTH, "Category", false)?,
        };
        let icon = match icon {
            None => info.icon.clone(),
            Some(i) => normalize_icon(Some(i))?,
        };
        let color = match color {
            None => info.color.clone(),
            Some(c) => normalize_color(Some(c))?,
        };
        let mut attributes = base_attributes(category.as_deref(), icon, color);
        add_type_attributes(&mut attributes, info.type_id.as_deref(), &info.fields)?;
        creds().write(&raw.target, &raw.blob, raw.user_name.as_deref(), raw.comment.as_deref(), &attributes)?;
        self.find(name)?.ok_or_else(|| Error::NotFound(name.to_string()))
    }

    /// Moves every secret in `from` to `to` (None: uncategorized). Returns how many moved.
    pub fn recategorize_all(&self, from: &str, to: Option<&str>) -> Result<usize> {
        let mut moved = 0;
        for s in self
            .list()?
            .into_iter()
            .filter(|s| s.category.as_deref().is_some_and(|c| eq_ic(c, from)))
        {
            self.update_details(&s.name, Some(to.unwrap_or("")), None, None)?;
            moved += 1;
        }
        Ok(moved)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let Some(raw) = creds().read(&self.target(name))? else { return Ok(false) };
        creds().delete(&raw.target)?;
        if raw.blob.first() == Some(&KIND_FILE) && raw.blob.len() == 21 {
            let _ = fs::remove_file(self.blob_path(read_file_reference(&raw.blob).0));
        }
        Ok(true)
    }

    fn target(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name.trim())
    }

    fn to_info(&self, raw: &RawCredential) -> Option<SecretInfo> {
        if raw.blob.is_empty() || !starts_with_ic(&raw.target, &self.prefix) {
            return None;
        }
        let (size, storage) = match raw.blob[0] {
            KIND_INLINE => (raw.blob.len() - 1, StorageKind::CredentialManager),
            KIND_FILE if raw.blob.len() == 21 => (read_file_reference(&raw.blob).1, StorageKind::EncryptedFile),
            _ => return None,
        };
        let non_empty = |name: &str| raw.attribute(name).filter(|v| !v.is_empty()).map(str::to_string);
        let fields = raw
            .attributes
            .iter()
            .filter(|(k, v)| k.starts_with(FIELD_ATTRIBUTE_PREFIX) && !v.is_empty())
            .map(|(k, v)| (k[FIELD_ATTRIBUTE_PREFIX.len()..].to_string(), v.clone()))
            .collect();
        Some(SecretInfo {
            name: raw.target[self.prefix.len()..].to_string(),
            category: non_empty(CATEGORY_ATTRIBUTE),
            username: raw.user_name.clone().filter(|u| !u.is_empty()),
            notes: raw.comment.clone().filter(|c| !c.is_empty()),
            updated_at: raw.last_written,
            size,
            storage,
            icon: non_empty(ICON_ATTRIBUTE),
            color: non_empty(COLOR_ATTRIBUTE),
            type_id: non_empty(TYPE_ATTRIBUTE),
            fields,
        })
    }

    fn blob_path(&self, id: Uuid) -> PathBuf {
        self.blob_dir.join(format!("{}.bin", id.simple()))
    }

    fn write_blob_file(&self, id: Uuid, value: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.blob_dir)?;
        let path = self.blob_path(id);
        let temp = self.blob_dir.join(format!("{}.bin.tmp", id.simple()));
        fs::write(&temp, platform::current().data_protector().protect(value, &entropy(id))?)?;
        fs::rename(&temp, &path)?;
        Ok(())
    }
}

fn starts_with_ic(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && eq_ic(&s[..prefix.len()], prefix)
}

fn read_file_reference(blob: &[u8]) -> (Uuid, usize) {
    let mut id = [0u8; 16];
    id.copy_from_slice(&blob[1..17]);
    let len = i32::from_le_bytes(blob[17..21].try_into().unwrap());
    (Uuid::from_bytes_le(id), len.max(0) as usize)
}

fn entropy(id: Uuid) -> Vec<u8> {
    format!("keylo:blob:{}", id.simple()).into_bytes()
}

/// Length in UTF-16 code units, as the OS stores count it.
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

pub fn is_valid_name(name: &str) -> bool {
    normalize_name(name).is_ok()
}

pub fn normalize_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Name is required.");
    }
    if utf16_len(name) > MAX_NAME_LENGTH {
        bail!("Name is longer than {MAX_NAME_LENGTH} characters.");
    }
    if name.chars().any(char::is_control) {
        bail!("Name cannot contain control characters.");
    }
    // '*' is the wildcard in Credential Manager filters, so a name containing it would match others.
    if name.contains('*') {
        bail!("Name cannot contain '*'.");
    }
    Ok(name.to_string())
}

fn normalize_optional(value: Option<&str>, max: usize, field: &str, allow_newlines: bool) -> Result<Option<String>> {
    let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    if utf16_len(v) > max {
        bail!("{field} is longer than {max} characters.");
    }
    if v.chars().any(|c| c.is_control() && !(allow_newlines && matches!(c, '\n' | '\r' | '\t'))) {
        bail!("{field} cannot contain control characters.");
    }
    Ok(Some(v.to_string()))
}

/// Icon names are identifiers like "Cloud24"; anything else is rejected.
pub fn normalize_icon(icon: Option<&str>) -> Result<Option<String>> {
    let Some(i) = icon.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    if i.len() > 64 || !i.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("'{i}' isn't a valid icon name.");
    }
    Ok(Some(i.to_string()))
}

/// Colours are "#RRGGBB" (stored upper-case).
pub fn normalize_color(color: Option<&str>) -> Result<Option<String>> {
    let Some(c) = color.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    if c.len() != 7 || !c.starts_with('#') || !c[1..].chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("'{c}' isn't a colour like #6366F1.");
    }
    Ok(Some(c.to_uppercase()))
}

fn base_attributes(category: Option<&str>, icon: Option<String>, color: Option<String>) -> BTreeMap<String, String> {
    let mut a = BTreeMap::new();
    if let Some(c) = category {
        a.insert(CATEGORY_ATTRIBUTE.to_string(), c.to_string());
    }
    if let Some(i) = icon {
        a.insert(ICON_ATTRIBUTE.to_string(), i);
    }
    if let Some(c) = color {
        a.insert(COLOR_ATTRIBUTE.to_string(), c);
    }
    a
}

/// Type id and non-secret fields as attributes.
fn add_type_attributes(
    attributes: &mut BTreeMap<String, String>,
    type_id: Option<&str>,
    fields: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(t) = type_id.filter(|t| !t.trim().is_empty()) else { return Ok(()) };
    if t.len() > 64 || !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("'{t}' isn't a valid type id.");
    }
    attributes.insert(TYPE_ATTRIBUTE.to_string(), t.to_string());

    let max = creds().max_attribute_bytes();
    for (id, value) in fields.iter().filter(|(_, v)| !v.is_empty()) {
        if value.len() > max {
            bail!("'{id}' is longer than {max} bytes. Shorten it, or use a secret field for long text.");
        }
        if value.chars().any(char::is_control) {
            bail!("'{id}' cannot contain line breaks or control characters.");
        }
        attributes.insert(format!("{FIELD_ATTRIBUTE_PREFIX}{id}"), value.clone());
    }
    let limit = creds().max_attributes();
    if attributes.len() > limit {
        bail!("Too many fields (the system store allows {limit} attributes).");
    }
    Ok(())
}
