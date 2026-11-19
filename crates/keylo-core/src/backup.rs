//! Password-protected backups, portable between accounts, PCs and Macs (unlike DPAPI or the
//! keychain).
//!
//! File layout (all integers little-endian):
//!   "KEYLOBK1"  8-byte magic
//!   version     1 byte (1)
//!   iterations  4 bytes, PBKDF2-SHA256
//!   salt        16 bytes
//!   nonce       12 bytes
//!   ciphertext  AES-256-GCM of the gzip-compressed JSON payload
//!   tag         16 bytes
//! The header (everything before the ciphertext) is the GCM associated data, so changing the
//! iteration count or salt is detected rather than silently weakening the file. Nothing about the
//! secrets, not even their names, is readable without the password.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use chrono::{DateTime, FixedOffset, Local};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::categories::CategoryCatalog;
use crate::icons;
use crate::secrets::SecretDraft;
use crate::store::SecretStore;
use crate::types::{built_in, SecretTypeCatalog, SecretTypeDefinition, Style};
use crate::{bail, Error, Result};

pub const MIN_PASSWORD_LENGTH: usize = 10;
/// OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256.
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const FILE_EXTENSION: &str = "keylo";

const MAGIC: &[u8; 8] = b"KEYLOBK1";
const VERSION: u8 = 1;
const SALT: usize = 16;
const NONCE: usize = 12;
const TAG: usize = 16;
const HEADER: usize = 8 + 1 + 4 + SALT + NONCE;
const MAX_ITERATIONS: u32 = 10_000_000;

const WRONG_PASSWORD: &str = "Wrong password, or the backup file is damaged.";

/// One secret in a backup. The value is base64 in the JSON.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSecret {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(with = "b64")]
    pub value: Zeroizing<Vec<u8>>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, String>>,
}

/// A decrypted backup, held in memory only (values are wiped when it's dropped).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupContents {
    #[serde(with = "dto")]
    pub created_at: DateTime<FixedOffset>,
    pub secrets: Vec<BackupSecret>,
    #[serde(default)]
    pub categories: BTreeMap<String, Style>,
    #[serde(default, with = "b64_map")]
    pub icons: BTreeMap<String, Vec<u8>>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub types: Vec<SecretTypeDefinition>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub path: String,
    pub secrets: usize,
    pub categories: usize,
    pub icons: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResult {
    pub added: usize,
    pub replaced: usize,
    pub skipped: usize,
    pub categories_added: usize,
    pub errors: Vec<String>,
}

pub fn check_password(password: &str) -> Option<String> {
    (password.chars().count() < MIN_PASSWORD_LENGTH)
        .then(|| format!("Use at least {MIN_PASSWORD_LENGTH} characters — a passphrase of a few words is ideal."))
}

/// "backup" → "backup.keylo"; a path with an extension is kept.
pub fn with_extension(path: &Path) -> PathBuf {
    if path.extension().is_some() {
        path.to_path_buf()
    } else {
        path.with_extension(FILE_EXTENSION)
    }
}

/// Everything a backup of this store holds: every secret with its value, every category, the
/// custom types, and the uploaded icons something still refers to.
pub fn collect(store: &SecretStore, catalog: &CategoryCatalog, types: &SecretTypeCatalog, data_dir: &Path) -> Result<BackupContents> {
    let infos = store.list()?;
    let mut secrets = Vec::with_capacity(infos.len());
    for info in &infos {
        let secret = store.get(&info.name)?;
        secrets.push(BackupSecret {
            name: info.name.clone(),
            category: info.category.clone(),
            username: info.username.clone(),
            notes: info.notes.clone(),
            icon: info.icon.clone(),
            color: info.color.clone(),
            value: secret.value.clone(),
            type_id: info.type_id.clone(),
            fields: (!info.fields.is_empty()).then(|| info.fields.clone()),
        });
    }
    let categories: BTreeMap<String, Style> =
        catalog.all(&infos).into_iter().map(|c| (c.name, Style { icon: c.icon, color: c.color })).collect();

    let mut images = BTreeMap::new();
    let used = secrets.iter().filter_map(|s| s.icon.as_ref()).chain(categories.values().filter_map(|c| c.icon.as_ref()));
    for icon in used {
        if icons::is_image(icon) && !images.contains_key(icon) {
            if let Ok(png) = fs::read(icon_file(data_dir, icon)) {
                images.insert(icon.clone(), png);
            }
        }
    }

    Ok(BackupContents { created_at: Local::now().fixed_offset(), secrets, categories, icons: images, types: types.custom()? })
}

/// Writes `contents` to `path`, encrypted with `password`.
pub fn write(contents: &BackupContents, path: &Path, password: &str, iterations: u32) -> Result<BackupSummary> {
    if let Some(problem) = check_password(password) {
        return Err(Error::Keylo(problem));
    }
    let json = Zeroizing::new(serde_json::to_vec(contents).map_err(|e| Error::msg(e.to_string()))?);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&json)?;
    let compressed = Zeroizing::new(gz.finish()?);
    let file = encrypt(&compressed, password, iterations)?;

    let temp = path.with_extension(format!("{}.tmp", path.extension().and_then(|e| e.to_str()).unwrap_or("")));
    fs::write(&temp, &file)?;
    fs::rename(&temp, path)?;
    Ok(BackupSummary {
        path: path.display().to_string(),
        secrets: contents.secrets.len(),
        categories: contents.categories.len(),
        icons: contents.icons.len(),
        bytes: file.len(),
    })
}

/// Decrypts a backup. A wrong password and a damaged file give the same error.
pub fn read(path: &Path, password: &str) -> Result<BackupContents> {
    let file = fs::read(path)?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    if file.len() < HEADER + TAG || &file[..8] != MAGIC {
        bail!("'{name}' isn't a Keylo backup.");
    }
    if file[8] != VERSION {
        bail!("This backup was made by a newer version of Keylo (format {}).", file[8]);
    }
    let iterations = u32::from_le_bytes(file[9..13].try_into().unwrap());
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        bail!("{WRONG_PASSWORD}");
    }
    let salt = &file[13..13 + SALT];
    let nonce = &file[13 + SALT..HEADER];
    let key = derive_key(password, salt, iterations);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).expect("32-byte key");
    let compressed = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(nonce), AeadPayload { msg: &file[HEADER..], aad: &file[..HEADER] })
            .map_err(|_| Error::msg(WRONG_PASSWORD))?,
    );

    let mut json = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(&compressed[..])
        .read_to_end(&mut json)
        .map_err(|_| Error::msg("The backup decrypted but its contents are unreadable."))?;
    let json = strip_bom(&json);
    serde_json::from_slice(json).map_err(|_| Error::msg("The backup decrypted but its contents are unreadable."))
}

/// Restores into this store. Existing secrets are skipped unless `overwrite`; categories are always
/// merged (their styles only replace existing ones when overwriting); custom types already defined
/// here are kept as they are.
pub fn restore(
    store: &SecretStore,
    catalog: &mut CategoryCatalog,
    types: &SecretTypeCatalog,
    data_dir: &Path,
    contents: &BackupContents,
    overwrite: bool,
) -> Result<RestoreResult> {
    for (icon, png) in &contents.icons {
        let file = icon_file(data_dir, icon);
        if icons::is_image(icon) && !file.exists() {
            fs::create_dir_all(data_dir.join("icons"))?;
            fs::write(file, png)?;
        }
    }

    let mut categories_added = 0;
    for (name, style) in &contents.categories {
        if catalog.merge(name, style, overwrite)? {
            categories_added += 1;
        }
    }

    let existing = types.custom()?;
    let defaults = built_in();
    let new_types: Vec<SecretTypeDefinition> = contents
        .types
        .iter()
        .filter(|t| existing.iter().all(|e| e.id != t.id) && defaults.iter().all(|b| b.id != t.id))
        .cloned()
        .collect();
    if !new_types.is_empty() {
        types.save_custom(existing.into_iter().chain(new_types).collect())?;
    }

    let mut result = RestoreResult { added: 0, replaced: 0, skipped: 0, categories_added, errors: vec![] };
    for s in &contents.secrets {
        // None: skipped; Some(true): replaced; Some(false): added.
        let outcome = (|| -> Result<Option<bool>> {
            let found = store.find(&s.name)?;
            if found.is_some() && !overwrite {
                return Ok(None);
            }
            let draft = SecretDraft {
                name: s.name.clone(),
                value: s.value.clone(),
                category: s.category.clone(),
                username: s.username.clone(),
                notes: s.notes.clone(),
                icon: s.icon.clone(),
                color: s.color.clone(),
                type_id: s.type_id.clone(),
                fields: s.fields.clone().unwrap_or_default(),
            };
            store.save(&draft, found.as_ref().map(|f| f.name.as_str()))?;
            Ok(Some(found.is_some()))
        })();
        match outcome {
            Ok(None) => result.skipped += 1,
            Ok(Some(true)) => result.replaced += 1,
            Ok(Some(false)) => result.added += 1,
            Err(e) => result.errors.push(format!("{}: {e}", s.name)),
        }
    }
    Ok(result)
}

fn icon_file(data_dir: &Path, icon: &str) -> PathBuf {
    data_dir.join("icons").join(format!("{}.png", &icon[3.min(icon.len())..]))
}

fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data)
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, iterations, &mut key[..]);
    key
}

fn encrypt(plaintext: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(HEADER);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&iterations.to_le_bytes());
    let mut random = [0u8; SALT + NONCE];
    rand::rngs::OsRng.fill_bytes(&mut random);
    header.extend_from_slice(&random);

    let key = derive_key(password, &random[..SALT], iterations);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).expect("32-byte key");
    // aes-gcm appends the tag to the ciphertext, which is the file's layout.
    let sealed = cipher
        .encrypt(Nonce::from_slice(&random[SALT..]), AeadPayload { msg: plaintext, aad: &header })
        .map_err(|_| Error::msg("Encryption failed."))?;
    header.extend_from_slice(&sealed);
    Ok(header)
}

fn null_as_empty<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

mod b64 {
    use super::*;
    pub fn serialize<S: Serializer>(v: &Zeroizing<Vec<u8>>, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&v[..]))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Zeroizing<Vec<u8>>, D::Error> {
        let text = Zeroizing::new(String::deserialize(d)?);
        base64::engine::general_purpose::STANDARD.decode(text.as_bytes()).map(Zeroizing::new).map_err(serde::de::Error::custom)
    }
}

mod b64_map {
    use super::*;
    pub fn serialize<S: Serializer>(m: &BTreeMap<String, Vec<u8>>, s: S) -> std::result::Result<S::Ok, S::Error> {
        let encoded: BTreeMap<&String, String> =
            m.iter().map(|(k, v)| (k, base64::engine::general_purpose::STANDARD.encode(v))).collect();
        encoded.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<BTreeMap<String, Vec<u8>>, D::Error> {
        Option::<BTreeMap<String, String>>::deserialize(d)?
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| base64::engine::general_purpose::STANDARD.decode(v).map(|b| (k, b)).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// A timestamp with offset and 7 fractional digits: "2026-11-16T10:42:07.1234567+00:00".
mod dto {
    use super::*;
    pub fn serialize<S: Serializer>(t: &DateTime<FixedOffset>, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&t.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<DateTime<FixedOffset>, D::Error> {
        let text = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn round_trip_restores_secrets_categories_and_types() {
        let dir = testing::setup();
        let store = SecretStore::new(Some(&dir), Some(&testing::prefix()));
        let mut catalog = CategoryCatalog::in_dir(&dir);
        let types = SecretTypeCatalog::in_dir(&dir);
        let draft = SecretDraft { name: "api".into(), value: Zeroizing::new(b"s3cret".to_vec()), category: Some("dev".into()), ..Default::default() };
        store.save(&draft, None).unwrap();
        catalog.create("empty", Some("Shield24"), None).unwrap();

        let path = dir.join("b.keylo");
        let contents = collect(&store, &catalog, &types, &dir).unwrap();
        assert!(write(&contents, &path, "short", 1000).is_err());
        let summary = write(&contents, &path, "correct horse battery", 1000).unwrap();
        assert_eq!((summary.secrets, summary.categories), (1, 2));
        assert!(read(&path, "wrong password!").is_err());

        // Into an empty store elsewhere.
        let dir2 = testing::setup();
        let store2 = SecretStore::new(Some(&dir2), Some(&testing::prefix()));
        let mut catalog2 = CategoryCatalog::in_dir(&dir2);
        let read_back = read(&path, "correct horse battery").unwrap();
        let r = restore(&store2, &mut catalog2, &SecretTypeCatalog::in_dir(&dir2), &dir2, &read_back, false).unwrap();
        assert_eq!((r.added, r.replaced, r.skipped, r.categories_added), (1, 0, 0, 2));
        assert_eq!(&store2.get("api").unwrap().value[..], b"s3cret");
        let r = restore(&store2, &mut catalog2, &SecretTypeCatalog::in_dir(&dir2), &dir2, &read_back, false).unwrap();
        assert_eq!((r.added, r.skipped), (0, 1));
        let r = restore(&store2, &mut catalog2, &SecretTypeCatalog::in_dir(&dir2), &dir2, &read_back, true).unwrap();
        assert_eq!(r.replaced, 1);
    }
}
