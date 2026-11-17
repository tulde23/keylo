//! The desktop keyring (Secret Service: GNOME Keyring, KWallet, KeePassXC…) as Keylo's credential
//! store. Each secret is an item in the default collection, labelled "Keylo: TARGET" and found by
//! the attributes service + account (plus libsecret's xdg:schema, so the C# build, which uses
//! libsecret, finds the same items). Everything else (value, username, notes, attributes) is inside
//! the encrypted secret as JSON, so nothing about it is readable without unlocking the keyring.

use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use keylo_core::platform::{CredentialStore, RawCredential};
use keylo_core::{Error, Result};
use secret_service::blocking::{Item, SecretService};
use secret_service::EncryptionType;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const DEFAULT_SERVICE: &str = "Keylo";
const SCHEMA: &str = "io.github.tulde23.keylo";

/// The JSON inside each item, as the C# build writes it (System.Text.Json defaults: PascalCase).
#[derive(Serialize, Deserialize)]
struct Payload {
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "UserName")]
    user_name: Option<String>,
    #[serde(rename = "Comment")]
    comment: Option<String>,
    #[serde(rename = "Attributes")]
    attributes: Option<BTreeMap<String, String>>,
}

pub struct SecretServiceStore {
    service: String,
}

fn ss_err(what: &str, e: secret_service::Error) -> Error {
    Error::msg(format!("Couldn't {what} in the keyring: {e}"))
}

fn connect() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh).map_err(|e| ss_err("connect", e))
}

impl SecretServiceStore {
    pub fn new(service: &str) -> Self {
        SecretServiceStore { service: service.to_string() }
    }

    /// Whether a usable Secret Service answers on this session's D-Bus: one that can be searched
    /// and has a default collection to save into (a keyring service started on demand without a
    /// keyring, as on servers and CI machines, answers searches but can't store anything).
    pub fn probe() -> std::result::Result<(), String> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| e.to_string())?;
        let mut query = HashMap::new();
        query.insert("service", "Keylo.Probe");
        ss.search_items(query).map_err(|e| e.to_string())?;
        ss.get_default_collection().map(|_| ()).map_err(|e| format!("no default keyring ({e})"))
    }

    /// Keylo's items (or the one for `account`), unlocking the keyring if needed.
    fn search(&self, account: Option<&str>) -> Result<Vec<RawCredential>> {
        let ss = connect()?;
        let mut query = HashMap::new();
        query.insert("service", self.service.as_str());
        if let Some(a) = account {
            query.insert("account", a);
        }
        let what = account.map(|a| format!("read '{a}'")).unwrap_or_else(|| "list Keylo items".into());
        let found = ss.search_items(query).map_err(|e| ss_err(&what, e))?;
        if !found.locked.is_empty() {
            let locked: Vec<&Item> = found.locked.iter().collect();
            ss.unlock_all(&locked).map_err(|e| ss_err("unlock", e))?;
        }
        let mut results = Vec::new();
        for item in found.unlocked.iter().chain(found.locked.iter()) {
            let attributes = item.get_attributes().map_err(|e| ss_err(&what, e))?;
            let Some(target) = attributes.get("account").cloned() else { continue };
            let secret = Zeroizing::new(item.get_secret().map_err(|e| ss_err(&format!("read '{target}'"), e))?);
            let modified = item.get_modified().ok().and_then(|s| DateTime::<Utc>::from_timestamp(s as i64, 0)).unwrap_or_else(Utc::now);
            results.push(to_credential(&target, &secret, modified));
        }
        Ok(results)
    }
}

fn to_credential(target: &str, secret: &[u8], modified: DateTime<Utc>) -> RawCredential {
    let payload: Option<Payload> = serde_json::from_slice(secret).ok();
    RawCredential {
        target: target.into(),
        user_name: payload.as_ref().and_then(|p| p.user_name.clone()),
        comment: payload.as_ref().and_then(|p| p.comment.clone()),
        last_written: modified,
        // An item written by something else: its secret as the value.
        blob: Zeroizing::new(match &payload {
            Some(p) => B64.decode(&p.value).unwrap_or_default(),
            None => secret.to_vec(),
        }),
        attributes: payload.and_then(|p| p.attributes).unwrap_or_default(),
    }
}

impl CredentialStore for SecretServiceStore {
    fn max_blob_bytes(&self) -> usize {
        16 * 1024
    }
    fn max_attribute_bytes(&self) -> usize {
        1024
    }
    fn max_attributes(&self) -> usize {
        64
    }

    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        Ok(self.search(Some(target))?.into_iter().find(|c| c.target.eq_ignore_ascii_case(target)))
    }

    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        let p = prefix.to_lowercase();
        Ok(self.search(None)?.into_iter().filter(|c| c.target.to_lowercase().starts_with(&p)).collect())
    }

    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        let payload = Zeroizing::new(
            serde_json::to_vec(&Payload {
                value: B64.encode(blob),
                user_name: user_name.map(str::to_string),
                comment: comment.map(str::to_string),
                attributes: Some(attributes.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect()),
            })
            .unwrap(),
        );
        let ss = connect()?;
        let collection = ss.get_default_collection().map_err(|e| ss_err(&format!("save '{target}'"), e))?;
        collection.ensure_unlocked().map_err(|e| ss_err("unlock", e))?;
        let mut attrs = HashMap::new();
        attrs.insert("xdg:schema", SCHEMA);
        attrs.insert("service", self.service.as_str());
        attrs.insert("account", target);
        // Same attributes with replace: updates the existing item.
        collection
            .create_item(&format!("{}: {target}", self.service), attrs, &payload, true, "text/plain")
            .map_err(|e| ss_err(&format!("save '{target}'"), e))?;
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<bool> {
        let ss = connect()?;
        let mut query = HashMap::new();
        query.insert("service", self.service.as_str());
        query.insert("account", target);
        let found = ss.search_items(query).map_err(|e| ss_err(&format!("delete '{target}'"), e))?;
        let mut removed = false;
        for item in found.unlocked.iter().chain(found.locked.iter()) {
            item.delete().map_err(|e| ss_err(&format!("delete '{target}'"), e))?;
            removed = true;
        }
        Ok(removed)
    }
}
