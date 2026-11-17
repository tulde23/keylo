use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use zeroize::Zeroizing;

/// Where a secret's value physically lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StorageKind {
    /// Inline in the OS store item.
    CredentialManager,
    /// An encrypted file under the data folder, referenced from the item.
    EncryptedFile,
}

/// Everything about a secret except its value. Safe to list and display.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretInfo {
    pub name: String,
    pub category: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub size: usize,
    pub storage: StorageKind,
    /// An icon name chosen in the app ("Cloud24", or "img{hash}" for an uploaded image).
    pub icon: Option<String>,
    /// "#RRGGBB".
    pub color: Option<String>,
    /// A secret type id (login, database…); none for a plain secret.
    #[serde(rename = "type")]
    pub type_id: Option<String>,
    /// The type's non-secret fields (host, url…); secret fields are in the value.
    pub fields: BTreeMap<String, String>,
}

/// A secret together with its value (wiped when dropped).
pub struct Secret {
    pub info: SecretInfo,
    pub value: Zeroizing<Vec<u8>>,
}

/// The fields supplied when adding or updating a secret.
#[derive(Default)]
pub struct SecretDraft {
    pub name: String,
    pub value: Zeroizing<Vec<u8>>,
    pub category: Option<String>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub type_id: Option<String>,
    pub fields: BTreeMap<String, String>,
}

impl SecretDraft {
    /// Re-saving an existing secret with its value, type and fields intact.
    pub fn from_secret(secret: &Secret) -> Self {
        let i = &secret.info;
        SecretDraft {
            name: i.name.clone(),
            value: secret.value.clone(),
            category: i.category.clone(),
            username: i.username.clone(),
            notes: i.notes.clone(),
            icon: i.icon.clone(),
            color: i.color.clone(),
            type_id: i.type_id.clone(),
            fields: i.fields.clone(),
        }
    }
}
