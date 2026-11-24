//! The macOS login keychain as Keylo's credential store. Each secret is a generic password
//! (service "Keylo", account = the target, so it shows in Keychain Access as such): the value is
//! the item's data, and username, notes and attributes ride along as JSON in the item's "generic"
//! attribute.
//!
//! KEYLO_KEYCHAIN uses a specific keychain file instead of the login keychain (a throwaway one for
//! tests, or from an SSH session where the login keychain is locked).

use std::collections::BTreeMap;
use std::ffi::c_void;

use chrono::{DateTime, Utc};
use core_foundation::array::CFArray;
use core_foundation::base::{CFType, OSStatus, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFTypeRef, CFRelease};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;
use keylo_core::platform::{CredentialStore, RawCredential};
use keylo_core::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const DEFAULT_SERVICE: &str = "Keylo";

const ERR_ITEM_NOT_FOUND: OSStatus = -25300;

#[allow(non_upper_case_globals)]
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecClass: CFStringRef;
    static kSecClassGenericPassword: CFStringRef;
    static kSecAttrService: CFStringRef;
    static kSecAttrAccount: CFStringRef;
    static kSecAttrLabel: CFStringRef;
    static kSecAttrGeneric: CFStringRef;
    static kSecAttrModificationDate: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecReturnData: CFStringRef;
    static kSecReturnAttributes: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecMatchLimitAll: CFStringRef;
    static kSecUseKeychain: CFStringRef;
    static kSecMatchSearchList: CFStringRef;

    fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemUpdate(query: CFDictionaryRef, changes: CFDictionaryRef) -> OSStatus;
    fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;
    fn SecKeychainOpen(path: *const std::os::raw::c_char, keychain: *mut CFTypeRef) -> OSStatus;
}

fn key(k: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(k) }
}

fn check(status: OSStatus, what: &str) -> Result<()> {
    if status == 0 {
        return Ok(());
    }
    let message = unsafe {
        let s = SecCopyErrorMessageString(status, std::ptr::null_mut());
        if s.is_null() { format!("error {status}") } else { CFString::wrap_under_create_rule(s).to_string() }
    };
    Err(Error::msg(format!("Couldn't {what} in the Keychain: {message}")))
}

/// What's kept in the item's "generic" attribute (PascalCase JSON).
#[derive(Serialize, Deserialize, Default)]
struct Metadata {
    #[serde(rename = "UserName")]
    user_name: Option<String>,
    #[serde(rename = "Comment")]
    comment: Option<String>,
    #[serde(rename = "Attributes")]
    attributes: Option<BTreeMap<String, String>>,
}

pub struct KeychainStore {
    service: String,
    /// A specific keychain (KEYLO_KEYCHAIN), opened once.
    keychain: Option<CFType>,
}

// The keychain reference is only read after creation.
unsafe impl Send for KeychainStore {}
unsafe impl Sync for KeychainStore {}

impl KeychainStore {
    pub fn new(service: &str, keychain_path: Option<&str>) -> Self {
        let keychain = keychain_path.filter(|p| !p.is_empty()).and_then(|p| {
            let path = std::ffi::CString::new(p).ok()?;
            let mut kc: CFTypeRef = std::ptr::null();
            let status = unsafe { SecKeychainOpen(path.as_ptr(), &mut kc) };
            (status == 0 && !kc.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(kc) })
        });
        KeychainStore { service: service.to_string(), keychain }
    }

    /// class + service (+ account), plus `extra`; with a specific keychain, where to add or search.
    fn query(&self, account: Option<&str>, adding: bool, extra: Vec<(CFString, CFType)>) -> CFDictionary<CFString, CFType> {
        let mut pairs: Vec<(CFString, CFType)> = vec![
            (key(unsafe { kSecClass }), key(unsafe { kSecClassGenericPassword }).as_CFType()),
            (key(unsafe { kSecAttrService }), CFString::new(&self.service).as_CFType()),
        ];
        if let Some(a) = account {
            pairs.push((key(unsafe { kSecAttrAccount }), CFString::new(a).as_CFType()));
        }
        if let Some(kc) = &self.keychain {
            if adding {
                pairs.push((key(unsafe { kSecUseKeychain }), kc.clone()));
            } else {
                pairs.push((key(unsafe { kSecMatchSearchList }), CFArray::from_CFTypes(&[kc.clone()]).as_CFType()));
            }
        }
        pairs.extend(extra);
        CFDictionary::from_CFType_pairs(&pairs)
    }

    /// Whether an item here can be read without a user prompt. False only when macOS would need to ask
    /// and can't (errSecInteractionNotAllowed, -25308 — e.g. over SSH); a missing item or any other
    /// status counts as reachable, so the real error surfaces later with its own message. Reading the
    /// data forces the access-control check that would prompt.
    pub fn reachable(&self, probe_account: &str) -> bool {
        const ERR_INTERACTION_NOT_ALLOWED: OSStatus = -25308;
        let query = self.query(
            Some(probe_account),
            false,
            vec![
                (key(unsafe { kSecReturnData }), CFBoolean::true_value().as_CFType()),
                (key(unsafe { kSecMatchLimit }), key(unsafe { kSecMatchLimitOne }).as_CFType()),
            ],
        );
        !matches!(copy_matching(&query), Err(ERR_INTERACTION_NOT_ALLOWED))
    }

    fn to_credential(&self, target: &str, attributes: &CFDictionary<CFString, CFType>, blob: Vec<u8>) -> RawCredential {
        let generic = attributes
            .find(key(unsafe { kSecAttrGeneric }))
            .and_then(|v| v.downcast::<CFData>())
            .map(|d| d.bytes().to_vec())
            .unwrap_or_default();
        let metadata: Metadata = if generic.is_empty() { Metadata::default() } else { serde_json::from_slice(&generic).unwrap_or_default() };
        let modified = attributes
            .find(key(unsafe { kSecAttrModificationDate }))
            .and_then(|v| v.downcast::<CFDate>())
            .and_then(|d| DateTime::<Utc>::from_timestamp_millis(((d.abs_time() + 978_307_200.0) * 1000.0) as i64))
            .unwrap_or_else(Utc::now);
        RawCredential {
            target: target.into(),
            user_name: metadata.user_name,
            comment: metadata.comment,
            last_written: modified,
            blob: Zeroizing::new(blob),
            attributes: metadata.attributes.unwrap_or_default(),
        }
    }
}

fn copy_matching(query: &CFDictionary<CFString, CFType>) -> std::result::Result<Option<CFType>, OSStatus> {
    let mut result: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    match status {
        0 if !result.is_null() => Ok(Some(unsafe { CFType::wrap_under_create_rule(result) })),
        0 | ERR_ITEM_NOT_FOUND => Ok(None),
        s => Err(s),
    }
}

impl CredentialStore for KeychainStore {
    // Everyday secrets stay in the keychain; certificates and key bundles go to protected files.
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
        let t = CFBoolean::true_value().as_CFType();
        let query = self.query(
            Some(target),
            false,
            vec![
                (key(unsafe { kSecReturnData }), t.clone()),
                (key(unsafe { kSecReturnAttributes }), t),
                (key(unsafe { kSecMatchLimit }), key(unsafe { kSecMatchLimitOne }).as_CFType()),
            ],
        );
        let found = copy_matching(&query).or_else(|s| check(s, &format!("read '{target}'")).map(|_| None))?;
        let Some(found) = found else { return Ok(None) };
        let Some(dict) = found.downcast::<CFDictionary>() else { return Ok(None) };
        let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_get_rule(dict.as_concrete_TypeRef()) };
        let data = dict.find(key(unsafe { kSecValueData })).and_then(|v| v.downcast::<CFData>()).map(|d| d.bytes().to_vec()).unwrap_or_default();
        Ok(Some(self.to_credential(target, &dict, data)))
    }

    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        // Attributes for every Keylo item first (returning data for "all" isn't allowed), then each value.
        let query = self.query(
            None,
            false,
            vec![
                (key(unsafe { kSecReturnAttributes }), CFBoolean::true_value().as_CFType()),
                (key(unsafe { kSecMatchLimit }), key(unsafe { kSecMatchLimitAll }).as_CFType()),
            ],
        );
        let found = copy_matching(&query).or_else(|s| check(s, "list Keylo items").map(|_| None))?;
        let Some(array) = found.and_then(|f| f.downcast::<CFArray>()) else { return Ok(vec![]) };
        let p = prefix.to_lowercase();
        let mut accounts = Vec::new();
        for item in array.iter() {
            let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_get_rule(*item as CFDictionaryRef) };
            if let Some(account) = dict.find(key(unsafe { kSecAttrAccount })).and_then(|v| v.downcast::<CFString>()) {
                let account = account.to_string();
                if account.to_lowercase().starts_with(&p) {
                    accounts.push(account);
                }
            }
        }
        let mut results = Vec::new();
        for a in accounts {
            if let Some(c) = self.read(&a)? {
                results.push(c);
            }
        }
        Ok(results)
    }

    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        let metadata = serde_json::to_vec(&Metadata {
            user_name: user_name.map(str::to_string),
            comment: comment.map(str::to_string),
            attributes: Some(attributes.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect()),
        })
        .unwrap();
        let data = CFData::from_buffer(blob);
        let generic = CFData::from_buffer(&metadata);

        // Update in place when it exists (keeps the item's access list), else add.
        let query = self.query(Some(target), false, vec![]);
        let mut changes = CFMutableDictionary::<CFString, CFType>::new();
        changes.set(key(unsafe { kSecValueData }), data.as_CFType());
        changes.set(key(unsafe { kSecAttrGeneric }), generic.as_CFType());
        let status = unsafe { SecItemUpdate(query.as_concrete_TypeRef(), changes.as_concrete_TypeRef()) };
        if status != ERR_ITEM_NOT_FOUND {
            return check(status, &format!("update '{target}'"));
        }
        let add = self.query(
            Some(target),
            true,
            vec![
                (key(unsafe { kSecAttrLabel }), CFString::new(target).as_CFType()),
                (key(unsafe { kSecValueData }), data.as_CFType()),
                (key(unsafe { kSecAttrGeneric }), generic.as_CFType()),
            ],
        );
        let status = unsafe { SecItemAdd(add.as_concrete_TypeRef(), std::ptr::null_mut()) };
        check(status, &format!("add '{target}'"))
    }

    fn delete(&self, target: &str) -> Result<bool> {
        let query = self.query(Some(target), false, vec![]);
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status == ERR_ITEM_NOT_FOUND {
            return Ok(false);
        }
        check(status, &format!("delete '{target}'"))?;
        Ok(true)
    }
}

#[allow(dead_code)]
fn release(r: CFTypeRef) {
    if !r.is_null() {
        unsafe { CFRelease(r) }
    }
}
