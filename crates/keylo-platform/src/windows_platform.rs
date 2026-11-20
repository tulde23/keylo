//! Keylo on Windows: Keylo's vault (SQLite, values sealed with a key protected by DPAPI; secrets kept
//! in Credential Manager by earlier versions are moved into it), Windows Hello, a clipboard kept out of history
//! and cloud sync, and Toolhelp32 process ancestry.

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, TimeZone, Utc};
use keylo_core::platform::*;
use keylo_core::{paths, Error, Result};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, GlobalFree, LocalFree, ERROR_NOT_FOUND, FILETIME, HANDLE, HGLOBAL, HLOCAL, HWND,
};
use windows::Win32::Security::Credentials::*;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::DataExchange::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, IsWindowVisible};
use zeroize::Zeroizing;

use crate::sqlite_vault::{OsKey, SqliteVault};

/// The one vault for this process, so `keylo unlock`/`lock` and the passphrase commands can reach it.
static VAULT: OnceLock<&'static SqliteVault> = OnceLock::new();

pub(crate) fn unlock(passphrase: Option<&str>) -> Result<bool> {
    match VAULT.get() {
        Some(v) => match passphrase {
            Some(p) => v.unlock(p).map(|()| true),
            None => v.try_unlock_quietly(),
        },
        None => Ok(true),
    }
}

pub(crate) fn lock() {
    if let Some(v) = VAULT.get() {
        v.lock();
    }
}

pub(crate) fn has_passphrase() -> Result<bool> {
    match VAULT.get() {
        Some(v) => v.has_passphrase(),
        None => Ok(false),
    }
}

pub(crate) fn set_passphrase(current: Option<&str>, new: Option<&str>) -> Result<()> {
    let &v = VAULT.get().ok_or_else(|| Error::msg("Keylo's vault isn't ready."))?;
    v.set_passphrase(current, new)
}

/// Whether "unlock with Windows Hello" is set up for the vault.
pub(crate) fn has_hello() -> Result<bool> {
    match VAULT.get() {
        Some(v) => v.has_hello(),
        None => Ok(false),
    }
}

/// Turns "unlock with Windows Hello" on (asks for the Hello gesture to bind the key) or off.
pub(crate) fn set_hello(enable: bool, passphrase: Option<&str>) -> Result<()> {
    let &v = VAULT.get().ok_or_else(|| Error::msg("Keylo's vault isn't ready."))?;
    if enable {
        let kek = crate::hello_key::derive()?;
        v.set_hello(true, passphrase, Some(&kek))
    } else {
        v.set_hello(false, None, None)
    }
}

/// Unlocks the vault with Windows Hello (asks for the gesture). Caches the session for the CLI/MCP.
pub(crate) fn unlock_hello() -> Result<()> {
    let &v = VAULT.get().ok_or_else(|| Error::msg("Keylo's vault isn't ready."))?;
    let kek = crate::hello_key::derive()?;
    v.unlock_hello(&kek)
}

pub(crate) fn status() -> Option<String> {
    let &v = VAULT.get()?;
    let locked = v.has_passphrase().unwrap_or(false) && !v.try_unlock_quietly().unwrap_or(true);
    Some(match (v.has_passphrase().unwrap_or(false), locked) {
        (false, _) => "Keylo's vault".into(),
        (true, false) => "Keylo's vault (master passphrase, unlocked)".into(),
        (true, true) => "Keylo's vault (master passphrase, locked)".into(),
    })
}

pub struct WindowsPlatform {
    credentials: VaultStore,
    protector: Dpapi,
    verifier: WindowsHello,
    clipboard: Clipboard,
    processes: Toolhelp,
}

impl WindowsPlatform {
    pub fn new() -> Self {
        WindowsPlatform {
            credentials: VaultStore {
                vault: *VAULT.get_or_init(|| Box::leak(Box::new(SqliteVault::new(paths::data_dir().join("keylo.db"), Box::new(DpapiKey))))),
                moved: Mutex::new(false),
            },
            protector: Dpapi,
            verifier: WindowsHello,
            clipboard: Clipboard,
            processes: Toolhelp,
        }
    }
}

impl Default for WindowsPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform for WindowsPlatform {
    fn name(&self) -> &str {
        "Windows"
    }
    fn credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }
    fn data_protector(&self) -> &dyn DataProtector {
        &self.protector
    }
    fn verifier(&self) -> &dyn UserVerifier {
        &self.verifier
    }
    fn verifier_name(&self) -> String {
        "Windows Hello".into()
    }
    fn store_name(&self) -> String {
        "Keylo's vault".into()
    }
    fn file_protection_name(&self) -> String {
        "DPAPI".into()
    }
    fn clipboard(&self) -> &dyn SecureClipboard {
        &self.clipboard
    }
    fn processes(&self) -> &dyn ProcessAncestry {
        &self.processes
    }
}

fn win_err(what: &str, e: windows::core::Error) -> Error {
    Error::msg(format!("{what} failed: {}", e.message()))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn from_wide(p: PWSTR) -> Option<String> {
    if p.is_null() {
        None
    } else {
        p.to_string().ok()
    }
}

// ---------------------------------------------------------------------------- the vault

/// The vault key, protected with DPAPI for this Windows account (as Credential Manager items are).
struct DpapiKey;

const VAULT_KEY_ENTROPY: &[u8] = b"keylo-vault-key:v1";

impl OsKey for DpapiKey {
    fn kind(&self) -> &'static str {
        "dpapi"
    }
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>> {
        Dpapi.protect(key, VAULT_KEY_ENTROPY)
    }
    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Dpapi.unprotect(stored, VAULT_KEY_ENTROPY)
    }
}

/// Keylo's vault, after moving in any secrets an earlier Keylo kept in Credential Manager.
struct VaultStore {
    vault: &'static SqliteVault,
    /// Whether the move has been done (or wasn't needed). A failed move is tried again next time.
    moved: Mutex<bool>,
}

impl VaultStore {
    fn ready(&self) -> Result<&SqliteVault> {
        let mut moved = self.moved.lock().unwrap();
        if !*moved {
            if migrates_here() {
                move_from_credential_manager(&self.vault, &CredentialManager, &paths::credential_prefix()).map_err(Error::msg)?;
            }
            *moved = true;
        }
        Ok(&self.vault)
    }
}

/// Moves Credential Manager items only into the real vault: the default data folder, or a test
/// setup that names its own prefix too. A KEYLO_HOME set on its own (an experiment, a throwaway
/// folder) must never take the real `Keylo:` secrets with it.
fn migrates_here() -> bool {
    let var = |v: &str| std::env::var(v).ok();
    migrates_for(var("KEYLO_HOME").as_deref(), var("KEYLO_PREFIX").as_deref())
}

fn migrates_for(home: Option<&str>, prefix: Option<&str>) -> bool {
    let set = |v: Option<&str>| v.is_some_and(|s| !s.is_empty());
    !set(home) || set(prefix)
}

/// Moves Credential Manager items named `prefix`… into the vault: copies them all in one transaction
/// (keeping a vault copy that's newer), reads each back, and only then deletes the original. Items
/// whose copy doesn't match stay where they are and are tried again next time, so nothing is lost if
/// it's interrupted.
fn move_from_credential_manager(vault: &SqliteVault, legacy: &dyn CredentialStore, prefix: &str) -> std::result::Result<(), String> {
    let old = legacy.enumerate(prefix).map_err(|e| format!("Couldn't read Credential Manager to move your secrets into Keylo's vault: {e}"))?;
    if old.is_empty() {
        return Ok(());
    }
    vault.import(&old).map_err(|e| format!("Couldn't move your secrets into Keylo's vault: {e}"))?;
    for c in &old {
        let copied = match vault.read(&c.target) {
            Ok(Some(v)) => v.last_written > c.last_written || same(&v, c),
            _ => false,
        };
        if copied {
            let _ = legacy.delete(&c.target);
        }
    }
    Ok(())
}

fn same(a: &RawCredential, b: &RawCredential) -> bool {
    let attrs = |c: &RawCredential| c.attributes.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect::<BTreeMap<_, _>>();
    a.blob.as_slice() == b.blob.as_slice() && a.user_name == b.user_name && a.comment == b.comment && attrs(a) == attrs(b)
}

impl CredentialStore for VaultStore {
    fn max_blob_bytes(&self) -> usize {
        self.vault.max_blob_bytes()
    }
    fn max_attribute_bytes(&self) -> usize {
        self.vault.max_attribute_bytes()
    }
    fn max_attributes(&self) -> usize {
        self.vault.max_attributes()
    }
    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        self.ready()?.read(target)
    }
    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        self.ready()?.enumerate(prefix)
    }
    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        self.ready()?.write(target, blob, user_name, comment, attributes)
    }
    fn delete(&self, target: &str) -> Result<bool> {
        self.ready()?.delete(target)
    }
    fn enumerate_details(&self, prefix: &str) -> Result<Vec<CredentialDetails>> {
        self.ready()?.enumerate_details(prefix)
    }
    fn read_details(&self, target: &str) -> Result<Option<CredentialDetails>> {
        self.ready()?.read_details(target)
    }
    fn update_details(&self, target: &str, user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<bool> {
        self.ready()?.update_details(target, user_name, comment, attributes)
    }
}

// ---------------------------------------------------------------------------- Credential Manager

const CRED_MAX_BLOB: usize = 5 * 512;
const CRED_MAX_VALUE: usize = 256;

struct CredentialManager;

unsafe fn raw_from(cred: &CREDENTIALW) -> RawCredential {
    let blob = if cred.CredentialBlobSize > 0 {
        std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize).to_vec()
    } else {
        vec![]
    };
    let mut attributes = BTreeMap::new();
    for i in 0..cred.AttributeCount as usize {
        let a = &*cred.Attributes.add(i);
        let value = if a.ValueSize > 0 { std::slice::from_raw_parts(a.Value, a.ValueSize as usize) } else { &[] };
        if let Some(k) = from_wide(a.Keyword) {
            attributes.insert(k, String::from_utf8_lossy(value).into_owned());
        }
    }
    RawCredential {
        target: from_wide(cred.TargetName).unwrap_or_default(),
        user_name: from_wide(cred.UserName),
        comment: from_wide(cred.Comment),
        last_written: filetime_to_utc(cred.LastWritten),
        blob: Zeroizing::new(blob),
        attributes,
    }
}

fn filetime_to_utc(ft: FILETIME) -> DateTime<Utc> {
    let ticks = ((ft.dwHighDateTime as i64) << 32) | ft.dwLowDateTime as i64;
    // FILETIME: 100 ns since 1601-01-01.
    let unix_100ns = ticks - 116_444_736_000_000_000;
    Utc.timestamp_nanos(unix_100ns.saturating_mul(100))
}

impl CredentialStore for CredentialManager {
    fn max_blob_bytes(&self) -> usize {
        CRED_MAX_BLOB
    }
    fn max_attribute_bytes(&self) -> usize {
        CRED_MAX_VALUE
    }
    fn max_attributes(&self) -> usize {
        64
    }

    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        let t = wide(target);
        let mut p: *mut CREDENTIALW = std::ptr::null_mut();
        unsafe {
            if let Err(e) = CredReadW(PCWSTR(t.as_ptr()), CRED_TYPE_GENERIC, None, &mut p) {
                if e.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Ok(None);
                }
                return Err(win_err(&format!("CredRead for '{target}'"), e));
            }
            let raw = raw_from(&*p);
            CredFree(p as *const c_void);
            Ok(Some(raw))
        }
    }

    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        // Credential Manager filters use '*' as the wildcard.
        let filter = wide(&format!("{prefix}*"));
        let mut count = 0u32;
        let mut items: *mut *mut CREDENTIALW = std::ptr::null_mut();
        unsafe {
            if let Err(e) = CredEnumerateW(PCWSTR(filter.as_ptr()), None, &mut count, &mut items) {
                if e.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Ok(vec![]);
                }
                return Err(win_err("CredEnumerate", e));
            }
            let list = (0..count as usize).map(|i| raw_from(&**items.add(i))).collect();
            CredFree(items as *const c_void);
            Ok(list)
        }
    }

    fn write(
        &self,
        target: &str,
        blob: &[u8],
        user_name: Option<&str>,
        comment: Option<&str>,
        attributes: &BTreeMap<String, String>,
    ) -> Result<()> {
        if blob.len() > CRED_MAX_BLOB {
            return Err(Error::msg(format!("Credential blob exceeds {CRED_MAX_BLOB} bytes.")));
        }
        let t = wide(target);
        let user = user_name.filter(|u| !u.is_empty()).map(wide);
        let note = comment.filter(|c| !c.is_empty()).map(wide);
        let mut blob_copy = Zeroizing::new(blob.to_vec());

        let attrs: Vec<(&String, &String)> = attributes.iter().filter(|(_, v)| !v.is_empty()).collect();
        let keywords: Vec<Vec<u16>> = attrs.iter().map(|(k, _)| wide(k)).collect();
        let mut values: Vec<Vec<u8>> = attrs.iter().map(|(_, v)| v.as_bytes().to_vec()).collect();
        if let Some((k, _)) = attrs.iter().zip(&values).find(|(_, v)| v.len() > CRED_MAX_VALUE).map(|(a, _)| a) {
            return Err(Error::msg(format!("Attribute '{k}' exceeds {CRED_MAX_VALUE} bytes.")));
        }
        let mut native: Vec<CREDENTIAL_ATTRIBUTEW> = keywords
            .iter()
            .zip(values.iter_mut())
            .map(|(k, v)| CREDENTIAL_ATTRIBUTEW {
                Keyword: PWSTR(k.as_ptr() as *mut u16),
                Flags: 0,
                ValueSize: v.len() as u32,
                Value: v.as_mut_ptr(),
            })
            .collect();

        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(t.as_ptr() as *mut u16),
            Comment: note.as_ref().map_or(PWSTR::null(), |n| PWSTR(n.as_ptr() as *mut u16)),
            CredentialBlobSize: blob_copy.len() as u32,
            CredentialBlob: blob_copy.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: native.len() as u32,
            Attributes: if native.is_empty() { std::ptr::null_mut() } else { native.as_mut_ptr() },
            UserName: user.as_ref().map_or(PWSTR::null(), |u| PWSTR(u.as_ptr() as *mut u16)),
            ..Default::default()
        };
        unsafe { CredWriteW(&cred, 0) }.map_err(|e| win_err(&format!("CredWrite for '{target}'"), e))
    }

    fn delete(&self, target: &str) -> Result<bool> {
        let t = wide(target);
        match unsafe { CredDeleteW(PCWSTR(t.as_ptr()), CRED_TYPE_GENERIC, None) } {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERROR_NOT_FOUND.to_hresult() => Ok(false),
            Err(e) => Err(win_err(&format!("CredDelete for '{target}'"), e)),
        }
    }
}

// ---------------------------------------------------------------------------- DPAPI

/// DPAPI for the current user (CryptProtectData, user scope).
struct Dpapi;

fn blob_of(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

unsafe fn take_blob(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
    std::ptr::write_bytes(out.pbData, 0, out.cbData as usize);
    let _ = LocalFree(Some(HLOCAL(out.pbData as *mut c_void)));
    v
}

impl DataProtector for Dpapi {
    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let input = blob_of(data);
        let ent = blob_of(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptProtectData(&input, PCWSTR::null(), Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
                .map_err(|e| win_err("DPAPI protect", e))?;
            Ok(take_blob(out))
        }
    }

    fn unprotect(&self, data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let input = blob_of(data);
        let ent = blob_of(entropy);
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptUnprotectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
                .map_err(|e| win_err("DPAPI unprotect", e))?;
            Ok(Zeroizing::new(take_blob(out)))
        }
    }
}

// ---------------------------------------------------------------------------- Windows Hello

/// Windows Hello (PIN, fingerprint or face) via UserConsentVerifier. Blocks until answered.
struct WindowsHello;

impl UserVerifier for WindowsHello {
    fn verify(&self, owner: isize, message: &str) -> (VerificationResult, Option<String>) {
        match hello(owner, message) {
            Ok(r) => r,
            Err(e) => (VerificationResult::Failed, Some(e.message().to_string())),
        }
    }
}

fn hello(owner: isize, message: &str) -> windows::core::Result<(VerificationResult, Option<String>)> {
    let availability = UserConsentVerifier::CheckAvailabilityAsync()?.join()?;
    if availability != UserConsentVerifierAvailability::Available {
        return Ok((VerificationResult::Unavailable, Some(availability_name(availability).into())));
    }

    // Desktop apps must parent the prompt to a window. A console's window works; under Windows
    // Terminal it is a hidden pseudo-window, so fall back to the foreground window.
    let mut hwnd = HWND(owner as *mut c_void);
    unsafe {
        if hwnd.is_invalid() {
            hwnd = GetConsoleWindow();
        }
        if hwnd.is_invalid() || !IsWindowVisible(hwnd).as_bool() {
            hwnd = GetForegroundWindow();
        }
    }
    let interop = windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let op: windows_future::IAsyncOperation<UserConsentVerificationResult> =
        unsafe { interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(message))? };
    let result = op.join()?;
    Ok(match result {
        UserConsentVerificationResult::Verified => (VerificationResult::Verified, None),
        UserConsentVerificationResult::Canceled => (VerificationResult::Canceled, None),
        UserConsentVerificationResult::DeviceNotPresent => (VerificationResult::Unavailable, Some("DeviceNotPresent".into())),
        UserConsentVerificationResult::NotConfiguredForUser => (VerificationResult::Unavailable, Some("NotConfiguredForUser".into())),
        UserConsentVerificationResult::DisabledByPolicy => (VerificationResult::Unavailable, Some("DisabledByPolicy".into())),
        UserConsentVerificationResult::DeviceBusy => (VerificationResult::Failed, Some("DeviceBusy".into())),
        UserConsentVerificationResult::RetriesExhausted => (VerificationResult::Failed, Some("RetriesExhausted".into())),
        _ => (VerificationResult::Failed, None),
    })
}

fn availability_name(a: UserConsentVerifierAvailability) -> &'static str {
    match a {
        UserConsentVerifierAvailability::DeviceNotPresent => "DeviceNotPresent",
        UserConsentVerifierAvailability::NotConfiguredForUser => "NotConfiguredForUser",
        UserConsentVerifierAvailability::DisabledByPolicy => "DisabledByPolicy",
        UserConsentVerifierAvailability::DeviceBusy => "DeviceBusy",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------- clipboard

/// Text marked so Windows keeps it out of clipboard history (Win+V) and cloud sync; cleared later
/// only if nothing else has been copied since (the sequence number is the token).
struct Clipboard;

fn open_clipboard() -> Result<()> {
    // Another process may briefly hold the clipboard open.
    for _ in 0..10 {
        if unsafe { OpenClipboard(None) }.is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Err(Error::msg("Couldn't open the clipboard."))
}

unsafe fn set_data(format: u32, data: &[u8]) -> Result<()> {
    let handle = GlobalAlloc(GMEM_MOVEABLE, data.len()).map_err(|e| win_err("GlobalAlloc", e))?;
    let target = GlobalLock(handle) as *mut u8;
    std::ptr::copy_nonoverlapping(data.as_ptr(), target, data.len());
    let _ = GlobalUnlock(handle);
    // On success the system owns the memory.
    if let Err(e) = SetClipboardData(format, Some(HANDLE(handle.0))) {
        let _ = GlobalFree(Some(HGLOBAL(handle.0)));
        return Err(win_err("SetClipboardData", e));
    }
    Ok(())
}

fn register(name: &str) -> u32 {
    let w = wide(name);
    unsafe { RegisterClipboardFormatW(PCWSTR(w.as_ptr())) }
}

impl SecureClipboard for Clipboard {
    fn set_text(&self, text: &str) -> Result<u32> {
        open_clipboard()?;
        let result = (|| unsafe {
            EmptyClipboard().map_err(|e| win_err("EmptyClipboard", e))?;
            let utf16 = Zeroizing::new(wide(text).iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>());
            set_data(CF_UNICODETEXT.0 as u32, &utf16)?;
            set_data(register("ExcludeClipboardContentFromMonitorProcessing"), &[0])?;
            set_data(register("CanIncludeInClipboardHistory"), &0u32.to_le_bytes())?;
            set_data(register("CanUploadToCloudClipboard"), &0u32.to_le_bytes())
        })();
        unsafe {
            let _ = CloseClipboard();
        }
        result?;
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    fn clear_if_unchanged(&self, token: u32) -> bool {
        if unsafe { GetClipboardSequenceNumber() } != token || open_clipboard().is_err() {
            return false;
        }
        let cleared = unsafe { GetClipboardSequenceNumber() == token && EmptyClipboard().is_ok() };
        unsafe {
            let _ = CloseClipboard();
        }
        cleared
    }
}

// ---------------------------------------------------------------------------- process ancestry

/// Parent chain from a Toolhelp32 snapshot. Windows reuses process ids, so a "parent" that started
/// after its child is an unrelated process and ends the chain.
struct Toolhelp;

fn start_time(pid: u32) -> Option<i64> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let (mut c, mut e, mut k, mut u) = Default::default();
        let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u).is_ok();
        let _ = CloseHandle(h);
        let c: FILETIME = c;
        ok.then(|| ((c.dwHighDateTime as i64) << 32) | c.dwLowDateTime as i64)
    }
}

fn snapshot() -> HashMap<u32, (u32, String)> {
    let mut map = HashMap::new();
    unsafe {
        let Ok(h) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return map };
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        if Process32FirstW(h, &mut entry).is_ok() {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                map.insert(entry.th32ProcessID, (entry.th32ParentProcessID, String::from_utf16_lossy(&entry.szExeFile[..len])));
                if Process32NextW(h, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(h);
    }
    map
}

impl ProcessAncestry for Toolhelp {
    fn current(&self, max_depth: usize) -> Vec<AncestorProcess> {
        let snap = snapshot();
        let mut chain = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut pid = std::process::id();
        let mut child_started = start_time(pid);
        for _ in 0..max_depth {
            let Some(&(parent, _)) = snap.get(&pid) else { break };
            if !seen.insert(pid) || parent == 0 {
                break;
            }
            let Some((_, name)) = snap.get(&parent) else { break };
            let parent_started = start_time(parent);
            match (parent_started, child_started) {
                (Some(p), Some(c)) if p <= c => {}
                _ => break,
            }
            chain.push(AncestorProcess { process_id: parent, executable_name: name.clone() });
            pid = parent;
            child_started = parent_started;
        }
        chain
    }
}

#[allow(dead_code)]
fn last_error() -> String {
    format!("{:?}", unsafe { GetLastError() })
}

// ---------------------------------------------------------------------------- screen lock

/// While Windows shows the lock screen (or the session is disconnected), the input desktop is the
/// secure Winlogon desktop, which a user process can't open.
pub fn is_screen_locked() -> bool {
    use windows::Win32::System::StationsAndDesktops::{CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_SWITCHDESKTOP};
    unsafe {
        match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_SWITCHDESKTOP) {
            Ok(desk) => {
                let _ = CloseDesktop(desk);
                false
            }
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Credential Manager stand-in: an in-memory list.
    #[derive(Default)]
    struct Memory(Mutex<Vec<RawCredential>>);

    impl CredentialStore for Memory {
        fn max_blob_bytes(&self) -> usize {
            2560
        }
        fn max_attribute_bytes(&self) -> usize {
            256
        }
        fn max_attributes(&self) -> usize {
            64
        }
        fn read(&self, target: &str) -> Result<Option<RawCredential>> {
            Ok(self.0.lock().unwrap().iter().find(|c| c.target == target).cloned())
        }
        fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
            Ok(self.0.lock().unwrap().iter().filter(|c| c.target.starts_with(prefix)).cloned().collect())
        }
        fn write(&self, _: &str, _: &[u8], _: Option<&str>, _: Option<&str>, _: &BTreeMap<String, String>) -> Result<()> {
            unreachable!()
        }
        fn delete(&self, target: &str) -> Result<bool> {
            let mut v = self.0.lock().unwrap();
            let before = v.len();
            v.retain(|c| c.target != target);
            Ok(v.len() != before)
        }
    }

    fn cred(target: &str, value: &str, days_ago: i64) -> RawCredential {
        RawCredential {
            target: target.into(),
            user_name: Some("octocat".into()),
            comment: Some("notes".into()),
            last_written: Utc::now() - chrono::Duration::days(days_ago),
            blob: Zeroizing::new(value.as_bytes().to_vec()),
            attributes: BTreeMap::from([("category".to_string(), "dev".to_string()), ("empty".to_string(), String::new())]),
        }
    }

    fn temp_vault(name: &str) -> (std::path::PathBuf, SqliteVault) {
        let dir = std::env::temp_dir().join(format!("keylo-winvault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("keylo.db");
        (dir, SqliteVault::new(path, Box::new(DpapiKey)))
    }

    #[test]
    fn moves_credential_manager_items_into_a_dpapi_vault() {
        let (dir, vault) = temp_vault("move");
        let legacy = Memory::default();
        legacy.0.lock().unwrap().extend([cred("Test:a", "one", 5), cred("Test:b", "two", 4), cred("Other:c", "not mine", 1)]);

        move_from_credential_manager(&vault, &legacy, "Test:").unwrap();
        // Ours moved (values, details and times kept); someone else's left alone.
        let left: Vec<String> = legacy.0.lock().unwrap().iter().map(|c| c.target.clone()).collect();
        assert_eq!(left, vec!["Other:c".to_string()]);
        let a = vault.read("Test:a").unwrap().unwrap();
        assert_eq!(a.blob.as_slice(), b"one");
        assert_eq!(a.user_name.as_deref(), Some("octocat"));
        assert_eq!(a.attribute("category"), Some("dev"));
        assert_eq!(vault.enumerate("Test:").unwrap().len(), 2);

        // Another process opens the same vault with DPAPI.
        let again = SqliteVault::new(dir.join("keylo.db"), Box::new(DpapiKey));
        assert_eq!(again.read("Test:b").unwrap().unwrap().blob.as_slice(), b"two");
        drop(again);
        drop(vault);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_secrets_only_move_into_the_real_vault() {
        assert!(migrates_for(None, None)); // the default data folder
        assert!(migrates_for(Some(""), None));
        assert!(!migrates_for(Some("C:/tmp/experiment"), None)); // a throwaway folder: never the real Keylo: items
        assert!(!migrates_for(Some("C:/tmp/experiment"), Some("")));
        assert!(migrates_for(Some("C:/tmp/test"), Some("KeyloTest:"))); // a test with its own prefix
    }

    #[test]
    fn an_older_credential_manager_copy_never_replaces_the_vaults() {
        let (dir, vault) = temp_vault("newer");
        let fresh = cred("Test:a", "fresh", 0);
        vault.import(std::slice::from_ref(&fresh)).unwrap();
        let legacy = Memory::default();
        legacy.0.lock().unwrap().push(cred("Test:a", "stale", 9));
        move_from_credential_manager(&vault, &legacy, "Test:").unwrap();
        assert_eq!(vault.read("Test:a").unwrap().unwrap().blob.as_slice(), b"fresh");
        // The stale original is still removed: the vault's copy is newer.
        assert!(legacy.0.lock().unwrap().is_empty());
        drop(vault);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
