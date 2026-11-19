//! Windows Hello (or a FIDO2 security key) as a key source, through WebAuthn's `hmac-secret`/PRF
//! extension. A credential is enrolled once ([`enroll`]); unlocking ([`derive`]) asks the
//! authenticator, after the user's Hello gesture, for a 32-byte secret that is stable for
//! (credential, salt). That secret wraps the vault key, so the vault opens with a gesture and no
//! typed passphrase, and the secret is bound to the TPM/authenticator — it can't be taken at rest.
//!
//! The gesture needs a foreground window, so only the app drives this; the CLI and MCP server ride
//! the shared session the app's unlock leaves behind.

use std::ffi::c_void;

use keylo_core::{bail, Error, Result};
use windows::core::{w, BOOL, PCWSTR};
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, IsWindowVisible};

/// The WebAuthn relying-party id Keylo enrols under. Not a network name; it just scopes the
/// credential to Keylo on this machine.
const RP_ID: PCWSTR = w!("keylo.vault.local");
/// Fixed client data (no signature is verified; the PRF output is what Keylo uses).
const CLIENT_DATA: &[u8] = b"{\"type\":\"keylo.vault\",\"origin\":\"keylo\"}";

/// Whether this Windows build supports the PRF/hmac-secret salts at assertion (API v4+).
pub fn available() -> bool {
    unsafe { WebAuthNGetApiVersionNumber() >= WEBAUTHN_API_VERSION_4 }
}

/// A foreground window for the Hello prompt; the app passes its own, else fall back.
fn window(owner: isize) -> HWND {
    let mut hwnd = HWND(owner as *mut c_void);
    unsafe {
        if hwnd.is_invalid() || !IsWindowVisible(hwnd).as_bool() {
            hwnd = GetConsoleWindow();
        }
        if hwnd.is_invalid() || !IsWindowVisible(hwnd).as_bool() {
            hwnd = GetForegroundWindow();
        }
    }
    hwnd
}

fn client_data() -> WEBAUTHN_CLIENT_DATA {
    WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: CLIENT_DATA.len() as u32,
        pbClientDataJSON: CLIENT_DATA.as_ptr() as *mut u8,
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    }
}

/// Enrols a Keylo credential with the hmac-secret extension and returns its credential id. The user
/// is asked for the Hello gesture.
pub fn enroll(owner: isize) -> Result<Vec<u8>> {
    if !available() {
        bail!("Windows Hello's security-key feature (WebAuthn hmac-secret) isn't available on this version of Windows.");
    }
    let hwnd = window(owner);
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: RP_ID,
        pwszName: w!("Keylo"),
        pwszIcon: PCWSTR::null(),
    };
    let mut user_id = *b"keylo-vault-user";
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: w!("Keylo vault"),
        pwszIcon: PCWSTR::null(),
        pwszDisplayName: w!("Keylo vault"),
    };
    let mut cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    };
    let cose_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS { cCredentialParameters: 1, pCredentialParameters: &mut cose };
    let client = client_data();

    let mut hmac_on: BOOL = BOOL(1);
    let mut ext = WEBAUTHN_EXTENSION {
        pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
        cbExtension: std::mem::size_of::<BOOL>() as u32,
        pvExtension: &mut hmac_on as *mut BOOL as *mut c_void,
    };
    let opts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3,
        dwTimeoutMilliseconds: 60_000,
        Extensions: WEBAUTHN_EXTENSIONS { cExtensions: 1, pExtensions: &mut ext },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        ..Default::default()
    };

    unsafe {
        let att = WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &cose_params, &client, Some(&opts))
            .map_err(|e| Error::msg(format!("Windows Hello enrolment failed: {}", e.message())))?;
        let a = &*att;
        if a.cbCredentialId == 0 || a.pbCredentialId.is_null() {
            WebAuthNFreeCredentialAttestation(Some(att));
            bail!("Windows Hello didn't return a credential.");
        }
        let cred = std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
        WebAuthNFreeCredentialAttestation(Some(att));
        Ok(cred)
    }
}

/// Asks the authenticator for the 32-byte PRF secret for (`cred_id`, `salt`), after the Hello
/// gesture. Stable across calls, so it can wrap the vault key.
pub fn derive(owner: isize, cred_id: &[u8], salt: &[u8; 32]) -> Result<[u8; 32]> {
    if !available() {
        bail!("Windows Hello's security-key feature isn't available on this version of Windows.");
    }
    let hwnd = window(owner);
    let client = client_data();

    let mut cred_id = cred_id.to_vec();
    let mut cred_ex = WEBAUTHN_CREDENTIAL_EX {
        dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
        cbId: cred_id.len() as u32,
        pbId: cred_id.as_mut_ptr(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        dwTransports: 0,
    };
    let mut pcred: *mut WEBAUTHN_CREDENTIAL_EX = &mut cred_ex;
    let allow = WEBAUTHN_CREDENTIAL_LIST { cCredentials: 1, ppCredentials: &mut pcred };

    let mut salt = *salt;
    let mut hmac_salt = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: salt.len() as u32,
        pbFirst: salt.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: std::ptr::null_mut(),
    };
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &mut hmac_salt,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: std::ptr::null_mut(),
    };
    let opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
        dwTimeoutMilliseconds: 60_000,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        pAllowCredentialList: &allow as *const _ as *mut WEBAUTHN_CREDENTIAL_LIST,
        pHmacSecretSaltValues: &mut salt_values,
        ..Default::default()
    };

    unsafe {
        let assertion = WebAuthNAuthenticatorGetAssertion(hwnd, RP_ID, &client, Some(&opts))
            .map_err(|e| Error::msg(format!("Windows Hello unlock failed: {}", e.message())))?;
        let a = &*assertion;
        if a.pHmacSecret.is_null() {
            WebAuthNFreeAssertion(assertion);
            bail!("Windows Hello didn't return the hmac-secret (the authenticator may not support it).");
        }
        let hs = &*a.pHmacSecret;
        if hs.cbFirst != 32 || hs.pbFirst.is_null() {
            WebAuthNFreeAssertion(assertion);
            bail!("Windows Hello returned an unexpected hmac-secret length.");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(std::slice::from_raw_parts(hs.pbFirst, 32));
        WebAuthNFreeAssertion(assertion);
        Ok(out)
    }
}

/// Enrols, then derives twice with a fixed salt, to check Hello PRF works and is stable on this
/// machine. For `keylo __hello-selftest`. Leaves one Keylo passkey behind.
pub fn selftest() -> Result<String> {
    if !available() {
        return Ok(format!("Windows Hello PRF: not available (WebAuthn API version {}; need 4+).", unsafe {
            WebAuthNGetApiVersionNumber()
        }));
    }
    let cred = enroll(0)?;
    let salt = [7u8; 32];
    let a = derive(0, &cred, &salt)?;
    let b = derive(0, &cred, &salt)?;
    if a != b {
        bail!("Windows Hello PRF is available but not stable (two reads differed); it can't be used to protect the vault.");
    }
    let other = derive(0, &cred, &[9u8; 32])?;
    let distinct = other != a;
    Ok(format!(
        "Windows Hello PRF works: credential {} bytes, secret stable across reads, and a different salt gives a {} secret. \
         You can remove the test passkey in Settings → Accounts → Passkeys ({}).",
        cred.len(),
        if distinct { "different" } else { "SAME (unexpected)" },
        "keylo.vault.local"
    ))
}
