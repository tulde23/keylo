//! Time-based one-time codes (TOTP, RFC 6238): the 6-digit codes of authenticator apps.
//!
//! A one-time code field stores the setup key a site shows when you turn on two-factor sign-in:
//! either an `otpauth://totp/...` link (what its QR code holds) or the key itself, in base32
//! ("JBSW Y3DP EHPK 3PXP"). Wherever the field's value is used (copy, `keylo get`, an agent's
//! command), the current code is used instead; the key itself is only shown when editing.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::{bail, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// Never prints the key.
impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// A code and how long it stays valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub code: String,
    pub seconds_left: u64,
    pub period: u64,
}

impl Totp {
    /// An `otpauth://totp/...` link or a base32 key (spaces, dashes and case don't matter).
    pub fn parse(text: &str) -> Result<Totp> {
        let text = text.trim();
        if text.is_empty() {
            bail!("Enter the setup key or otpauth:// link.");
        }
        if text.len() >= 10 && text[..10].eq_ignore_ascii_case("otpauth://") {
            return parse_uri(text);
        }
        Ok(Totp { secret: decode_base32(text)?, algorithm: Algorithm::Sha1, digits: 6, period: 30, issuer: None, account: None })
    }

    /// The code for a Unix time.
    pub fn code_at(&self, unix_seconds: u64) -> String {
        let counter = (unix_seconds / self.period).to_be_bytes();
        macro_rules! mac {
            ($d:ty) => {{
                let mut m = <Hmac<$d> as Mac>::new_from_slice(&self.secret).expect("any key length");
                m.update(&counter);
                m.finalize().into_bytes().to_vec()
            }};
        }
        let hash = match self.algorithm {
            Algorithm::Sha1 => mac!(sha1::Sha1),
            Algorithm::Sha256 => mac!(sha2::Sha256),
            Algorithm::Sha512 => mac!(sha2::Sha512),
        };
        // Dynamic truncation (RFC 4226 §5.3).
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([hash[offset] & 0x7f, hash[offset + 1], hash[offset + 2], hash[offset + 3]]);
        let code = binary as u64 % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// The code now.
    pub fn now(&self) -> Code {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Code { code: self.code_at(t), seconds_left: self.period - t % self.period, period: self.period }
    }

    /// As an otpauth:// link (what 1Password and authenticator apps import).
    pub fn to_uri(&self, label: &str) -> String {
        let alg = match self.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        };
        let label = self.account.as_deref().unwrap_or(label);
        let mut uri = format!(
            "otpauth://totp/{}?secret={}&algorithm={alg}&digits={}&period={}",
            percent_encode(label),
            encode_base32(&self.secret),
            self.digits,
            self.period
        );
        if let Some(i) = &self.issuer {
            uri += &format!("&issuer={}", percent_encode(i));
        }
        uri
    }
}

fn parse_uri(uri: &str) -> Result<Totp> {
    let rest = &uri[10..];
    let (kind, rest) = rest.split_once('/').ok_or_else(|| Error::msg("That otpauth:// link isn't complete."))?;
    if kind.eq_ignore_ascii_case("hotp") {
        bail!("That's a counter-based (HOTP) code; Keylo supports time-based (TOTP) codes, which almost every site uses.");
    }
    if !kind.eq_ignore_ascii_case("totp") {
        bail!("That isn't an otpauth://totp/ link.");
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(label);
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None => (None, label.trim().to_string()),
    };

    let mut secret = None;
    let mut totp = Totp { secret: Zeroizing::new(Vec::new()), algorithm: Algorithm::Sha1, digits: 6, period: 30, issuer: label_issuer, account: None };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_base32(&v)?),
            "issuer" if !v.trim().is_empty() => totp.issuer = Some(v.trim().to_string()),
            "algorithm" => {
                totp.algorithm = match v.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => bail!("Unsupported algorithm '{other}' (SHA1, SHA256 or SHA512)."),
                }
            }
            "digits" => {
                totp.digits = v.parse().ok().filter(|d| (6..=8).contains(d)).ok_or_else(|| Error::msg("Codes have 6 to 8 digits."))?;
            }
            "period" => {
                totp.period = v.parse().ok().filter(|p| (1..=300).contains(p)).ok_or_else(|| Error::msg("The period must be 1 to 300 seconds."))?;
            }
            _ => {}
        }
    }
    totp.secret = secret.ok_or_else(|| Error::msg("That otpauth:// link has no secret."))?;
    totp.account = Some(account).filter(|a| !a.is_empty());
    Ok(totp)
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn decode_base32(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut bits, mut count, mut chars) = (0u64, 0u32, 0usize);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=') {
        let v = BASE32
            .iter()
            .position(|&x| x as char == c.to_ascii_uppercase())
            .ok_or_else(|| Error::msg("That isn't a setup key: keys use the letters A–Z and digits 2–7, or paste the otpauth:// link."))?;
        bits = (bits << 5) | v as u64;
        count += 5;
        chars += 1;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if chars < 16 || out.len() < 10 {
        bail!("That setup key is too short (keys are at least 16 characters).");
    }
    Ok(out)
}

fn encode_base32(data: &[u8]) -> String {
    let (mut bits, mut count) = (0u64, 0u32);
    let mut out = String::new();
    for &b in data {
        bits = (bits << 8) | b as u64;
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(BASE32[((bits >> count) & 31) as usize] as char);
        }
        bits &= (1 << count) - 1;
    }
    if count > 0 {
        out.push(BASE32[((bits << (5 - count)) & 31) as usize] as char);
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"), 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'@') { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(secret: &[u8], algorithm: Algorithm) -> Totp {
        Totp { secret: Zeroizing::new(secret.to_vec()), algorithm, digits: 8, period: 30, issuer: None, account: None }
    }

    #[test]
    fn rfc_6238_test_vectors() {
        let sha1 = with(b"12345678901234567890", Algorithm::Sha1);
        let sha256 = with(b"12345678901234567890123456789012", Algorithm::Sha256);
        let sha512 = with(b"1234567890123456789012345678901234567890123456789012345678901234", Algorithm::Sha512);
        for (t, a, b, c) in [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(sha1.code_at(t), a, "SHA1 at {t}");
            assert_eq!(sha256.code_at(t), b, "SHA256 at {t}");
            assert_eq!(sha512.code_at(t), c, "SHA512 at {t}");
        }
    }

    #[test]
    fn keys_and_links_parse() {
        // "12345678901234567890" in base32, as an authenticator app shows it.
        let key = "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ";
        let t = Totp::parse(&key.to_lowercase()).unwrap();
        assert_eq!((t.digits, t.period, t.algorithm), (6, 30, Algorithm::Sha1));
        assert_eq!(t.code_at(59), "287082");

        let t = Totp::parse("otpauth://totp/GitHub:octo%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(t.issuer.as_deref(), Some("GitHub"));
        assert_eq!(t.account.as_deref(), Some("octo@example.com"));
        assert_eq!((t.digits, t.period, t.algorithm), (8, 60, Algorithm::Sha256));

        let back = Totp::parse(&t.to_uri("x")).unwrap();
        assert_eq!(back.code_at(1234567890), t.code_at(1234567890));
        assert_eq!(back.account.as_deref(), Some("octo@example.com"));
    }

    #[test]
    fn bad_input_is_explained() {
        assert!(Totp::parse("").is_err());
        assert!(Totp::parse("hunter2").is_err());
        assert!(Totp::parse("GEZDGNBV").is_err(), "too short");
        assert!(Totp::parse("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1").unwrap_err().to_string().contains("HOTP"));
        assert!(Totp::parse("otpauth://totp/x?issuer=a").is_err(), "no secret");
        assert!(Totp::parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=12").is_err());
    }

    #[test]
    fn the_code_now_counts_down() {
        let c = Totp::parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap().now();
        assert_eq!(c.code.len(), 6);
        assert!((1..=30).contains(&c.seconds_left));
    }
}
