//! Guesses a secret type for an imported file from its name, extension and (text) content. Only
//! confident guesses are made; anything else stays a plain secret, which is always safe. The same
//! rules as the C# build's SecretTypeInference.

use std::collections::BTreeMap;
use std::collections::HashSet;

use crate::types::decode_text;

const MAX_TEXT_BYTES: usize = 64 * 1024;

/// A guessed type and the value split into that type's fields.
#[derive(Debug, Clone)]
pub struct InferredType {
    pub type_id: String,
    pub fields: BTreeMap<String, String>,
}

fn guess(type_id: &str, fields: &[(&str, String)]) -> Option<InferredType> {
    Some(InferredType { type_id: type_id.into(), fields: fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() })
}

/// "notes.txt" → ("notes", ".txt"); ".env" → ("", ".env"), as .NET's Path does.
pub fn split_file_name(path: &str) -> (String, String) {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match file.rfind('.') {
        Some(dot) => (file[..dot].to_string(), file[dot..].to_string()),
        None => (file.to_string(), String::new()),
    }
}

/// The type to use for `file_name` with `content`, or None for plain.
pub fn infer(file_name: &str, content: &[u8]) -> Option<InferredType> {
    if content.is_empty() || content.len() > MAX_TEXT_BYTES {
        return None;
    }
    let text = decode_text(content)?;
    if text.contains('\0') {
        return None;
    }
    let (stem, extension) = split_file_name(file_name);
    let name = stem.to_lowercase();
    let extension = extension.to_lowercase();
    let value = text.trim();
    if value.is_empty() || matches!(extension.as_str(), ".pub" | ".crt" | ".cer") {
        return None;
    }

    // SSH / PEM private keys, by content.
    let key = || format!("{}\n", text.trim_end());
    if is_private_key(value) {
        return guess("ssh_key", &[("private_key", key())]);
    }
    if matches!(name.as_str(), "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa") && value.contains("PRIVATE KEY") {
        return guess("ssh_key", &[("private_key", key())]);
    }

    let single_line = !value.contains('\n');
    let words = words(&name);
    let any = |list: &[&str]| list.iter().any(|w| words.contains(*w));

    // Database: a connection URL or string, by content; or a db-ish name.
    if single_line {
        if let Some(fields) = parse_database_url(value) {
            return Some(InferredType { type_id: "database".into(), fields });
        }
        if is_sql_server_string(value) {
            return guess("database", &[("engine", "sqlserver".into()), ("connection_string", value.into())]);
        }
        if any(&["db", "database", "conn", "connection", "dsn", "postgres", "mysql", "mongo", "mongodb", "redis"]) {
            return guess("database", &[("connection_string", value.into())]);
        }
    }
    if !single_line {
        return None;
    }
    if any(&["password", "passwd", "pwd", "pass", "login"]) {
        return guess("login", &[("password", value.into())]);
    }
    if any(&["token", "apikey", "secret", "pat", "key", "bearer"]) || name.contains("api_key") || name.contains("api-key") {
        return guess("api_key", &[("secret", value.into())]);
    }
    None
}

/// "-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"…
fn is_private_key(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("-----BEGIN ") else { return false };
    if rest.starts_with("PRIVATE KEY-----") {
        return true;
    }
    let word: String = rest.chars().take_while(char::is_ascii_uppercase).collect();
    !word.is_empty() && rest[word.len()..].starts_with(" PRIVATE KEY-----")
}

/// "Server=…;…Password=…" (or Data Source / Pwd), as SQL Server connection strings are.
fn is_sql_server_string(value: &str) -> bool {
    let lower = value.to_lowercase();
    let Some(rest) = lower.strip_prefix("server=").or_else(|| lower.strip_prefix("data source=")) else { return false };
    match rest.find(';') {
        Some(semi) if semi > 0 => {
            let after = &rest[semi + 1..];
            after.contains("password=") || after.contains("pwd=")
        }
        _ => false,
    }
}

/// "github-api_token.prod" → {github, api, token, prod}.
fn words(name: &str) -> HashSet<String> {
    name.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).filter(|w| !w.is_empty()).map(str::to_string).collect()
}

fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// "postgres://user:pass@host:5432/app" → engine, host, port, database, username, password, connection_string.
pub fn parse_database_url(value: &str) -> Option<BTreeMap<String, String>> {
    let (scheme, rest) = value.split_once("://")?;
    let engine = match scheme.to_lowercase().as_str() {
        "postgres" | "postgresql" => "postgres",
        "mysql" | "mariadb" => "mysql",
        "mongodb" | "mongodb+srv" => "mongodb",
        "redis" | "rediss" => "redis",
        "sqlserver" | "mssql" => "sqlserver",
        _ => return None,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (user_info, host_port) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    // .NET's Uri rejects a host list ("h1,h2") and spaces; so do we.
    if host_port.contains([',', ' ']) {
        return None;
    }
    let (host, port) = match host_port.rfind(':') {
        Some(colon) if !host_port[colon..].contains(']') => {
            let port = &host_port[colon + 1..];
            if !port.is_empty() && !port.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            (&host_port[..colon], Some(port).filter(|p| !p.is_empty()))
        }
        _ => (host_port, None),
    };

    let mut fields = BTreeMap::new();
    fields.insert("engine".to_string(), engine.to_string());
    fields.insert("connection_string".to_string(), value.to_string());
    if !host.is_empty() {
        fields.insert("host".into(), host.to_string());
    }
    if let Some(p) = port.and_then(|p| p.parse::<u16>().ok()).filter(|p| *p > 0) {
        fields.insert("port".into(), p.to_string());
    }
    let path = tail.split(['?', '#']).next().unwrap_or("").trim_matches('/');
    if !path.is_empty() {
        fields.insert("database".into(), unescape(path));
    }
    if let Some(info) = user_info.filter(|u| !u.is_empty()) {
        let mut parts = info.splitn(2, ':');
        fields.insert("username".into(), unescape(parts.next().unwrap_or("")));
        if let Some(p) = parts.next() {
            fields.insert("password".into(), unescape(p));
        }
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_of(file: &str, content: &str) -> Option<String> {
        infer(file, content.as_bytes()).map(|t| t.type_id)
    }

    #[test]
    fn confident_guesses() {
        let cases = [
            ("id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n", "ssh_key"),
            ("server.pem", "-----BEGIN RSA PRIVATE KEY-----\nabc\n", "ssh_key"),
            ("db.env", "postgres://alice:p%40ss@db.local:5432/app", "database"),
            ("anything", "Server=sql1;Database=x;User Id=a;Password=b;", "database"),
            ("prod-db", "some-opaque-string", "database"),
            ("router-password.txt", "hunter2", "login"),
            ("github-token", "ghp_abc123", "api_key"),
            ("stripe_api_key.txt", "sk_test_123", "api_key"),
        ];
        for (file, content, expected) in cases {
            assert_eq!(type_of(file, content).as_deref(), Some(expected), "{file}");
        }
    }

    #[test]
    fn everything_else_stays_plain() {
        for (file, content) in [
            ("id_ed25519.pub", "ssh-ed25519 AAAA… me@host"),
            ("notes.txt", "remember the milk"),
            ("github-token", "line one\nline two"),
            ("cert.crt", "-----BEGIN CERTIFICATE-----"),
            ("keyboard-layout", "us"),
        ] {
            assert_eq!(type_of(file, content), None, "{file}");
        }
        assert!(infer("token.bin", &[0xff, 0xfe, 0x00, 0x01]).is_none());
    }

    #[test]
    fn database_urls_are_split_into_fields() {
        let f = parse_database_url("postgresql://alice:p%40ss@db.local:5432/app").unwrap();
        let get = |k: &str| f.get(k).map(String::as_str);
        assert_eq!(
            (get("engine"), get("host"), get("port"), get("database"), get("username"), get("password")),
            (Some("postgres"), Some("db.local"), Some("5432"), Some("app"), Some("alice"), Some("p@ss"))
        );
    }

    #[test]
    fn file_names_split_like_dotnet() {
        assert_eq!(split_file_name("dir/.env"), (String::new(), ".env".into()));
        assert_eq!(split_file_name("a.b.txt"), ("a.b".into(), ".txt".into()));
        assert_eq!(split_file_name("token"), ("token".into(), String::new()));
    }
}
