//! "NAME", "NAME:FIELD", "NAME@ENV" and "NAME@ENV:FIELD" references to secrets. Names may contain
//! ':' and '@', so an exact secret name always wins.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretReference {
    pub name: String,
    pub environment: Option<String>,
    pub field: Option<String>,
}

impl SecretReference {
    /// The name with its environment, for approvals and the audit log: "orders-db@prod".
    pub fn display(&self) -> String {
        match &self.environment {
            Some(e) => format!("{}@{e}", self.name),
            None => self.name.clone(),
        }
    }

    pub fn parse(text: &str, exists: impl Fn(&str) -> bool) -> Option<SecretReference> {
        let text = text.trim();
        if exists(text) {
            return Some(SecretReference { name: text.into(), environment: None, field: None });
        }
        if let Some(r) = split_environment(text, &exists) {
            return Some(r);
        }
        let colon = text.rfind(':')?;
        if colon == 0 || colon == text.len() - 1 {
            return None;
        }
        let (head, field) = (&text[..colon], &text[colon + 1..]);
        if exists(head) {
            return Some(SecretReference { name: head.into(), environment: None, field: Some(field.into()) });
        }
        split_environment(head, &exists).map(|r| SecretReference { field: Some(field.into()), ..r })
    }
}

fn split_environment(text: &str, exists: &impl Fn(&str) -> bool) -> Option<SecretReference> {
    let at = text.rfind('@')?;
    if at == 0 || at == text.len() - 1 {
        return None;
    }
    let (name, env) = (&text[..at], &text[at + 1..]);
    (is_valid_environment_name(env) && exists(name))
        .then(|| SecretReference { name: name.into(), environment: Some(env.into()), field: None })
}

pub fn is_valid_environment_name(name: &str) -> bool {
    (1..=32).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Linked secrets (type "link") point at items in 1Password or AWS Secrets Manager.
pub const LINK_TYPE: &str = "link";

pub fn is_linked(info: &crate::secrets::SecretInfo) -> bool {
    info.type_id.as_deref() == Some(LINK_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_name_wins_then_field_then_environment() {
        let names = ["a:b", "db", "orders"];
        let exists = |n: &str| names.contains(&n);
        assert_eq!(SecretReference::parse("a:b", exists).unwrap().field, None);
        let r = SecretReference::parse("db:password", exists).unwrap();
        assert_eq!((r.name.as_str(), r.field.as_deref()), ("db", Some("password")));
        let r = SecretReference::parse("orders@uat:password", exists).unwrap();
        assert_eq!((r.environment.as_deref(), r.field.as_deref()), (Some("uat"), Some("password")));
        assert!(SecretReference::parse("missing", exists).is_none());
    }
}
