//! Searching secrets by their details, never their values.

use crate::secrets::SecretInfo;
use crate::{contains_ic, eq_ic};

fn has(field: Option<&str>, term: &str) -> bool {
    field.is_some_and(|f| contains_ic(f, term))
}

/// Every whitespace-separated term must match the name, category, username, notes, type or a
/// non-secret field. "cat:cloud" only matches the category, "type:login" only the type id.
pub fn matches(s: &SecretInfo, query: Option<&str>) -> bool {
    let Some(q) = query.filter(|q| !q.trim().is_empty()) else { return true };
    for term in q.split_whitespace() {
        let lower = term.to_lowercase();
        if let Some(cat) = lower.strip_prefix("cat:") {
            if !has(s.category.as_deref(), cat) {
                return false;
            }
            continue;
        }
        if let Some(t) = lower.strip_prefix("type:") {
            if !has(s.type_id.as_deref(), t) {
                return false;
            }
            continue;
        }
        let hit = contains_ic(&s.name, term)
            || has(s.category.as_deref(), term)
            || has(s.username.as_deref(), term)
            || has(s.notes.as_deref(), term)
            || has(s.type_id.as_deref(), term)
            || s.fields.values().any(|v| contains_ic(v, term));
        if !hit {
            return false;
        }
    }
    true
}

pub fn filter<'a>(secrets: &'a [SecretInfo], query: Option<&str>, category: Option<&str>) -> Vec<&'a SecretInfo> {
    secrets
        .iter()
        .filter(|s| category.is_none_or(|c| s.category.as_deref().is_some_and(|sc| eq_ic(sc, c))) && matches(s, query))
        .collect()
}
