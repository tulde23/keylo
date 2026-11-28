//! The "headless access" plan: which secrets the user chose to publish into the headless vault file
//! (`headless-vault.json`) for use over SSH, and whether to keep each one in sync. This is intent
//! metadata — a plain file (`headless.json`) — not a store: the secret values themselves are only
//! ever written into the headless vault by a publish, never kept here. The file records just a name,
//! a content hash from the last publish (so drift can be shown without the value), and the
//! keep-in-sync choice.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::platform::RawCredential;
use crate::{eq_ic, paths, Result};

/// One secret chosen for headless access.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadlessEntry {
    /// The secret's display name (its store target without the prefix).
    pub name: String,
    /// The [`content_hash`] recorded at the last publish; empty when never published yet.
    #[serde(default)]
    pub published_hash: String,
    /// Re-publish this secret automatically when the main vault's copy changes.
    #[serde(default)]
    pub keep_in_sync: bool,
}

/// How a chosen secret stands relative to what was last published into the headless vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HeadlessState {
    /// Chosen but never published yet.
    Pending,
    /// Published, and unchanged in the main vault since.
    InSync,
    /// The main vault's copy changed since it was last published — a re-publish is due.
    Drifted,
    /// Chosen, but the secret no longer exists in the main vault.
    Missing,
}

/// A stable hash of everything a publish writes for one secret, so drift (a changed value or
/// published detail) can be detected without keeping the value here. Deliberately excludes
/// `last_written`, which changes on every save even when nothing else did, and is length-prefixed so
/// no concatenation of fields can collide with a different split.
pub fn content_hash(c: &RawCredential) -> String {
    let mut h = Sha256::new();
    let field = |h: &mut Sha256, b: &[u8]| {
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    };
    field(&mut h, &c.blob);
    field(&mut h, c.user_name.as_deref().unwrap_or("").as_bytes());
    field(&mut h, c.comment.as_deref().unwrap_or("").as_bytes());
    // attributes is a BTreeMap, so iteration order is already canonical.
    h.update((c.attributes.len() as u64).to_le_bytes());
    for (k, v) in &c.attributes {
        field(&mut h, k.as_bytes());
        field(&mut h, v.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Classifies a chosen entry against the main vault's current copy (`None` if it's gone).
pub fn classify(entry: &HeadlessEntry, current: Option<&RawCredential>) -> HeadlessState {
    match current {
        None => HeadlessState::Missing,
        Some(_) if entry.published_hash.is_empty() => HeadlessState::Pending,
        Some(c) if content_hash(c) == entry.published_hash => HeadlessState::InSync,
        Some(_) => HeadlessState::Drifted,
    }
}

/// The chosen set, persisted to `headless.json`.
pub struct HeadlessPlan {
    path: PathBuf,
    entries: Vec<HeadlessEntry>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PlanFile {
    #[serde(default)]
    secrets: Vec<HeadlessEntry>,
}

impl Default for HeadlessPlan {
    fn default() -> Self {
        Self::in_dir(&paths::data_dir())
    }
}

impl HeadlessPlan {
    pub fn in_dir(dir: &Path) -> Self {
        let path = dir.join("headless.json");
        // A damaged file only loses the chosen set, never a secret.
        let file: PlanFile = fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
            .unwrap_or_default();
        HeadlessPlan { path, entries: file.secrets }
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = PlanFile { secrets: self.entries.clone() };
        fs::write(&self.path, serde_json::to_string_pretty(&file).unwrap())?;
        Ok(())
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|e| eq_ic(&e.name, name))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.index(name).is_some()
    }

    pub fn entries(&self) -> &[HeadlessEntry] {
        &self.entries
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    pub fn entry(&self, name: &str) -> Option<&HeadlessEntry> {
        self.index(name).map(|i| &self.entries[i])
    }

    /// Adds a secret to the set (keeping the given name's spelling). Idempotent: an existing entry is
    /// left as it is, so its publish history and keep-in-sync choice survive. Returns whether it was
    /// newly added.
    pub fn add(&mut self, name: &str, keep_in_sync: bool) -> Result<bool> {
        if self.contains(name) {
            return Ok(false);
        }
        self.entries.push(HeadlessEntry { name: name.to_string(), published_hash: String::new(), keep_in_sync });
        self.save()?;
        Ok(true)
    }

    /// Removes a secret from the set. Returns whether it was present. Note: this does not remove the
    /// value already written into the headless vault — a publish does that.
    pub fn remove(&mut self, name: &str) -> Result<bool> {
        match self.index(name) {
            Some(i) => {
                self.entries.remove(i);
                self.save()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn set_keep_in_sync(&mut self, name: &str, keep: bool) -> Result<bool> {
        match self.index(name) {
            Some(i) => {
                self.entries[i].keep_in_sync = keep;
                self.save()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Records the content hash a secret was published with, so later drift is measured from here.
    pub fn mark_published(&mut self, name: &str, hash: &str) -> Result<()> {
        if let Some(i) = self.index(name) {
            self.entries[i].published_hash = hash.to_string();
            self.save()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    fn cred(value: &str, user: Option<&str>) -> RawCredential {
        RawCredential {
            target: "Keylo:demo".into(),
            user_name: user.map(str::to_string),
            comment: None,
            last_written: Utc::now(),
            blob: Zeroizing::new(value.as_bytes().to_vec()),
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn content_hash_ignores_last_written_but_tracks_value_and_details() {
        let a = cred("s3cret", Some("alice"));
        let mut b = a.clone();
        b.last_written = a.last_written + chrono::Duration::days(1);
        assert_eq!(content_hash(&a), content_hash(&b), "last_written must not affect the hash");

        let changed_value = cred("rotated", Some("alice"));
        assert_ne!(content_hash(&a), content_hash(&changed_value), "a changed value must change the hash");

        let changed_user = cred("s3cret", Some("bob"));
        assert_ne!(content_hash(&a), content_hash(&changed_user), "a changed detail must change the hash");
    }

    #[test]
    fn content_hash_is_unambiguous_across_field_boundaries() {
        // Without length-prefixing, ("ab", "c") and ("a", "bc") could collide.
        let mut x = cred("ab", None);
        x.comment = Some("c".into());
        let mut y = cred("a", None);
        y.comment = Some("bc".into());
        assert_ne!(content_hash(&x), content_hash(&y));
    }

    #[test]
    fn classify_covers_every_state() {
        let now = cred("v", None);
        let published = HeadlessEntry { name: "demo".into(), published_hash: content_hash(&now), keep_in_sync: false };
        let pending = HeadlessEntry { name: "demo".into(), published_hash: String::new(), keep_in_sync: false };

        assert_eq!(classify(&pending, Some(&now)), HeadlessState::Pending);
        assert_eq!(classify(&published, Some(&now)), HeadlessState::InSync);
        assert_eq!(classify(&published, Some(&cred("rotated", None))), HeadlessState::Drifted);
        assert_eq!(classify(&published, None), HeadlessState::Missing);
    }

    #[test]
    fn plan_round_trips_and_is_case_insensitive() {
        let dir = testing::setup();
        let mut plan = HeadlessPlan::in_dir(&dir);
        assert!(plan.add("GitHub-Token", true).unwrap());
        assert!(!plan.add("github-token", true).unwrap(), "same name, different case, is not a new entry");
        plan.mark_published("github-token", "deadbeef").unwrap();

        let reloaded = HeadlessPlan::in_dir(&dir);
        assert!(reloaded.contains("GITHUB-TOKEN"));
        assert_eq!(reloaded.entry("github-token").unwrap().published_hash, "deadbeef");
        assert!(reloaded.entry("github-token").unwrap().keep_in_sync);
    }

    #[test]
    fn remove_reports_presence() {
        let dir = testing::setup();
        let mut plan = HeadlessPlan::in_dir(&dir);
        plan.add("a", false).unwrap();
        assert!(plan.remove("A").unwrap());
        assert!(!plan.remove("a").unwrap());
        assert!(HeadlessPlan::in_dir(&dir).names().is_empty());
    }
}
