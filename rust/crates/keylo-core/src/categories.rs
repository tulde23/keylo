//! Categories live on the secrets themselves (an item attribute). This catalog adds what a secret
//! can't hold: categories with no secrets yet, and each category's icon and colour. It's display
//! metadata, not a security setting: a plain file (categories.json), as in the C# build.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::secrets::SecretInfo;
use crate::store::{normalize_color, normalize_icon, SecretStore, MAX_CATEGORY_LENGTH};
use crate::types::Style;
use crate::{bail, eq_ic, paths, Result};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategorySummary {
    pub name: String,
    pub count: usize,
    pub icon: Option<String>,
    pub color: Option<String>,
}

pub struct CategoryCatalog {
    path: PathBuf,
    entries: BTreeMap<String, Style>,
}

impl Default for CategoryCatalog {
    fn default() -> Self {
        Self::in_dir(&paths::data_dir())
    }
}

impl CategoryCatalog {
    pub fn in_dir(dir: &Path) -> Self {
        let path = dir.join("categories.json");
        // A damaged file only loses icons and empty categories; secrets keep their categories.
        let entries = fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
            .unwrap_or_default();
        CategoryCatalog { path, entries }
    }

    fn key(&self, name: &str) -> Option<String> {
        self.entries.keys().find(|k| eq_ic(k, name)).cloned()
    }

    /// Every category: those in use plus empty ones created here, with counts and styles, A-Z.
    pub fn all(&self, secrets: &[SecretInfo]) -> Vec<CategorySummary> {
        let mut out: Vec<CategorySummary> = Vec::new();
        for s in secrets {
            let Some(c) = &s.category else { continue };
            match out.iter_mut().find(|x| eq_ic(&x.name, c)) {
                Some(x) => x.count += 1,
                None => out.push(CategorySummary { name: c.clone(), count: 1, icon: None, color: None }),
            }
        }
        for name in self.entries.keys() {
            if !out.iter().any(|x| eq_ic(&x.name, name)) {
                out.push(CategorySummary { name: name.clone(), count: 0, icon: None, color: None });
            }
        }
        for c in out.iter_mut() {
            if let Some(style) = self.style_of(&c.name) {
                c.icon = style.icon.clone();
                c.color = style.color.clone();
            }
        }
        out.sort_by_key(|c| c.name.to_lowercase());
        out
    }

    pub fn style_of(&self, category: &str) -> Option<&Style> {
        self.entries.iter().find(|(k, _)| eq_ic(k, category)).map(|(_, v)| v)
    }

    /// Adds an empty category (keeps an existing one), with an optional style.
    pub fn create(&mut self, name: &str, icon: Option<&str>, color: Option<&str>) -> Result<()> {
        let name = validate(name)?;
        if self.key(&name).is_none() {
            self.entries.insert(name.clone(), Style::default());
        }
        self.set_style(&name, icon, color)
    }

    /// Adds a category from elsewhere (a backup). Its style applies when `overwrite_style`, or when
    /// the existing category has none. Returns whether the category is new.
    pub fn merge(&mut self, name: &str, style: &Style, overwrite_style: bool) -> Result<bool> {
        let name = validate(name)?;
        let key = self.key(&name);
        let is_new = key.is_none();
        let key = key.unwrap_or(name);
        let existing = self.entries.entry(key).or_default();
        if overwrite_style || (existing.icon.is_none() && existing.color.is_none()) {
            *existing = Style { icon: normalize_icon(style.icon.as_deref())?, color: normalize_color(style.color.as_deref())? };
        }
        self.save()?;
        Ok(is_new)
    }

    pub fn set_style(&mut self, name: &str, icon: Option<&str>, color: Option<&str>) -> Result<()> {
        let name = validate(name)?;
        let style = Style { icon: normalize_icon(icon)?, color: normalize_color(color)? };
        let key = self.key(&name).unwrap_or(name);
        self.entries.insert(key, style);
        self.save()
    }

    /// Renames a category on every secret in it. Renaming onto an existing category merges the two
    /// (the target keeps its own style). Returns how many secrets moved.
    pub fn rename(&mut self, store: &SecretStore, from: &str, to: &str) -> Result<usize> {
        let to = validate(to)?;
        // Merging into an existing category keeps its spelling ("Production" onto "production").
        let existing = store
            .categories()?
            .into_iter()
            .chain(self.entries.keys().cloned())
            .find(|c| eq_ic(c, &to) && !eq_ic(c, from));
        let to = existing.unwrap_or(to);
        let moved = store.recategorize_all(from, Some(&to))?;
        let style = self.key(from).and_then(|k| self.entries.remove(&k));
        if self.key(&to).is_none() {
            self.entries.insert(to, style.unwrap_or_default());
        }
        self.save()?;
        Ok(moved)
    }

    /// Removes a category. Its secrets move to `move_to` (None: uncategorized), or are deleted with
    /// `delete_secrets`. Returns how many secrets were affected.
    pub fn delete(&mut self, store: &SecretStore, name: &str, move_to: Option<&str>, delete_secrets: bool) -> Result<usize> {
        let affected = if delete_secrets {
            let mut n = 0;
            for s in store.list()?.into_iter().filter(|s| s.category.as_deref().is_some_and(|c| eq_ic(c, name))) {
                if store.delete(&s.name)? {
                    n += 1;
                }
            }
            n
        } else {
            let target = match move_to {
                Some(m) => {
                    let m = validate(m)?;
                    if self.key(&m).is_none() {
                        self.entries.insert(m.clone(), Style::default());
                    }
                    Some(m)
                }
                None => None,
            };
            store.recategorize_all(name, target.as_deref())?
        };
        if let Some(k) = self.key(name) {
            self.entries.remove(&k);
        }
        self.save()?;
        Ok(affected)
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&self.path, serde_json::to_string_pretty(&self.entries).unwrap())?;
        Ok(())
    }
}

fn validate(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Category name is required.");
    }
    if name.encode_utf16().count() > MAX_CATEGORY_LENGTH {
        bail!("Category is longer than {MAX_CATEGORY_LENGTH} characters.");
    }
    if name.chars().any(char::is_control) {
        bail!("Category cannot contain control characters.");
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretDraft;
    use crate::testing;
    use zeroize::Zeroizing;

    fn add(store: &SecretStore, name: &str, category: &str) {
        let draft = SecretDraft { name: name.into(), value: Zeroizing::new(b"v".to_vec()), category: Some(category.into()), ..Default::default() };
        store.save(&draft, None).unwrap();
    }

    fn category_of(store: &SecretStore, name: &str) -> Option<String> {
        store.find(name).unwrap().unwrap().category
    }

    #[test]
    fn rename_moves_secrets_and_merging_keeps_the_existing_spelling() {
        let dir = testing::setup();
        let store = SecretStore::new(Some(&dir), Some(&testing::prefix()));
        let mut catalog = CategoryCatalog::in_dir(&dir);
        add(&store, "a", "prod");
        add(&store, "b", "staging");

        assert_eq!(catalog.rename(&store, "prod", "production").unwrap(), 1);
        assert_eq!(category_of(&store, "a").as_deref(), Some("production"));

        // "Production" onto the existing "production": one category, its spelling.
        assert_eq!(catalog.rename(&store, "staging", "Production").unwrap(), 1);
        assert_eq!(category_of(&store, "b").as_deref(), Some("production"));
        let all = catalog.all(&store.list().unwrap());
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].name.as_str(), all[0].count), ("production", 2));
    }

    #[test]
    fn empty_categories_and_styles_are_kept() {
        let dir = testing::setup();
        let store = SecretStore::new(Some(&dir), Some(&testing::prefix()));
        let mut catalog = CategoryCatalog::in_dir(&dir);
        catalog.create("personal", Some("Shield24"), Some("#ef4444")).unwrap();
        let reloaded = CategoryCatalog::in_dir(&dir).all(&store.list().unwrap());
        assert_eq!(reloaded.len(), 1);
        assert_eq!((reloaded[0].count, reloaded[0].icon.as_deref(), reloaded[0].color.as_deref()), (0, Some("Shield24"), Some("#EF4444")));
        assert!(catalog.set_style("personal", Some("not an icon!"), None).is_err());
    }

    #[test]
    fn delete_moves_or_deletes_the_secrets() {
        let dir = testing::setup();
        let store = SecretStore::new(Some(&dir), Some(&testing::prefix()));
        let mut catalog = CategoryCatalog::in_dir(&dir);
        add(&store, "a", "legacy");
        add(&store, "b", "old");

        assert_eq!(catalog.delete(&store, "legacy", Some("archive"), false).unwrap(), 1);
        assert_eq!(category_of(&store, "a").as_deref(), Some("archive"));
        assert_eq!(catalog.delete(&store, "archive", None, false).unwrap(), 1);
        assert_eq!(category_of(&store, "a"), None);
        assert_eq!(catalog.delete(&store, "old", None, true).unwrap(), 1);
        assert!(store.find("b").unwrap().is_none());
        assert!(catalog.all(&store.list().unwrap()).is_empty());
    }
}
