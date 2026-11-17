//! Imports files (e.g. the contents of a .secrets folder) as secrets, one secret per file. The same
//! rules as the C# build's SecretImporter.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::inference::{infer, split_file_name};
use crate::secrets::SecretDraft;
use crate::store::{is_valid_name, normalize_name, SecretStore, MAX_VALUE_BYTES};
use crate::types::{decode_text, typed_draft, SecretTypeCatalog};
use crate::Result;

/// A file to import (or imported) and the secret it becomes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportItem {
    pub name: String,
    pub source_path: String,
    pub category: Option<String>,
    /// In a plan, the guessed type; after importing, the type used. None: plain.
    #[serde(rename = "type")]
    pub type_id: Option<String>,
    /// In a plan: a secret with this name already exists.
    #[serde(default)]
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedFile {
    pub source_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub imported: Vec<ImportItem>,
    pub skipped: Vec<SkippedFile>,
}

/// How to import. Every file gets `category` when it's given; otherwise files from a folder take
/// their top-level subfolder as the category when `subfolder_categories` is set. `names` overrides
/// the secret name of individual files and `types` their type ("" for plain), keyed by full path;
/// other files get a guessed type when `infer_types` is set.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    pub category: Option<String>,
    pub overwrite: bool,
    pub subfolder_categories: bool,
    pub names: HashMap<String, String>,
    pub types: HashMap<String, String>,
    pub infer_types: bool,
}

impl ImportOptions {
    pub fn new() -> Self {
        ImportOptions { subfolder_categories: true, infer_types: true, ..Default::default() }
    }
}

fn absolute(path: &str) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// What an import would do, without touching the store: names and categories from the paths, plus
/// each file's guessed type and whether its name is taken (`store`, when given).
pub fn plan(paths: &[String], category: Option<&str>, subfolder_categories: bool, store: Option<&SecretStore>) -> Result<ImportResult> {
    let mut files: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut skipped = Vec::new();
    let category = category.map(str::trim).filter(|c| !c.is_empty());

    for input in paths {
        let full = absolute(input);
        if full.is_dir() {
            let mut found = Vec::new();
            walk(&full, &mut found)?;
            found.sort();
            for file in found {
                let relative = file.strip_prefix(&full).unwrap_or(&file);
                let parts: Vec<_> = relative.components().collect();
                let sub = (subfolder_categories && parts.len() > 1).then(|| parts[0].as_os_str().to_string_lossy().to_string());
                files.push((file, category.map(str::to_string).or(sub)));
            }
        } else if full.is_file() {
            files.push((full, category.map(str::to_string)));
        } else {
            skipped.push(SkippedFile { source_path: input.clone(), reason: "Not found".into() });
        }
    }

    let stem_of = |p: &Path| split_file_name(&p.to_string_lossy()).0;
    let mut stems: HashMap<String, usize> = HashMap::new();
    for (p, _) in &files {
        *stems.entry(stem_of(p).to_lowercase()).or_default() += 1;
    }

    let existing: Vec<String> = match store {
        Some(s) => s.list()?.into_iter().map(|i| i.name.to_lowercase()).collect(),
        None => vec![],
    };
    let mut used = HashSet::new();
    let mut items = Vec::new();
    for (path, file_category) in files {
        let shown = path.display().to_string();
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len > MAX_VALUE_BYTES as u64 {
            skipped.push(SkippedFile { source_path: shown, reason: "Larger than 4 MB".into() });
            continue;
        }
        let stem = stem_of(&path);
        let name = if stem.is_empty() || stems[&stem.to_lowercase()] > 1 {
            path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
        } else {
            stem
        };
        if !is_valid_name(&name) || !used.insert(name.trim().to_lowercase()) {
            skipped.push(SkippedFile { source_path: shown, reason: format!("Can't derive a unique, valid name ('{name}')") });
            continue;
        }
        let name = normalize_name(&name)?;
        let type_id = (len as usize <= 64 * 1024)
            .then(|| fs::read(&path).ok().map(Zeroizing::new))
            .flatten()
            .and_then(|content| infer(&shown, &content))
            .map(|t| t.type_id);
        let exists = existing.contains(&name.to_lowercase());
        items.push(ImportItem { name, source_path: shown, category: file_category, type_id, exists });
    }
    Ok(ImportResult { imported: items, skipped })
}

/// Imports the files. Existing secrets are skipped unless `overwrite` (then their notes, icon and
/// colour are kept).
pub fn import(store: &SecretStore, types: &SecretTypeCatalog, paths: &[String], options: &ImportOptions) -> Result<ImportResult> {
    let planned = plan(paths, options.category.as_deref(), options.subfolder_categories, None)?;
    let mut result = ImportResult { imported: vec![], skipped: planned.skipped };

    for mut item in planned.imported {
        if let Some(name) = options.names.get(&item.source_path).map(|n| n.trim()).filter(|n| !n.is_empty()) {
            item.name = name.to_string();
        }
        match import_one(store, types, &item, options) {
            Ok(None) => result.skipped.push(SkippedFile { source_path: item.source_path, reason: format!("'{}' already exists", item.name) }),
            Ok(Some(type_id)) => {
                item.type_id = type_id;
                item.exists = false;
                result.imported.push(item);
            }
            Err(e) => result.skipped.push(SkippedFile { source_path: item.source_path, reason: e.to_string() }),
        }
    }
    Ok(result)
}

/// Imports one file. None: skipped (exists); Some(type): imported, with that type (or plain).
fn import_one(store: &SecretStore, types: &SecretTypeCatalog, item: &ImportItem, options: &ImportOptions) -> Result<Option<Option<String>>> {
    let value = Zeroizing::new(fs::read(&item.source_path)?);
    let existing = store.find(&item.name)?;
    if existing.is_some() && !options.overwrite {
        return Ok(None);
    }
    let notes = existing
        .as_ref()
        .and_then(|e| e.notes.clone())
        .or_else(|| Path::new(&item.source_path).file_name().map(|n| format!("Imported from {}", n.to_string_lossy())));
    let category = item.category.clone().or_else(|| existing.as_ref().and_then(|e| e.category.clone()));
    let icon = existing.as_ref().and_then(|e| e.icon.clone());
    let color = existing.as_ref().and_then(|e| e.color.clone());

    let inferred = infer(&item.source_path, &value);
    let type_id = match options.types.get(&item.source_path) {
        Some(chosen) => Some(chosen.clone()),
        None if options.infer_types => inferred.as_ref().map(|i| i.type_id.clone()),
        None => None,
    }
    .filter(|t| !t.is_empty());
    let t = types.find(type_id.as_deref())?;
    let text = t.as_ref().and_then(|_| decode_text(&value).map(Zeroizing::new));

    let draft = match (&t, &text) {
        (Some(t), Some(text)) => {
            // The guessed split when the guess was kept; otherwise the whole value goes in the main field.
            let fields: BTreeMap<String, String> = match &inferred {
                Some(i) if i.type_id == t.id => i.fields.clone(),
                _ => {
                    let main = t.primary().or(t.fields.first()).map(|f| f.id.clone()).unwrap_or_default();
                    BTreeMap::from([(main, text.trim().to_string())])
                }
            };
            typed_draft(t, &item.name, &fields, category, notes, icon, color)?
        }
        _ => SecretDraft {
            name: item.name.clone(),
            value: value.clone(),
            category,
            username: existing.as_ref().and_then(|e| e.username.clone()),
            notes,
            icon,
            color,
            ..Default::default()
        },
    };
    store.save(&draft, existing.as_ref().map(|e| e.name.as_str()))?;
    Ok(Some(t.filter(|_| text.is_some()).map(|t| t.id)))
}

/// Overwrites each file with zeros, then deletes it. On an SSD that isn't a guaranteed wipe, but it
/// keeps the plaintext out of the recycle bin and casual undelete tools.
pub fn delete_originals(items: &[ImportItem]) -> Vec<SkippedFile> {
    let mut failed = vec![];
    for item in items {
        let wipe = || -> std::io::Result<()> {
            let len = fs::metadata(&item.source_path)?.len() as usize;
            fs::write(&item.source_path, vec![0u8; len])?;
            fs::remove_file(&item.source_path)
        };
        if let Err(e) = wipe() {
            failed.push(SkippedFile { source_path: item.source_path.clone(), reason: e.to_string() });
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn imports_a_folder_with_subfolder_categories_and_guessed_types() {
        let dir = testing::setup();
        let store = SecretStore::new(Some(&dir), Some(&testing::prefix()));
        let types = SecretTypeCatalog::in_dir(&dir);
        let src = dir.join("src");
        fs::create_dir_all(src.join("prod")).unwrap();
        fs::write(src.join("github-token"), "ghp_abc\n").unwrap();
        fs::write(src.join("prod").join("orders-db.env"), "postgres://alice:pw@db:5432/orders").unwrap();
        fs::write(src.join("notes.txt"), "remember").unwrap();
        fs::write(src.join("notes.md"), "clash").unwrap();

        let paths = vec![src.display().to_string()];
        let plan = plan(&paths, None, true, Some(&store)).unwrap();
        let names: Vec<&str> = plan.imported.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["github-token", "notes.md", "notes.txt", "orders-db"]);

        let result = import(&store, &types, &paths, &ImportOptions::new()).unwrap();
        assert_eq!(result.imported.len(), 4);
        let db = store.find("orders-db").unwrap().unwrap();
        assert_eq!((db.category.as_deref(), db.type_id.as_deref()), (Some("prod"), Some("database")));
        assert_eq!(db.fields.get("host").map(String::as_str), Some("db"));
        assert_eq!(store.find("github-token").unwrap().unwrap().type_id.as_deref(), Some("api_key"));
        assert_eq!(store.find("notes.txt").unwrap().unwrap().type_id, None);
        assert_eq!(&store.get("notes.txt").unwrap().value[..], b"remember");

        // A second run skips what exists.
        let again = import(&store, &types, &paths, &ImportOptions::new()).unwrap();
        assert_eq!((again.imported.len(), again.skipped.len()), (0, 4));
    }
}
