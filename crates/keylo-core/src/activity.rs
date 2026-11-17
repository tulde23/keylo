//! Pinned secrets (pins.json) and recently used ones: your own views and copies (recent.json)
//! merged with tools' uses from the audit log. Names and times only, never values.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, Local};
use serde::{Deserialize, Serialize};

use crate::access::audit_path_in;
use crate::{eq_ic, paths, Result};

const MAX_OWN_USES: usize = 200;
const AUDIT_LINES_SCANNED: usize = 1000;

/// One use of a secret: by you in the app, or by a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentUse {
    pub name: String,
    pub time: DateTime<FixedOffset>,
    /// "You", or the access key's name.
    pub who: String,
    /// viewed, copied, exported, run, get.
    pub action: String,
}

pub struct Activity {
    dir: PathBuf,
}

impl Default for Activity {
    fn default() -> Self {
        Activity { dir: paths::data_dir() }
    }
}

impl Activity {
    pub fn in_dir(dir: &Path) -> Self {
        Activity { dir: dir.to_path_buf() }
    }

    fn pins_path(&self) -> PathBuf {
        self.dir.join("pins.json")
    }
    fn recent_path(&self) -> PathBuf {
        self.dir.join("recent.json")
    }

    pub fn pins(&self) -> Vec<String> {
        load(&self.pins_path()).unwrap_or_default()
    }

    pub fn is_pinned(&self, name: &str) -> bool {
        self.pins().iter().any(|p| eq_ic(p, name))
    }

    pub fn set_pinned(&self, name: &str, pinned: bool) -> Result<()> {
        let mut pins: Vec<String> = self.pins().into_iter().filter(|p| !eq_ic(p, name)).collect();
        if pinned {
            pins.push(name.to_string());
        }
        self.save(&self.pins_path(), &pins)
    }

    pub fn record_use(&self, name: &str, action: &str) -> Result<()> {
        let mut uses: Vec<RecentUse> = load(&self.recent_path()).unwrap_or_default();
        uses.push(RecentUse { name: name.into(), time: Local::now().fixed_offset(), who: "You".into(), action: action.into() });
        let skip = uses.len().saturating_sub(MAX_OWN_USES);
        self.save(&self.recent_path(), &uses[skip..].to_vec())
    }

    /// The latest use of each secret, newest first: yours and tools'.
    pub fn recent(&self, limit: usize) -> Vec<RecentUse> {
        let mut all: Vec<RecentUse> = load(&self.recent_path()).unwrap_or_default();
        all.extend(self.tool_uses());
        all.sort_by(|a, b| b.time.cmp(&a.time));
        let mut latest: Vec<RecentUse> = Vec::new();
        for u in all {
            if !latest.iter().any(|l| eq_ic(&l.name, &u.name)) {
                latest.push(u);
            }
            if latest.len() == limit {
                break;
            }
        }
        latest
    }

    fn tool_uses(&self) -> Vec<RecentUse> {
        let Ok(text) = fs::read_to_string(audit_path_in(&self.dir)) else { return vec![] };
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(AUDIT_LINES_SCANNED);
        let mut uses = Vec::new();
        for line in &lines[start..] {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let Some(time) = v.get("time").and_then(|t| t.as_str()).and_then(|t| DateTime::parse_from_rfc3339(t).ok()) else {
                continue;
            };
            let who = v.get("key").and_then(|k| k.as_str()).filter(|k| !k.is_empty()).unwrap_or("A tool");
            let action = v.get("operation").and_then(|o| o.as_str()).unwrap_or("used");
            for name in v.get("secrets").and_then(|s| s.as_array()).into_iter().flatten().filter_map(|s| s.as_str()) {
                if !name.is_empty() {
                    uses.push(RecentUse { name: name.into(), time, who: who.into(), action: action.into() });
                }
            }
        }
        uses
    }

    /// Keeps pins and your own history pointing at a renamed secret.
    pub fn renamed(&self, old: &str, new: &str) -> Result<()> {
        if old == new {
            return Ok(());
        }
        let mut pins: Vec<String> = Vec::new();
        for p in self.pins() {
            let p = if eq_ic(&p, old) { new.to_string() } else { p };
            if !pins.iter().any(|x| eq_ic(x, &p)) {
                pins.push(p);
            }
        }
        self.save(&self.pins_path(), &pins)?;
        let uses: Vec<RecentUse> = load::<Vec<RecentUse>>(&self.recent_path())
            .unwrap_or_default()
            .into_iter()
            .map(|mut u| {
                if eq_ic(&u.name, old) {
                    u.name = new.into();
                }
                u
            })
            .collect();
        self.save(&self.recent_path(), &uses)
    }

    /// Forgets deleted secrets' pins and your history of them (the audit log is left alone).
    pub fn removed(&self, names: &[String]) -> Result<()> {
        let gone = |n: &str| names.iter().any(|g| eq_ic(g, n));
        let pins: Vec<String> = self.pins().into_iter().filter(|p| !gone(p)).collect();
        self.save(&self.pins_path(), &pins)?;
        let uses: Vec<RecentUse> = load::<Vec<RecentUse>>(&self.recent_path())
            .unwrap_or_default()
            .into_iter()
            .filter(|u| !gone(&u.name))
            .collect();
        self.save(&self.recent_path(), &uses)
    }

    fn save<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, serde_json::to_string_pretty(value).unwrap())?;
        fs::rename(&temp, path)?;
        Ok(())
    }
}

/// A damaged file only loses pins/history, never secrets.
fn load<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_str(fs::read_to_string(path).ok()?.trim_start_matches('\u{feff}')).ok()
}
