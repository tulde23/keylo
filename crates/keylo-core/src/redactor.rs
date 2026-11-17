//! Replaces secret values in command output with `[keylo:name]` before an agent sees it. Catches
//! accidental leaks (a command that echoes its token), not deliberate ones: a command can still
//! transform a value (base64, reversed) so it no longer matches.

use zeroize::Zeroize;

/// Shorter values would match ordinary text, so they aren't redacted.
pub const MIN_LENGTH: usize = 4;

#[derive(Default)]
pub struct OutputRedactor {
    labels: Vec<(String, String)>,
    longest: usize,
}

impl OutputRedactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Length (in bytes) of the longest value, so streaming callers know how much to hold back.
    pub fn longest_value(&self) -> usize {
        self.longest
    }

    pub fn add(&mut self, name: &str, value: &str) {
        // Values imported from files often end with a newline the output won't repeat.
        for variant in [value, value.trim()] {
            if variant.chars().count() < MIN_LENGTH || self.labels.iter().any(|(v, _)| v == variant) {
                continue;
            }
            self.labels.push((variant.to_string(), format!("[keylo:{name}]")));
            self.longest = self.longest.max(variant.len());
        }
        // Longest first, so a value containing another is replaced whole.
        self.labels.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (value, label) in &self.labels {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), label);
            }
        }
        out
    }
}

impl Drop for OutputRedactor {
    fn drop(&mut self) {
        for (v, _) in self.labels.iter_mut() {
            v.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_longest_first_and_trimmed() {
        let mut r = OutputRedactor::new();
        r.add("short", "abcd");
        r.add("long", "abcdefgh\n");
        assert_eq!(r.redact("x abcdefgh y abcd"), "x [keylo:long] y [keylo:short]");
    }

    #[test]
    fn ignores_tiny_values() {
        let mut r = OutputRedactor::new();
        r.add("t", "abc");
        assert_eq!(r.redact("abc"), "abc");
    }
}
