//! Minimal argument reader: positionals, "--name value" options, repeatable options, boolean flags,
//! and "--" ending option parsing (everything after it is `rest`). Unknown options are errors.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};

pub type CliResult<T> = Result<T, CliError>;

/// A usage mistake (exit code 2) or a Keylo error (exit code 1).
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Keylo(keylo_core::Error),
}

impl From<keylo_core::Error> for CliError {
    fn from(e: keylo_core::Error) -> Self {
        CliError::Keylo(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Keylo(e.into())
    }
}

#[macro_export]
macro_rules! usage {
    ($($arg:tt)*) => { return Err($crate::args::CliError::Usage(format!($($arg)*))) };
}

#[macro_export]
macro_rules! fail {
    ($($arg:tt)*) => { return Err($crate::args::CliError::Keylo(keylo_core::Error::Keylo(format!($($arg)*)))) };
}

pub struct Args {
    positionals: Vec<String>,
    options: BTreeMap<String, Vec<String>>,
    flags: HashSet<String>,
    consumed: RefCell<HashSet<String>>,
    pub rest: Vec<String>,
}

impl Args {
    pub fn parse(args: &[String], flag_names: &[&str]) -> CliResult<Args> {
        let mut a = Args {
            positionals: vec![],
            options: BTreeMap::new(),
            flags: HashSet::new(),
            consumed: RefCell::new(HashSet::new()),
            rest: vec![],
        };
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if arg == "--" {
                a.rest = args[i + 1..].to_vec();
                break;
            }
            if let Some(name) = arg.strip_prefix("--").filter(|n| !n.is_empty()) {
                let (name, inline) = match name.find('=') {
                    Some(eq) if eq > 0 => (&name[..eq], Some(name[eq + 1..].to_string())),
                    _ => (name, None),
                };
                let lower = name.to_lowercase();
                if flag_names.contains(&lower.as_str()) {
                    a.flags.insert(lower);
                    i += 1;
                    continue;
                }
                let value = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => usage!("--{name} needs a value."),
                        }
                    }
                };
                a.options.entry(lower).or_default().push(value);
                i += 1;
                continue;
            }
            a.positionals.push(arg.clone());
            i += 1;
        }
        Ok(a)
    }

    pub fn positional_count(&self) -> usize {
        self.positionals.len()
    }

    pub fn positional(&self, index: usize, what: &str) -> CliResult<String> {
        match self.positionals.get(index) {
            Some(p) => Ok(p.clone()),
            None => usage!("Missing {what}."),
        }
    }

    pub fn optional_positional(&self, index: usize) -> Option<String> {
        self.positionals.get(index).cloned()
    }

    pub fn positionals_from(&self, index: usize) -> Vec<String> {
        self.positionals.iter().skip(index).cloned().collect()
    }

    pub fn flag(&self, name: &str) -> bool {
        self.consumed.borrow_mut().insert(name.into());
        self.flags.contains(name)
    }

    pub fn option(&self, name: &str) -> Option<String> {
        self.consumed.borrow_mut().insert(name.into());
        self.options.get(name).and_then(|v| v.last().cloned())
    }

    pub fn options(&self, name: &str) -> Vec<String> {
        self.consumed.borrow_mut().insert(name.into());
        self.options.get(name).cloned().unwrap_or_default()
    }

    /// Rejects options the command didn't read and, with `max_positionals`, extra positionals.
    pub fn throw_on_unknown(&self, max_positionals: Option<usize>) -> CliResult<()> {
        let consumed = self.consumed.borrow();
        if let Some(k) = self.options.keys().chain(self.flags.iter()).find(|k| !consumed.contains(*k)) {
            usage!("Unknown option --{k}.");
        }
        if let Some(max) = max_positionals {
            if self.positionals.len() > max {
                usage!("Unexpected argument '{}'.", self.positionals[max]);
            }
        }
        Ok(())
    }
}
