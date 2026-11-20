//! Starts a program the way a shell would, with extra environment variables.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::args::CliResult;
use crate::usage;

/// Secret values written to short-lived files for one command run. Each value lives in its own file
/// inside a private per-run directory; the directory's files are overwritten with zeros and removed
/// when this value is dropped — i.e. once the command has finished. Only the file *paths* are ever
/// exposed (through environment variables the child reads); the value itself is never returned to
/// the caller or an agent. This is how a secret that a program expects as a file on disk
/// (a service-account JSON, a kubeconfig, a PEM key) is used without it ever leaving Keylo as text.
pub struct SecretFiles {
    dir: PathBuf,
    files: Vec<PathBuf>,
}

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

impl SecretFiles {
    /// Creates the private per-run directory (user-only). Empty until `add` is called.
    pub fn new() -> std::io::Result<Self> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        loop {
            let n = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let dir = base.join(format!("keylo-run-{pid}-{nanos}-{n}"));
            match create_private_dir(&dir) {
                Ok(()) => return Ok(SecretFiles { dir, files: Vec::new() }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Writes `value` to a user-only file named after `name` (sanitized) and returns its path, which
    /// the caller maps into the child's environment.
    pub fn add(&mut self, name: &str, value: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.dir.join(format!("{}-{}", self.files.len(), sanitize(name)));
        write_private_file(&path, value)?;
        self.files.push(path.clone());
        Ok(path)
    }
}

impl Drop for SecretFiles {
    fn drop(&mut self) {
        for f in &self.files {
            if let Ok(meta) = std::fs::metadata(f) {
                let _ = std::fs::write(f, vec![0u8; meta.len() as usize]);
            }
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A safe, non-hidden file name: ASCII letters/digits and `.`/`-`/`_`, never empty.
fn sanitize(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    s.truncate(64);
    let s = s.trim_matches(|c| c == '.' || c == '_');
    if s.is_empty() { "secret".into() } else { s.to_string() }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    // %TEMP% lives under the user's profile and isn't readable by other users; the directory
    // inherits those permissions.
    std::fs::create_dir(dir)
}

#[cfg(unix)]
fn write_private_file(path: &Path, value: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(value)?;
    f.flush()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, value: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(value)?;
    f.flush()
}

pub fn run(command: &[String], env: &BTreeMap<String, String>) -> CliResult<i32> {
    let Some(first) = command.first() else {
        usage!("Nothing to run. Usage: keylo run --env VAR=secret -- <command> [args]");
    };
    let Some(exe) = resolve(first) else { usage!("'{first}' wasn't found on PATH.") };
    let mut cmd = build(&exe, &command[1..]);
    cmd.envs(env);
    ignore_ctrl_c();
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}

/// The command for `exe` with `args`; batch files (npm.cmd…) run through cmd.exe on Windows.
pub fn build(exe: &Path, args: &[String]) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let ext = exe.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if ext == "cmd" || ext == "bat" {
            // /s /c "..." keeps the inner quoting intact.
            let line: Vec<String> = std::iter::once(quote(&exe.to_string_lossy())).chain(args.iter().map(|a| quote(a))).collect();
            let comspec = std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into());
            let mut cmd = Command::new(comspec);
            cmd.raw_arg(format!("/d /s /c \"{}\"", line.join(" ")));
            return cmd;
        }
    }
    let mut cmd = Command::new(exe);
    cmd.args(args);
    cmd
}

#[cfg(windows)]
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c.is_whitespace() || c == '"') {
        arg.to_string()
    } else {
        format!("\"{}\"", arg.replace('"', "\\\""))
    }
}

/// Let Ctrl+C reach the child (which shares the console) without ending keylo first.
fn ignore_ctrl_c() {
    #[cfg(windows)]
    unsafe {
        let _ = windows::Win32::System::Console::SetConsoleCtrlHandler(None, true);
    }
}

/// Resolves like the shell, except the current directory isn't searched implicitly (a planted
/// "git.exe" in a project folder shouldn't receive your secrets).
pub fn resolve(command: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let exts: Vec<String> = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect();
        let candidates = |base: PathBuf| -> Vec<PathBuf> {
            let mut c = Vec::new();
            if base.extension().is_some() {
                c.push(base.clone());
            }
            c.extend(exts.iter().map(|e| PathBuf::from(format!("{}{e}", base.display()))));
            c
        };
        let p = Path::new(command);
        if command.contains('\\') || command.contains('/') || p.is_absolute() {
            let full = std::path::absolute(p).ok()?;
            return candidates(full).into_iter().find(|c| c.is_file());
        }
        let path = std::env::var("PATH").unwrap_or_default();
        path.split(';')
            .map(|d| d.trim().trim_matches('"'))
            .filter(|d| !d.is_empty())
            .flat_map(|d| candidates(Path::new(d).join(command)))
            .find(|c| c.is_file())
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let runnable = |p: &Path| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
        if command.contains('/') {
            let full = std::path::absolute(command).ok()?;
            return runnable(&full).then_some(full);
        }
        std::env::var("PATH")
            .unwrap_or_else(|_| "/usr/bin:/bin".into())
            .split(':')
            .filter(|d| !d.is_empty())
            .map(|d| Path::new(d).join(command))
            .find(|p| runnable(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_file_holds_the_value_then_is_wiped_on_drop() {
        let path;
        let dir;
        {
            let mut files = SecretFiles::new().unwrap();
            let p = files.add("GOOGLE_APPLICATION_CREDENTIALS", br#"{"client_secret":"abc"}"#).unwrap();
            assert_eq!(std::fs::read(&p).unwrap(), br#"{"client_secret":"abc"}"#);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            }
            path = p;
            dir = files.dir.clone();
        }
        // The file and its private directory are gone once SecretFiles drops.
        assert!(!path.exists(), "the temp file should be removed after the run");
        assert!(!dir.exists(), "the per-run directory should be removed after the run");
    }

    #[test]
    fn two_files_do_not_collide_and_names_are_safe() {
        let mut files = SecretFiles::new().unwrap();
        let a = files.add("VAR", b"one").unwrap();
        let b = files.add("VAR", b"two").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"one");
        assert_eq!(std::fs::read(&b).unwrap(), b"two");

        // A hostile "name" can't escape the private directory or hide the file.
        let c = files.add("../../etc/passwd", b"x").unwrap();
        assert_eq!(c.parent().unwrap(), files.dir);
        let fname = c.file_name().unwrap().to_string_lossy();
        assert!(!fname.contains('/') && !fname.contains('\\') && !fname.starts_with('.'), "unsafe name: {fname}");
    }

    #[test]
    fn sanitize_is_never_empty_or_hidden() {
        assert_eq!(sanitize(""), "secret");
        assert_eq!(sanitize("..."), "secret");
        assert_eq!(sanitize("my.key_1-a"), "my.key_1-a");
        assert_eq!(sanitize("a/b\\c:d"), "a_b_c_d");
    }
}
