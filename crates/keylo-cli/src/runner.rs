//! Starts a program the way a shell would, with extra environment variables.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::args::CliResult;
use crate::usage;

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
