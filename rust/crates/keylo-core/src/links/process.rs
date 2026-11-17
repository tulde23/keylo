//! Running the vault CLIs (`op`, `aws`). Values only ever travel on stdin and stdout, never on a
//! command line (every process can read those).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{Error, Result};

/// What a CLI printed. `code` is None when the program couldn't be started (not installed).
#[derive(Debug, Default, Clone)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// The first non-empty line of stderr.
    pub fn first_error_line(&self) -> Option<String> {
        self.stderr.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string)
    }
}

/// Runs a program; tests stand in for `op` and `aws` with their own.
pub trait Runner: Send + Sync {
    fn run(&self, program: &str, args: &[String], stdin: Option<&str>) -> Result<Output>;
}

/// The real thing, with a time limit (the CLIs may wait for the user to unlock a vault).
pub struct SystemRunner {
    pub timeout: Duration,
}

impl Default for SystemRunner {
    fn default() -> Self {
        SystemRunner { timeout: Duration::from_secs(90) }
    }
}

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[String], stdin: Option<&str>) -> Result<Output> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // No pager or prompts from the aws CLI, and no colour codes in what we parse.
            .env("AWS_PAGER", "")
            .env("NO_COLOR", "1");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Output::default()),
            Err(e) => return Err(Error::msg(format!("Couldn't start {program}: {e}"))),
        };

        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let out_thread = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = out.read_to_end(&mut b);
            b
        });
        let err_thread = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = err.read_to_end(&mut b);
            b
        });
        if let Some(mut input) = child.stdin.take() {
            if let Some(text) = stdin {
                let _ = input.write_all(text.as_bytes());
            }
            // Dropping closes stdin.
        }

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::msg(format!("{program} didn't answer within {} seconds.", self.timeout.as_secs())));
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        let stdout = String::from_utf8_lossy(&out_thread.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&err_thread.join().unwrap_or_default()).into_owned();
        Ok(Output { code: Some(status.code().unwrap_or(-1)), stdout, stderr })
    }
}

/// Finds a program on PATH (to say whether a CLI is installed without running it).
pub fn which(program: &str) -> Option<std::path::PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
            .split(';')
            .map(|e| e.to_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        exts.iter().map(|e| dir.join(format!("{program}{e}"))).find(|p| p.is_file())
    })
}
