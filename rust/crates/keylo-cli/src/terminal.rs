//! Reading secrets and confirmations from the terminal; messages go to stderr.

use std::io::{self, IsTerminal, Read, Write};

use zeroize::Zeroizing;

use crate::args::{CliError, CliResult};

pub fn info(message: &str) {
    eprintln!("{message}");
}

pub fn input_redirected() -> bool {
    !io::stdin().is_terminal()
}

/// Reads a secret value: from stdin when it's redirected (one trailing newline dropped), otherwise
/// typed without echo (twice with `confirm`).
pub fn read_secret(prompt: &str, confirm: bool) -> CliResult<Zeroizing<Vec<u8>>> {
    if input_redirected() {
        let mut data = Zeroizing::new(Vec::new());
        io::stdin().read_to_end(&mut data)?;
        if data.last() == Some(&b'\n') {
            data.pop();
        }
        if data.last() == Some(&b'\r') {
            data.pop();
        }
        return Ok(data);
    }
    let first = read_hidden(prompt)?;
    if confirm {
        let second = read_hidden("Confirm: ")?;
        if *first != *second {
            return Err(CliError::Usage("Values didn't match.".into()));
        }
    }
    if first.is_empty() {
        return Err(CliError::Usage("Value is empty.".into()));
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

fn read_hidden(prompt: &str) -> CliResult<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

pub fn confirm(question: &str) -> bool {
    if input_redirected() {
        return false;
    }
    eprint!("{question} [y/N] ");
    let _ = io::stderr().flush();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).is_ok() && answer.trim().to_lowercase().starts_with('y')
}

/// Writes the exact bytes to stdout (binary-safe), adding a newline only on an interactive console.
pub fn write_raw(value: &[u8]) -> CliResult<()> {
    let mut out = io::stdout().lock();
    out.write_all(value)?;
    if io::stdout().is_terminal() {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(())
}

/// Columns padded to the widest cell (max 48 characters, longer cells cut with "…").
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| rows.iter().map(|r| r[i].chars().count()).chain([h.chars().count()]).max().unwrap_or(0).min(48))
        .collect();
    let line = |cells: Vec<String>| {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let c = if c.chars().count() > widths[i] {
                    c.chars().take(widths[i] - 1).collect::<String>() + "…"
                } else {
                    c.clone()
                };
                format!("{c:<w$}", w = widths[i])
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    println!("{}", line(headers.iter().map(|h| h.to_string()).collect()));
    for r in rows {
        println!("{}", line(r.clone()));
    }
}
