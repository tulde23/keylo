//! keylo headless: choose a subset of secrets to publish into the headless vault file
//! (`headless-vault.json`) for use over SSH, and publish/update them. See
//! keylo_core::headless and keylo_platform::publish_headless.
//!
//! The chosen set lives in `headless.json` (intent only, no values). A publish reads the chosen
//! secrets from the main vault and writes them into the separate headless vault, encrypted under a
//! passphrase the SSH session supplies — least privilege: the headless box only ever holds the
//! secrets you pick.

use keylo_core::headless::{classify, content_hash, HeadlessPlan, HeadlessState};
use keylo_core::{paths, platform::RawCredential};

use crate::args::{Args, CliResult};
use crate::terminal::{info, print_table, read_secret};
use crate::{usage, Context};

pub fn headless_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let action = args.optional_positional(0).map(|a| a.to_lowercase()).unwrap_or_else(|| "status".into());
    match action.as_str() {
        "status" | "list" => status(c, args),
        "add" => add(args),
        "remove" | "rm" => remove(args),
        "sync" => keep_in_sync(args),
        "publish" => publish(c, args),
        other => usage!("Unknown 'keylo headless' action '{other}'. Try: status, add, remove, sync, publish."),
    }
}

fn add(args: &Args) -> CliResult<i32> {
    let names = args.positionals_from(1);
    if names.is_empty() {
        usage!("Give one or more secret names to add. Example: keylo headless add github-token db-url");
    }
    let keep = args.flag("sync");
    args.throw_on_unknown(None)?;
    let mut plan = HeadlessPlan::default();
    let mut added = 0;
    for name in &names {
        if plan.add(name, keep)? {
            added += 1;
        }
    }
    info(&format!(
        "Added {added} secret(s) to the headless set{}. Run 'keylo headless publish' to write them to the headless vault.",
        if keep { ", kept in sync" } else { "" }
    ));
    Ok(0)
}

fn remove(args: &Args) -> CliResult<i32> {
    let names = args.positionals_from(1);
    if names.is_empty() {
        usage!("Give one or more secret names to remove.");
    }
    args.throw_on_unknown(None)?;
    let mut plan = HeadlessPlan::default();
    let mut removed = 0;
    for name in &names {
        if plan.remove(name)? {
            removed += 1;
        }
    }
    info(&format!("Removed {removed} secret(s) from the headless set. Run 'keylo headless publish' to update the headless vault."));
    Ok(0)
}

fn keep_in_sync(args: &Args) -> CliResult<i32> {
    let name = args.positional(1, "secret name")?;
    let off = args.flag("off");
    args.throw_on_unknown(Some(2))?;
    let mut plan = HeadlessPlan::default();
    if !plan.set_keep_in_sync(&name, !off)? {
        usage!("'{name}' isn't in the headless set. Add it first with 'keylo headless add {name}'.");
    }
    info(&format!("'{name}' will {}be kept in sync.", if off { "no longer " } else { "" }));
    Ok(0)
}

fn status(c: &mut Context, args: &Args) -> CliResult<i32> {
    args.throw_on_unknown(Some(1))?;
    let plan = HeadlessPlan::default();
    if plan.entries().is_empty() {
        info("No secrets are chosen for headless access. Add some with 'keylo headless add NAME'.");
        return Ok(0);
    }
    // Checking drift reads the current values, so it's only done when the vault is already open (a
    // session). Locked, we show what the plan records without prompting for the identity check.
    let unlocked = c.gate.is_unlocked();
    let mut rows = Vec::new();
    for e in plan.entries() {
        let state = if unlocked {
            match c.store.raw_for_publish(&e.name)? {
                Some((_, false)) => "file-backed (not supported)".to_string(),
                Some((cred, true)) => describe(classify(e, Some(&cred))),
                None => describe(HeadlessState::Missing),
            }
        } else if e.published_hash.is_empty() {
            "not published yet".to_string()
        } else {
            "published (unlock to check for changes)".to_string()
        };
        rows.push(vec![e.name.clone(), state, if e.keep_in_sync { "yes".into() } else { "no".into() }]);
    }
    print_table(&["Secret", "Headless status", "Keep in sync"], &rows);
    Ok(0)
}

fn describe(state: HeadlessState) -> String {
    match state {
        HeadlessState::Pending => "not published yet",
        HeadlessState::InSync => "published",
        HeadlessState::Drifted => "changed — re-publish due",
        HeadlessState::Missing => "deleted from main vault",
    }
    .to_string()
}

fn publish(c: &mut Context, args: &Args) -> CliResult<i32> {
    args.throw_on_unknown(Some(1))?;
    let mut plan = HeadlessPlan::default();
    if plan.entries().is_empty() {
        usage!("No secrets are chosen for headless access. Add some with 'keylo headless add NAME' first.");
    }
    // Publishing reads the chosen values, so it needs the identity check (or a session).
    c.browse()?;

    // Gather the inline secrets to publish; note what can't go.
    let mut creds: Vec<RawCredential> = Vec::new();
    let mut hashes: Vec<(String, String)> = Vec::new();
    let mut missing = Vec::new();
    let mut file_backed = Vec::new();
    for e in plan.entries() {
        match c.store.raw_for_publish(&e.name)? {
            None => missing.push(e.name.clone()),
            Some((_, false)) => file_backed.push(e.name.clone()),
            Some((cred, true)) => {
                hashes.push((e.name.clone(), content_hash(&cred)));
                creds.push(cred);
            }
        }
    }

    for n in &missing {
        info(&format!("Skipped '{n}': no longer in the main vault."));
    }
    for n in &file_backed {
        info(&format!("Skipped '{n}': file-backed or large values can't be published to the headless vault yet."));
    }
    if creds.is_empty() {
        usage!("Nothing to publish: none of the chosen secrets are publishable.");
    }

    let data_dir = paths::data_dir();
    let creating = !data_dir.join("headless-vault.json").exists();
    let prompt = if creating {
        "Set a passphrase for the headless vault (the SSH session will enter it): "
    } else {
        "Headless vault passphrase: "
    };
    let pass = read_secret(prompt, creating)?;
    let pass = String::from_utf8_lossy(&pass).into_owned();

    let result = keylo_platform::publish_headless(&data_dir, &pass, &paths::credential_prefix(), &creds)?;
    for (name, hash) in &hashes {
        plan.mark_published(name, hash)?;
    }
    info(&format!(
        "Published {} secret(s) to the headless vault{}. Use them over SSH with KEYLO_STORE=file (the passphrase in KEYLO_PASSPHRASE or at the prompt).",
        result.written,
        if result.removed > 0 { format!(", removed {} stale", result.removed) } else { String::new() }
    ));
    Ok(0)
}
