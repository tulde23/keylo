//! keylo link, push and provider: secrets linked to 1Password or AWS Secrets Manager (read live
//! through `op` and `aws`), copying secrets into them, and their settings and environments.

use std::collections::BTreeMap;

use keylo_core::links::{self, environments, LinkTarget, Settings, VaultEnvironment, VaultProvider};
use keylo_core::store::normalize_name;
use keylo_core::{eq_ic, search, Error};

use crate::args::{Args, CliResult};
use crate::terminal::{self, info, print_table};
use crate::{fail, usage, Context};

fn provider(id: &str) -> CliResult<Box<dyn VaultProvider>> {
    match links::find(id) {
        Some(p) => Ok(p),
        None => {
            let ids: Vec<&str> = links::providers().iter().map(|p| p.id()).collect();
            usage!("No vault '{id}'. Available: {}.", ids.join(", "))
        }
    }
}

fn settings_mut<'a>(c: &'a mut Context, id: &str) -> &'a mut Settings {
    let key = c.config.providers.keys().find(|k| eq_ic(k, id)).cloned().unwrap_or_else(|| id.to_string());
    c.config.providers.entry(key).or_default()
}

/// keylo link NAME --item ITEM: a secret that points at an item in another vault (1Password by
/// default, or --provider aws); values are read from there on every use. --search QUERY finds items.
pub fn link(c: &mut Context, args: &Args) -> CliResult<i32> {
    let provider = provider(&args.option("provider").unwrap_or_else(|| "1password".into()))?;
    let search_text = args.option("search");
    let item = args.option("item");
    let environment = args.option("environment");
    let env_names = args.options("env-name");
    let vault_filter = args.option("vault");
    let only = args.option("field");
    let category = args.option("category");
    let notes = args.option("notes");
    let scope: Vec<(&str, String)> = ["account", "profile", "region"].into_iter().filter_map(|k| args.option(k).map(|v| (k, v))).collect();
    args.throw_on_unknown(Some(1))?;

    let mut settings = links::provider_settings(&c.config, provider.id());
    for (key, v) in scope {
        settings.insert(key.into(), v);
    }
    if let Some(e) = &environment {
        // Search that environment's account; the link itself names only the secret.
        if environments::find(&settings, e).is_none() {
            usage!("No environment '{e}'. Add one: keylo provider env {} set {e} PROFILE REGION", provider.id());
        }
        settings.insert(links::ENVIRONMENT_SETTING.into(), e.clone());
    }
    let in_vault = |v: &Option<String>| vault_filter.as_ref().is_none_or(|f| v.as_deref().is_some_and(|v| eq_ic(v, f)));

    if let Some(q) = search_text {
        let found: Vec<_> = provider.search(Some(&q), &settings)?.into_iter().filter(|i| in_vault(&i.vault_name)).collect();
        if found.is_empty() {
            info("Nothing matches.");
            return Ok(1);
        }
        let rows: Vec<Vec<String>> = found
            .into_iter()
            .map(|i| vec![i.title, i.vault_name.unwrap_or_default(), i.location.unwrap_or_default(), i.category.unwrap_or_default(), i.item_id])
            .collect();
        print_table(&["TITLE", "VAULT", "WHERE", "CATEGORY", "ID"], &rows);
        return Ok(0);
    }

    let name = normalize_name(&args.positional(0, "secret name")?)?;
    let Some(item) = item else {
        usage!("Usage: keylo link NAME --item ITEM [--vault V] [--account A] [--field F] [--category C]   (find items with --search QUERY)")
    };
    c.browse()?;
    if c.store.exists(&name)? {
        return Err(Error::Exists(name).into());
    }

    // ITEM is an id or a title; a title must match exactly one item.
    let all = provider.search(None, &settings)?;
    let candidates: Vec<_> = all.iter().filter(|i| in_vault(&i.vault_name) && (i.item_id == item || eq_ic(&i.title, &item))).collect();
    let chosen = match candidates.len() {
        1 => candidates[0].clone(),
        0 => fail!("No item '{item}' in {}. Try: keylo link --search \"{item}\"", provider.display_name()),
        n => {
            let list: Vec<String> = candidates
                .iter()
                .map(|i| format!("{} · {} · {}", i.vault_name.as_deref().unwrap_or(""), i.location.as_deref().unwrap_or(""), i.item_id))
                .collect();
            fail!("'{item}' matches {n} items ({}). Use --vault, --account or the id.", list.join("; "))
        }
    };

    let target = match &environment {
        None => LinkTarget {
            provider: provider.id().into(),
            item_id: chosen.item_id.clone(),
            vault_id: chosen.vault_id.clone(),
            location: chosen.location.clone(),
        },
        Some(_) => LinkTarget { provider: provider.id().into(), item_id: chosen.title.clone(), vault_id: None, location: Some(links::PER_ENVIRONMENT.into()) },
    };
    let fields = provider.describe(&target, &settings)?;
    if let Some(o) = &only {
        if !fields.iter().any(|f| eq_ic(&f.id, o)) {
            let ids: Vec<&str> = fields.iter().map(|f| f.id.as_str()).collect();
            usage!("{} has no field '{o}'. Fields: {}.", chosen.title, ids.join(", "));
        }
    }

    let mut environment_names = BTreeMap::new();
    for n in &env_names {
        match n.split_once('=') {
            Some((e, s)) if !e.is_empty() && !s.is_empty() => {
                environment_names.insert(e.to_string(), s.to_string());
            }
            _ => usage!("--env-name expects ENV=SECRET-NAME, e.g. --env-name prod=orders/db-prod"),
        }
    }
    if !environment_names.is_empty() && environment.is_none() {
        usage!("--env-name needs --environment (a per-environment link).");
    }

    let r#where = match &environment {
        None => [chosen.vault_name.as_deref(), chosen.location.as_deref()].into_iter().flatten().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · "),
        Some(_) => "per environment".into(),
    };
    let link = links::Link {
        target,
        title: chosen.title.clone(),
        r#where: Some(r#where.clone()).filter(|w| !w.is_empty()),
        fields,
        only_field: only.map(|o| o.to_lowercase()),
        environment_names,
    };
    let category = match category {
        Some(c) => c,
        None if environment.is_some() => provider.display_name().into(),
        None => {
            let mut locations: Vec<_> = all.iter().map(|i| i.location.clone()).collect();
            locations.sort();
            locations.dedup();
            links::default_category(provider.display_name(), &chosen, locations.len() > 1)
        }
    };
    c.store.save(&links::draft(&name, &link, Some(&category).filter(|c| !c.is_empty()).map(|c| c.as_str()), notes.as_deref(), None, None), None)?;
    let ids: Vec<&str> = link.visible_fields().iter().map(|f| f.id.as_str()).collect();
    info(&format!(
        "Linked '{name}' to {} in {} ({}), category '{category}'. Fields: {}.",
        chosen.title,
        provider.display_name(),
        r#where,
        ids.join(", ")
    ));
    if environment.is_some() {
        let names: Vec<String> = environments::read(&settings).into_iter().map(|e| e.name).collect();
        info(&format!("Use it as {name}@ENV ({}); plain '{name}' uses the default environment.", names.join(", ")));
    }
    Ok(0)
}

/// keylo push PROVIDER [NAME...] [--category C] [--all] [--yes]: copies secrets into a vault.
pub fn push(c: &mut Context, args: &Args) -> CliResult<i32> {
    let provider = provider(&args.positional(0, "provider (e.g. 1password)")?)?;
    let names = args.positionals_from(1);
    let category = args.option("category");
    let all = args.flag("all");
    let yes = args.flag("yes");
    args.throw_on_unknown(None)?;

    let settings = links::provider_settings(&c.config, provider.id());
    let status = provider.status(&settings);
    if !status.ready {
        fail!("{}: {}", provider.display_name(), status.message);
    }

    c.browse()?;
    let selected = if !names.is_empty() {
        let mut list = Vec::new();
        for n in &names {
            list.push(c.store.find(n)?.ok_or_else(|| Error::NotFound(n.clone()))?);
        }
        list
    } else if all || category.is_some() {
        let everything = c.store.list()?;
        search::filter(&everything, None, category.as_deref()).into_iter().cloned().collect()
    } else {
        usage!("Name the secrets to push, or use --category C or --all.")
    };
    let selected: Vec<_> = selected.into_iter().filter(|s| !links::is_linked(s)).collect();
    if selected.is_empty() {
        info("Nothing to push (linked secrets already live in a vault).");
        return Ok(0);
    }

    // Where it all goes, before anything is read or sent.
    let preview = provider.preview(&selected[0].name, &settings);
    info(&format!("Pushing {} secret(s) to {}: {}", selected.len(), provider.display_name(), preview.target));
    for s in selected.iter().take(10) {
        info(&format!("  {}", s.name));
    }
    if selected.len() > 10 {
        info(&format!("  …and {} more", selected.len() - 10));
    }
    if !yes && !terminal::confirm("Push them? (existing Keylo-pushed items are updated)") {
        info("Nothing pushed.");
        return Ok(1);
    }
    c.gate.ensure(0, &format!("Keylo: push {} secret(s) to {}", selected.len(), provider.display_name()), true)?;

    let mut failures = 0;
    for s in &selected {
        let result = provider.push(&c.store.get(&s.name)?, &settings);
        info(&format!("  {} {}: {}", if result.succeeded { "+" } else { "!" }, s.name, result.message));
        if !result.succeeded {
            failures += 1;
        }
    }
    info(&format!("Pushed {} of {} to {}.", selected.len() - failures, selected.len(), provider.display_name()));
    Ok(if failures > 0 { 1 } else { 0 })
}

/// keylo provider list | status ID | set ID KEY VALUE | env ID ...
pub fn provider_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let action = args.optional_positional(0).map(|a| a.to_lowercase()).unwrap_or_else(|| "list".into());
    let ask = args.flag("ask");
    let no_ask = args.flag("no-ask");
    args.throw_on_unknown(None)?;
    match action.as_str() {
        "list" => {
            let rows: Vec<Vec<String>> = links::providers()
                .iter()
                .map(|p| {
                    let s = links::provider_settings(&c.config, p.id());
                    let keys: Vec<String> = p
                        .setting_descriptions()
                        .iter()
                        .map(|(k, _)| if links::setting(&s, k).is_some() { format!("{k}=✓") } else { k.to_string() })
                        .collect();
                    vec![p.id().into(), p.display_name().into(), keys.join(", ")]
                })
                .collect();
            print_table(&["ID", "NAME", "SETTINGS"], &rows);
            Ok(0)
        }
        "status" => {
            let p = provider(&args.positional(1, "provider id")?)?;
            let status = p.status(&links::provider_settings(&c.config, p.id()));
            println!("{}: {}", p.display_name(), status.message);
            Ok(if status.ready { 0 } else { 1 })
        }
        "set" => {
            let p = provider(&args.positional(1, "provider id")?)?;
            let key = args.positional(2, "setting name")?;
            let value = args.positional(3, "setting value")?;
            let known: Vec<&str> = p.setting_descriptions().iter().map(|(k, _)| *k).collect();
            if !known.iter().any(|k| eq_ic(k, &key)) {
                usage!("{} settings: {}", p.display_name(), known.join(", "));
            }
            settings_mut(c, p.id()).insert(key.to_lowercase(), value.clone());
            c.config.save()?;
            info(&format!("{}: {key} = {value}", p.display_name()));
            Ok(0)
        }
        "env" => environments_cmd(c, args, provider(&args.positional(1, "provider id")?)?, ask, no_ask),
        _ => usage!("Usage: keylo provider list | status ID | set ID KEY VALUE | env ID [list | set ENV PROFILE REGION [--ask] | remove ENV | default ENV]"),
    }
}

/// keylo provider env aws [list | set ENV PROFILE REGION [--ask|--no-ask] | remove ENV | default ENV]:
/// the environments per-environment links read from. Changes ask for the identity check, since
/// "always ask" decides what agents can use without approval.
fn environments_cmd(c: &mut Context, args: &Args, p: Box<dyn VaultProvider>, ask: bool, no_ask: bool) -> CliResult<i32> {
    if !p.has_environments() {
        usage!("{} has no environments.", p.display_name());
    }
    let settings = links::provider_settings(&c.config, p.id());
    let mut all = environments::read(&settings);
    let default = environments::default(&settings);
    let what = format!("Keylo: change {} environments", p.display_name());

    let save = |c: &mut Context, all: &[VaultEnvironment], default: Option<String>| -> CliResult<()> {
        c.gate.ensure(0, &what, true)?;
        environments::write(settings_mut(c, p.id()), all, default.as_deref())?;
        c.config.save()?;
        Ok(())
    };
    let stored_default = links::setting(&settings, environments::DEFAULT_KEY).map(str::to_string);

    match args.optional_positional(2).map(|a| a.to_lowercase()).unwrap_or_else(|| "list".into()).as_str() {
        "list" => {
            if all.is_empty() {
                info(&format!("No environments yet. Add one: keylo provider env {} set dev PROFILE REGION", p.id()));
                return Ok(0);
            }
            let rows: Vec<Vec<String>> = all
                .iter()
                .map(|e| {
                    vec![
                        e.name.clone(),
                        e.profile.clone().unwrap_or_else(|| "(default credentials)".into()),
                        e.region.clone().unwrap_or_else(|| "(profile's)".into()),
                        if e.always_ask { "yes".into() } else { String::new() },
                        if default.as_deref().is_some_and(|d| eq_ic(d, &e.name)) { "✓".into() } else { String::new() },
                    ]
                })
                .collect();
            print_table(&["ENVIRONMENT", "PROFILE", "REGION", "ALWAYS ASK", "DEFAULT"], &rows);
            Ok(0)
        }
        "set" => {
            let name = args.positional(3, "environment name")?;
            let existing = all.iter().find(|e| eq_ic(&e.name, &name)).cloned();
            // Production-like names start as "always ask"; --ask / --no-ask decide explicitly.
            let always_ask = ask || (!no_ask && existing.map(|e| e.always_ask).unwrap_or_else(|| environments::looks_like_production(&name)));
            let updated = VaultEnvironment { name: name.clone(), profile: args.optional_positional(4), region: args.optional_positional(5), always_ask };
            if !environments::is_valid_name(&name) {
                usage!("'{name}' isn't a valid environment name: use letters, digits, '-' and '_'.");
            }
            all.retain(|e| !eq_ic(&e.name, &name));
            all.push(updated.clone());
            save(c, &all, stored_default)?;
            info(&format!(
                "{name}: profile {}, region {}{}.",
                updated.profile.as_deref().unwrap_or("(default credentials)"),
                updated.region.as_deref().unwrap_or("(profile's)"),
                if always_ask { ", always asks" } else { "" }
            ));
            Ok(0)
        }
        "remove" | "rm" => {
            let name = args.positional(3, "environment name")?;
            let before = all.len();
            all.retain(|e| !eq_ic(&e.name, &name));
            if all.len() == before {
                fail!("No environment '{name}'.");
            }
            save(c, &all, stored_default.filter(|d| !eq_ic(d, &name)))?;
            info(&format!("Removed {name}."));
            Ok(0)
        }
        "default" => {
            let name = args.positional(3, "environment name")?;
            if !all.iter().any(|e| eq_ic(&e.name, &name)) {
                fail!("No environment '{name}'.");
            }
            save(c, &all, Some(name.clone()))?;
            info(&format!("Default environment: {name}."));
            Ok(0)
        }
        _ => usage!("Usage: keylo provider env {} [list | set ENV PROFILE REGION [--ask|--no-ask] | remove ENV | default ENV]", p.id()),
    }
}
