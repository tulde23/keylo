//! keylo: the command line for Keylo's secrets, and (keylo mcp) the MCP server for AI agents.

mod args;
mod mcp;
mod runner;
mod terminal;

use std::collections::BTreeMap;
use std::process::ExitCode;

use args::{Args, CliError, CliResult};
use keylo_core::access::{self, AccessKey, KeyScope, SecretOperation};
use keylo_core::config::{HelloMode, KeyloConfig};
use keylo_core::gate::{verifier_name, AccessGate};
use keylo_core::platform;
use keylo_core::refs::{is_linked, SecretReference};
use keylo_core::secrets::{SecretDraft, SecretInfo};
use keylo_core::store::{normalize_name, SecretStore};
use keylo_core::types::{self, SecretTypeCatalog, SecretTypeDefinition};
use keylo_core::{eq_ic, paths, search, Error};
use terminal::info;
use zeroize::Zeroizing;

const FLAGS: &[&str] = &[
    "clip", "yes", "overwrite", "delete-originals", "flat", "plain", "all", "json", "force", "dry-run",
    "password-stdin", "both", "add-to-claude", "help", "stdio", "ask", "no-ask",
];

fn usage_text() -> String {
    let p = platform::current();
    format!(
        "keylo - local secrets in {store}

keylo list [search...] [--category C] [--json]
                                        List secrets (search matches name, category, username, notes,
                                        non-secret fields; \"type:login\" and \"cat:dev\" narrow it)
keylo categories                        List categories with counts
keylo types                             List secret types and their fields
keylo get NAME [--clip] [--out FILE] [--field F] [--both]
                                        Print the value (a typed secret's main field, or --field F)
keylo set NAME [--category C] [--username U] [--notes N] [--file FILE]
                                        Add or update (value is prompted, piped, or read from FILE)
keylo set NAME --type T [--field F=V]... [--category C] [--notes N] [--file FILE]
                                        Add a typed secret (the main secret field is prompted)
keylo edit NAME [--rename NEW] [--category C] [--username U] [--notes N] [--field F=V]...
keylo rm NAME [--yes]                   Delete a secret
keylo run --env VAR=NAME [...] -- CMD [ARGS]
                                        Run CMD with secrets as environment variables
                                        (NAME:FIELD maps one field, e.g. prod-db:password)
keylo keys                              List access keys (let tools use secrets without {verifier})
keylo keys create NAME [--all | --category C... --secret S...] [--expires-days N]
keylo keys revoke NAME
keylo mcp                               The MCP server for AI agents
keylo unlock | lock | status | version
keylo config [hello session|always|never | session-minutes N | clipboard-seconds N | audit-days N|forever]

Not in the Rust build yet: import, link, push, provider, backup, restore (use the C# keylo).",
        store = p.store_name(),
        verifier = p.verifier_name()
    )
}

fn main() -> ExitCode {
    keylo_platform::install();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(code) => ExitCode::from(code as u8),
        Err(CliError::Usage(m)) => {
            info(&format!("keylo: {m}"));
            ExitCode::from(2)
        }
        Err(CliError::Keylo(e)) => {
            info(&format!("keylo: {e}"));
            ExitCode::from(1)
        }
    }
}

fn run(argv: &[String]) -> CliResult<i32> {
    let Some(first) = argv.first() else {
        println!("{}", usage_text());
        info("The Rust build has no app yet; everything is in the keylo command.");
        return Ok(0);
    };
    let command = first.to_lowercase();
    let args = Args::parse(&argv[1..], FLAGS)?;
    if args.flag("help") || matches!(command.as_str(), "help" | "-h" | "--help" | "/?") {
        println!("{}", usage_text());
        return Ok(0);
    }

    let mut c = Context::new()?;
    match command.as_str() {
        "version" | "--version" | "-v" => {
            println!("keylo {}", keylo_core::build_version!());
            Ok(0)
        }
        "list" | "ls" | "search" => list(&mut c, &args),
        "categories" | "cats" => categories(&mut c, &args),
        "types" => types_cmd(&c, &args),
        "get" => get(&mut c, &args),
        "set" | "add" => set(&mut c, &args),
        "edit" => edit(&mut c, &args),
        "rm" | "delete" | "remove" => remove(&mut c, &args),
        "run" => run_cmd(&mut c, &args),
        "keys" | "key" => keys(&mut c, &args),
        "mcp" => {
            if args.flag("stdio") || terminal::input_redirected() {
                mcp::serve(c)
            } else {
                mcp::explain(&c.config);
                Ok(0)
            }
        }
        "unlock" => unlock(&mut c, &args),
        "lock" => {
            args.throw_on_unknown(None)?;
            c.gate.lock();
            info("Locked.");
            Ok(0)
        }
        "status" => status(&c, &args),
        "config" => config_cmd(&mut c, &args),
        "__clip-clear" => clip_clear(&args),
        "import" | "link" | "push" | "provider" | "providers" | "backup" | "export" | "restore" => {
            fail!("'{first}' isn't in the Rust build of keylo yet; use the C# keylo for it.")
        }
        _ => usage!("Unknown command '{first}'. Run 'keylo help'."),
    }
}

pub struct Context {
    pub config: KeyloConfig,
    pub store: SecretStore,
    pub types: SecretTypeCatalog,
    pub gate: AccessGate,
}

impl Context {
    pub fn new() -> CliResult<Self> {
        let config = KeyloConfig::load()?;
        let gate = AccessGate::new(&config);
        Ok(Context { config, store: SecretStore::default(), types: SecretTypeCatalog::default(), gate })
    }

    /// The access key in KEYLO_ACCESS_KEY, if it's valid and unexpired.
    pub fn key(&self) -> Option<AccessKey> {
        access::from_environment(&self.config).cloned()
    }

    /// For commands that change secrets or settings: access keys never apply.
    pub fn browse(&mut self) -> CliResult<()> {
        Ok(self.gate.ensure(0, "Unlock Keylo", false)?)
    }

    /// What this caller may see: everything once unlocked; for a caller with an access key, only
    /// what the key covers (without prompting); otherwise prompts.
    pub fn visible_secrets(&mut self) -> CliResult<Vec<SecretInfo>> {
        if !self.gate.is_unlocked() {
            if let Some(key) = self.key() {
                return Ok(self.store.list()?.into_iter().filter(|s| key.covers(s)).collect());
            }
        }
        self.browse()?;
        Ok(self.store.list()?)
    }

    /// Allows a value operation via the access key (audited) or the identity check.
    pub fn authorize(&mut self, op: SecretOperation, secrets: &[SecretInfo], what: &str) -> CliResult<()> {
        if let Some(key) = self.key() {
            if key.allows(op, secrets) {
                let names: Vec<String> = secrets.iter().map(|s| s.name.clone()).collect();
                access::audit(op.as_str(), &names, Some(&key), "access key")?;
                return Ok(());
            }
        } else if access::is_present_in_environment() {
            info(&format!(
                "keylo: {} isn't a valid, unexpired access key; asking {} instead.",
                access::ENVIRONMENT_VARIABLE,
                platform::current().verifier_name()
            ));
        }
        Ok(self.gate.ensure(0, &format!("Keylo: {what}"), true)?)
    }

    pub fn find_reference(&self, text: &str) -> CliResult<(SecretInfo, SecretReference)> {
        let r = SecretReference::parse(text, |n| self.store.exists(n).unwrap_or(false))
            .ok_or_else(|| CliError::Keylo(Error::NotFound(text.to_string())))?;
        let info = self.store.find(&r.name)?.ok_or_else(|| CliError::Keylo(Error::NotFound(r.name.clone())))?;
        if is_linked(&info) {
            fail!("'{}' is linked to another vault; linked secrets aren't in the Rust build yet.", info.name);
        }
        if r.environment.is_some() {
            fail!("'{}' isn't a per-environment link, so '@{}' doesn't apply.", info.name, r.environment.unwrap());
        }
        Ok((info, r))
    }

    /// A secret's main value, or one field, as text.
    pub fn field_value(&self, info: &SecretInfo, field: Option<&str>) -> CliResult<Zeroizing<String>> {
        let field = field.map(str::to_lowercase);
        if matches!(field.as_deref(), Some("username" | "key")) {
            return match &info.username {
                Some(u) => Ok(Zeroizing::new(u.clone())),
                None => fail!("'{}' has no username.", info.name),
            };
        }
        let t = self.types.find(info.type_id.as_deref())?;
        let secret = self.store.get(&info.name)?;
        let Some(t) = t else {
            if !matches!(field.as_deref(), None | Some("value")) {
                fail!("'{}' is a plain secret; it only has value and username.", info.name);
            }
            return match types::decode_text(&secret.value) {
                Some(v) => Ok(Zeroizing::new(v)),
                None => fail!("'{}' is binary and can't be an environment variable.", info.name),
            };
        };
        let chosen = pick_field(&t, &info.name, field.as_deref())?;
        let mut fields = types::read_fields(&t, info, &secret.value, true);
        match chosen.and_then(|f| fields.remove(&f.id)) {
            Some(v) => Ok(Zeroizing::new(v)),
            None => fail!("'{}' has no {}.", info.name, chosen.map(|f| f.label.as_str()).unwrap_or("value")),
        }
    }
}

fn pick_field<'a>(
    t: &'a SecretTypeDefinition,
    name: &str,
    field: Option<&str>,
) -> CliResult<Option<&'a types::FieldDefinition>> {
    match field {
        None | Some("value") => Ok(t.primary()),
        Some(f) => match t.field(f) {
            Some(d) => Ok(Some(d)),
            None => {
                let ids: Vec<&str> = t.fields.iter().map(|f| f.id.as_str()).collect();
                fail!("{} '{name}' has no field '{f}'. Fields: {}.", t.name, ids.join(", "))
            }
        },
    }
}

// ---------------------------------------------------------------------------- commands

fn list(c: &mut Context, args: &Args) -> CliResult<i32> {
    let category = args.option("category");
    let json = args.flag("json");
    args.throw_on_unknown(None)?;
    let query = args.positionals_from(0).join(" ");
    let all = c.visible_secrets()?;
    let secrets = search::filter(&all, Some(&query), category.as_deref());

    if json {
        println!("{}", serde_json::to_string_pretty(&secrets).unwrap());
        return Ok(0);
    }
    if secrets.is_empty() {
        info(if !query.is_empty() || category.is_some() {
            "No matching secrets."
        } else {
            "No secrets yet. Add one with 'keylo set NAME'."
        });
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = secrets
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                s.type_id.clone().unwrap_or_default(),
                s.category.clone().unwrap_or_default(),
                s.username.clone().unwrap_or_default(),
                s.updated_at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string(),
            ]
        })
        .collect();
    terminal::print_table(&["NAME", "TYPE", "CATEGORY", "USERNAME", "UPDATED"], &rows);
    Ok(0)
}

fn categories(c: &mut Context, args: &Args) -> CliResult<i32> {
    args.throw_on_unknown(None)?;
    let mut groups: Vec<(String, usize)> = Vec::new();
    for s in c.visible_secrets()? {
        let key = s.category.unwrap_or_else(|| "(none)".into());
        match groups.iter_mut().find(|(k, _)| eq_ic(k, &key)) {
            Some(g) => g.1 += 1,
            None => groups.push((key, 1)),
        }
    }
    groups.sort_by_key(|(k, _)| (k == "(none)", k.to_lowercase()));
    let rows: Vec<Vec<String>> = groups.into_iter().map(|(k, n)| vec![k, n.to_string()]).collect();
    terminal::print_table(&["CATEGORY", "SECRETS"], &rows);
    Ok(0)
}

fn types_cmd(c: &Context, args: &Args) -> CliResult<i32> {
    args.throw_on_unknown(None)?;
    for t in c.types.all()? {
        println!("{}  ({}{})", t.id, t.name, if t.is_built_in { "" } else { ", custom" });
        let primary = t.primary().map(|p| p.id.clone());
        for f in &t.fields {
            let main = if Some(&f.id) == primary.as_ref() { ", main value" } else { "" };
            let opts = f.options.as_ref().filter(|o| !o.is_empty()).map(|o| format!("  [{}]", o.join(", "))).unwrap_or_default();
            println!("    {:<20} {:?}{main}{opts}", f.id, f.kind);
        }
    }
    println!();
    println!("Add one: keylo set NAME --type login --field username=alice --field url=https://…  (the main value is prompted)");
    println!("Custom types are managed in the app (Settings → Secret types).");
    Ok(0)
}

fn get(c: &mut Context, args: &Args) -> CliResult<i32> {
    let name = args.positional(0, "secret name")?;
    let clip = args.flag("clip");
    let mut field = args.option("field").map(|f| f.to_lowercase());
    let out_file = args.option("out");
    let both = args.flag("both");
    args.throw_on_unknown(Some(1))?;
    if both && (clip || out_file.is_some() || field.is_some()) {
        usage!("--both prints to the terminal; it can't be combined with --clip, --out or --field.");
    }

    let (info, reference) = c.find_reference(&name)?;
    if field.is_none() {
        field = reference.field.map(|f| f.to_lowercase());
    }
    let t = c.types.find(info.type_id.as_deref())?;

    if matches!(field.as_deref(), Some("username" | "key")) {
        let Some(user) = info.username.clone() else { fail!("'{name}' has no username.") };
        c.authorize(SecretOperation::Get, std::slice::from_ref(&info), &format!("read the username of '{name}'"))?;
        return if clip { copy_with_timeout(c, &user, "Username") } else {
            println!("{user}");
            Ok(0)
        };
    }
    if t.is_none() && !matches!(field.as_deref(), None | Some("value")) {
        usage!("'{name}' is a plain secret; --field must be value or username.");
    }

    c.authorize(SecretOperation::Get, std::slice::from_ref(&info), &format!("read '{name}'"))?;
    let secret = c.store.get(&info.name)?;

    if both {
        match &t {
            None => {
                let Some(value) = types::decode_text(&secret.value).map(Zeroizing::new) else {
                    fail!("'{name}' is binary; use --out FILE instead.")
                };
                if let Some(u) = &info.username {
                    println!("key: {u}");
                }
                println!("value: {}", *value);
            }
            Some(t) => {
                let fields = types::read_fields(t, &info, &secret.value, true);
                println!("type: {}", t.id);
                for f in &t.fields {
                    if let Some(v) = fields.get(&f.id) {
                        println!("{}: {v}", f.id);
                    }
                }
            }
        }
        return Ok(0);
    }

    let Some(t) = t else {
        if let Some(path) = out_file {
            std::fs::write(&path, &*secret.value)?;
            terminal::info(&format!("Wrote {} bytes to {}", secret.value.len(), absolute(&path)));
            return Ok(0);
        }
        if clip {
            let Some(text) = types::decode_text(&secret.value).map(Zeroizing::new) else {
                fail!("'{name}' is binary; use --out FILE instead.")
            };
            return copy_with_timeout(c, &text, "Value");
        }
        terminal::write_raw(&secret.value)?;
        return Ok(0);
    };

    let chosen = pick_field(&t, &name, field.as_deref())?;
    let mut fields = types::read_fields(&t, &info, &secret.value, true);
    let Some((label, value)) = chosen.and_then(|f| fields.remove(&f.id).map(|v| (f.label.clone(), Zeroizing::new(v)))) else {
        fail!("'{name}' has no {}.", chosen.map(|f| f.label.as_str()).unwrap_or("value"))
    };
    if let Some(path) = out_file {
        std::fs::write(&path, value.as_bytes())?;
        terminal::info(&format!("Wrote {label} to {}", absolute(&path)));
        return Ok(0);
    }
    if clip {
        return copy_with_timeout(c, &value, &label);
    }
    println!("{}", *value);
    Ok(0)
}

fn absolute(path: &str) -> String {
    std::path::absolute(path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.to_string())
}

fn parse_field_args(t: &SecretTypeDefinition, pairs: &[String]) -> CliResult<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for pair in pairs {
        let Some(eq) = pair.find('=').filter(|&e| e > 0) else { usage!("--field expects NAME=VALUE, got '{pair}'.") };
        let id = pair[..eq].trim();
        let Some(f) = t.field(id) else {
            let ids: Vec<&str> = t.fields.iter().map(|f| f.id.as_str()).collect();
            usage!("{} has no field '{id}'. Fields: {}.", t.name, ids.join(", "));
        };
        if f.is_secret() {
            info(&format!("keylo: note that '{}' given on the command line is visible in your shell history.", f.id));
        }
        fields.insert(f.id.clone(), pair[eq + 1..].to_string());
    }
    Ok(fields)
}

fn set(c: &mut Context, args: &Args) -> CliResult<i32> {
    let name = normalize_name(&args.positional(0, "secret name")?)?;
    let category = args.option("category");
    let username = args.option("username");
    let notes = args.option("notes");
    let file = args.option("file");
    let type_name = args.option("type");
    let field_args = args.options("field");
    args.throw_on_unknown(Some(1))?;
    c.browse()?;

    let existing = c.store.find(&name)?;
    let original = existing.as_ref().map(|e| e.name.clone());
    if type_name.is_none() && field_args.is_empty() {
        let value = match &file {
            Some(f) => Zeroizing::new(std::fs::read(f)?),
            None => terminal::read_secret(
                &if existing.is_none() { format!("Value for '{name}': ") } else { format!("New value for '{name}': ") },
                true,
            )?,
        };
        let e = existing.as_ref();
        let draft = SecretDraft {
            name: name.clone(),
            value,
            category: category.or_else(|| e.and_then(|e| e.category.clone())),
            username: username.or_else(|| e.and_then(|e| e.username.clone())),
            notes: notes.or_else(|| e.and_then(|e| e.notes.clone())),
            icon: e.and_then(|e| e.icon.clone()),
            color: e.and_then(|e| e.color.clone()),
            ..Default::default()
        };
        c.store.save(&draft, original.as_deref())?;
    } else {
        let t = match &type_name {
            Some(n) => c.types.resolve(n)?,
            None => c.types.find(existing.as_ref().and_then(|e| e.type_id.as_deref()))?,
        };
        let Some(t) = t else {
            match type_name {
                None => usage!("--field needs --type (e.g. --type login). See 'keylo types'."),
                Some(n) => usage!("No type '{n}'. See 'keylo types'."),
            }
        };
        let mut fields = parse_field_args(&t, &field_args)?;
        if let (Some(u), Some(uf)) = (username, t.username_field()) {
            fields.insert(uf.id.clone(), u);
        }
        if let Some(p) = t.primary() {
            if !fields.contains_key(&p.id) {
                let v = match &file {
                    Some(f) => std::fs::read_to_string(f)?,
                    None => String::from_utf8_lossy(&terminal::read_secret(&format!("{} for '{name}': ", p.label), true)?).into_owned(),
                };
                fields.insert(p.id.clone(), v);
            }
        }
        let e = existing.as_ref();
        let draft = types::typed_draft(
            &t,
            &name,
            &fields,
            category.or_else(|| e.and_then(|e| e.category.clone())),
            notes.or_else(|| e.and_then(|e| e.notes.clone())),
            e.and_then(|e| e.icon.clone()),
            e.and_then(|e| e.color.clone()),
        )?;
        c.store.save(&draft, original.as_deref())?;
    }
    info(&if existing.is_none() { format!("Added '{name}'.") } else { format!("Updated '{name}'.") });
    Ok(0)
}

fn edit(c: &mut Context, args: &Args) -> CliResult<i32> {
    let name = args.positional(0, "secret name")?;
    let rename = args.option("rename");
    let category = args.option("category");
    let username = args.option("username");
    let notes = args.option("notes");
    let field_args = args.options("field");
    args.throw_on_unknown(Some(1))?;
    if rename.is_none() && category.is_none() && username.is_none() && notes.is_none() && field_args.is_empty() {
        usage!("Nothing to change. Use --rename, --category, --username, --notes or --field.");
    }
    c.browse()?;
    let secret = c.store.get(&name)?;
    let i = &secret.info;
    let t = c.types.find(i.type_id.as_deref())?;

    let draft = if !field_args.is_empty() {
        let Some(t) = t else { usage!("'{name}' is a plain secret; --field only applies to typed secrets.") };
        let mut fields = types::read_fields(&t, i, &secret.value, false);
        fields.extend(parse_field_args(&t, &field_args)?); // "" clears
        if let (Some(u), Some(uf)) = (username, t.username_field()) {
            fields.insert(uf.id.clone(), u);
        }
        fields.retain(|_, v| !v.is_empty());
        types::typed_draft(
            &t,
            rename.as_deref().unwrap_or(&i.name),
            &fields,
            category.or_else(|| i.category.clone()),
            notes.or_else(|| i.notes.clone()),
            i.icon.clone(),
            i.color.clone(),
        )?
    } else {
        let mut d = SecretDraft::from_secret(&secret);
        if let Some(r) = rename {
            d.name = r;
        }
        if category.is_some() {
            d.category = category;
        }
        if username.is_some() {
            d.username = username;
        }
        if notes.is_some() {
            d.notes = notes;
        }
        d
    };
    let saved = c.store.save(&draft, Some(&i.name))?;
    info(&format!("Updated '{}'.", saved.name));
    Ok(0)
}

fn remove(c: &mut Context, args: &Args) -> CliResult<i32> {
    let name = args.positional(0, "secret name")?;
    let yes = args.flag("yes");
    args.throw_on_unknown(Some(1))?;
    c.browse()?;
    if c.store.find(&name)?.is_none() {
        return Err(Error::NotFound(name).into());
    }
    if !yes && !terminal::confirm(&format!("Delete '{name}'?")) {
        info("Not deleted.");
        return Ok(1);
    }
    c.store.delete(&name)?;
    info(&format!("Deleted '{name}'."));
    Ok(0)
}

fn run_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let mappings = args.options("env");
    args.throw_on_unknown(None)?;
    if mappings.is_empty() {
        usage!("Map at least one secret: --env VAR=NAME");
    }
    if args.positional_count() > 0 {
        usage!("Put the command after '--': keylo run --env VAR=NAME -- CMD");
    }
    if args.rest.first().map(String::as_str) == Some("YOUR-COMMAND") {
        usage!("Replace YOUR-COMMAND with the program that needs the secret, e.g. ... -- node deploy.js (it reads the variables from its environment).");
    }

    let mut pairs = Vec::new();
    for m in &mappings {
        let Some(eq) = m.find('=').filter(|&e| e > 0 && e < m.len() - 1) else { usage!("--env expects VAR=NAME, got '{m}'.") };
        let (info, r) = c.find_reference(&m[eq + 1..])?;
        pairs.push((m[..eq].to_string(), info, r.field));
    }
    let mut infos: Vec<SecretInfo> = Vec::new();
    for (_, i, _) in &pairs {
        if !infos.iter().any(|x| eq_ic(&x.name, &i.name)) {
            infos.push(i.clone());
        }
    }
    let labels: Vec<String> = infos.iter().map(|i| i.name.clone()).collect();
    c.authorize(SecretOperation::Run, &infos, &format!("run with {}", labels.join(", ")))?;

    let mut env = BTreeMap::new();
    for (var, info, field) in &pairs {
        env.insert(var.clone(), c.field_value(info, field.as_deref())?.to_string());
    }
    let code = runner::run(&args.rest, &env);
    for v in env.values_mut() {
        zeroize::Zeroize::zeroize(v);
    }
    code
}

fn keys(c: &mut Context, args: &Args) -> CliResult<i32> {
    let action = args.optional_positional(0).map(|a| a.to_lowercase()).unwrap_or_else(|| "list".into());
    match action.as_str() {
        "list" | "ls" => {
            args.throw_on_unknown(Some(1))?;
            if c.config.access_keys.is_empty() {
                println!("No access keys. Create one with 'keylo keys create NAME' or in the app (Settings → Access keys).");
                return Ok(0);
            }
            let now = chrono::Local::now().fixed_offset();
            let rows: Vec<Vec<String>> = c
                .config
                .access_keys
                .iter()
                .map(|k| {
                    let covers = if k.scope == KeyScope::All {
                        "everything".to_string()
                    } else {
                        let list: Vec<String> = k.categories.iter().map(|c| format!("cat:{c}")).chain(k.secrets.iter().cloned()).collect();
                        if list.is_empty() { "nothing (asks each time)".into() } else { list.join(", ") }
                    };
                    let expires = match k.expires {
                        Some(e) if k.is_expired(now) => { let _ = e; "expired".to_string() }
                        Some(e) => e.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string(),
                        None => "never".into(),
                    };
                    vec![k.name.clone(), k.id.clone(), covers, expires]
                })
                .collect();
            terminal::print_table(&["NAME", "ID", "COVERS", "EXPIRES"], &rows);
            println!();
            let var = access::ENVIRONMENT_VARIABLE;
            match c.key() {
                Some(k) => println!("This process has the key '{}' ({var}).", k.name),
                None if access::is_present_in_environment() => println!("{var} is set but isn't a valid, unexpired key."),
                None => println!("This process has no access key ({var} isn't set)."),
            }
            Ok(0)
        }
        "create" | "new" | "add" => {
            let name = args.positional(1, "key name")?.trim().to_string();
            let cats = args.options("category");
            let secrets = args.options("secret");
            let all = args.flag("all");
            let expires = args.option("expires-days");
            if args.flag("add-to-claude") {
                fail!("--add-to-claude isn't in the Rust build yet; register the key with 'claude mcp add' as shown below.");
            }
            args.throw_on_unknown(Some(2))?;
            if name.is_empty() {
                usage!("Give the key a name, e.g. 'Claude Code'.");
            }
            if c.config.access_keys.iter().any(|k| eq_ic(&k.name, &name)) {
                usage!("There's already a key called '{name}'. Revoke it first, or pick another name.");
            }
            let days = match expires {
                None => None,
                Some(d) => match d.parse::<i64>() {
                    Ok(n) if n > 0 => Some(n),
                    _ => usage!("--expires-days must be a positive number."),
                },
            };
            c.gate.confirm(0, &format!("Keylo: create access key '{name}'"))?;
            let (mut key, token) = access::create(&name, days);
            key.categories = dedup_ic(cats);
            key.secrets = dedup_ic(secrets);
            key.scope = if all { KeyScope::All } else { KeyScope::Selected };
            c.config.access_keys.push(key);
            c.config.save()?;
            info(&format!("Created '{name}'. This is the only time the key is shown:"));
            println!("{token}");
            info("Register it with Claude Code (user scope; never put it in a project's .mcp.json):");
            info(&format!(
                "  claude mcp add keylo --scope user --env {}={token} -- \"{}\" mcp",
                access::ENVIRONMENT_VARIABLE,
                self_path()
            ));
            Ok(0)
        }
        "revoke" | "rm" | "delete" => {
            let which = args.positional(1, "key name or id")?;
            args.throw_on_unknown(Some(2))?;
            let Some(pos) = c.config.access_keys.iter().position(|k| k.id == which || eq_ic(&k.name, &which)) else {
                fail!("No access key '{which}'. See 'keylo keys'.")
            };
            let key_name = c.config.access_keys[pos].name.clone();
            c.gate.confirm(0, &format!("Keylo: revoke access key '{key_name}'"))?;
            c.config.access_keys.remove(pos);
            c.config.save()?;
            info(&format!(
                "Revoked '{key_name}'. Anything still using it now gets {} prompts or approval requests.",
                platform::current().verifier_name()
            ));
            Ok(0)
        }
        _ => usage!("Usage: keylo keys [list | create NAME ... | revoke NAME]"),
    }
}

fn dedup_ic(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if !out.iter().any(|o| eq_ic(o, &i)) {
            out.push(i);
        }
    }
    out
}

pub fn self_path() -> String {
    std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "keylo".into())
}

fn unlock(c: &mut Context, args: &Args) -> CliResult<i32> {
    args.throw_on_unknown(None)?;
    if c.gate.mode() == HelloMode::Never {
        info(&format!("{} is off (hello = never); nothing to unlock.", verifier_name()));
        return Ok(0);
    }
    c.gate.lock();
    c.gate.unlock(0, "Unlock Keylo")?;
    info(&match c.gate.session_expires_at() {
        Some(until) => format!("Unlocked until {}.", until.with_timezone(&chrono::Local).format("%H:%M")),
        None => "Verified.".into(),
    });
    Ok(0)
}

fn status(c: &Context, args: &Args) -> CliResult<i32> {
    args.throw_on_unknown(None)?;
    let v = platform::current().verifier_name();
    let state = match c.gate.mode() {
        HelloMode::Never => format!("no {v} prompt (hello = never)"),
        HelloMode::Always => format!("{v} on every value access (hello = always)"),
        HelloMode::Session => match c.gate.session_expires_at() {
            Some(until) => format!("unlocked until {}", until.with_timezone(&chrono::Local).format("%H:%M")),
            None => "locked".into(),
        },
    };
    println!("Keylo {}: {state}", keylo_core::build_version!());
    println!("Data:  {}", paths::data_dir().display());
    Ok(0)
}

fn config_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let key = args.optional_positional(0).map(|k| k.to_lowercase());
    let value = args.optional_positional(1);
    args.throw_on_unknown(Some(2))?;
    let Some(key) = key else {
        let cfg = &c.config;
        println!("hello             {}", format!("{:?}", cfg.hello).to_lowercase());
        println!("session-minutes   {}", cfg.session_minutes);
        println!("clipboard-seconds {}", cfg.clipboard_seconds);
        let days = if cfg.audit_retention_days == 0 { "forever".to_string() } else { cfg.audit_retention_days.to_string() };
        println!("audit-days        {days}");
        return Ok(0);
    };
    let Some(value) = value else { usage!("Missing value for {key}.") };

    // These settings decide when verification happens, so changing them always verifies.
    c.gate.confirm(0, "Keylo: change settings")?;
    let number = |what: &str| value.parse::<i64>().map_err(|_| CliError::Usage(format!("Expected a number of {what}.")));
    match key.as_str() {
        "hello" => {
            c.config.hello = match value.to_lowercase().as_str() {
                "session" => HelloMode::Session,
                "always" => HelloMode::Always,
                "never" => HelloMode::Never,
                _ => usage!("hello must be session, always or never."),
            }
        }
        "session-minutes" => c.config.session_minutes = number("minutes")?,
        "clipboard-seconds" => c.config.clipboard_seconds = number("seconds")?,
        "audit-days" => {
            c.config.audit_retention_days = if value.eq_ignore_ascii_case("forever") {
                0
            } else {
                match value.parse::<i64>() {
                    Ok(d) if d >= 0 => d,
                    _ => usage!("Expected a number of days, or forever."),
                }
            }
        }
        _ => usage!("Settings: hello, session-minutes, clipboard-seconds, audit-days."),
    }
    c.config.save()?;
    c.gate.lock();
    info(&format!("Saved. {key} = {value}"));
    Ok(0)
}

fn copy_with_timeout(c: &Context, text: &str, what: &str) -> CliResult<i32> {
    let token = platform::current().clipboard().set_text(text)?;
    let seconds = c.config.clipboard_seconds;
    // A separate hidden process clears the clipboard, so this command can return immediately.
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(["__clip-clear", &token.to_string(), &seconds.to_string()]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    cmd.spawn()?;
    info(&format!("{what} copied. The clipboard clears in {seconds}s."));
    Ok(0)
}

fn clip_clear(args: &Args) -> CliResult<i32> {
    let token: u32 = args.positional(0, "token")?.parse().map_err(|_| CliError::Usage("Bad token.".into()))?;
    let seconds: u64 = args.positional(1, "seconds")?.parse().map_err(|_| CliError::Usage("Bad seconds.".into()))?;
    std::thread::sleep(std::time::Duration::from_secs(seconds));
    platform::current().clipboard().clear_if_unchanged(token);
    Ok(0)
}
