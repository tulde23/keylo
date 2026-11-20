//! keylo: the command line for Keylo's secrets, and (keylo mcp) the MCP server for AI agents.

mod args;
mod mcp;
mod runner;
mod sync_cmd;
mod terminal;
mod vaults;

use std::collections::BTreeMap;
use std::process::ExitCode;

use args::{Args, CliError, CliResult};
use keylo_core::access::{self, AccessKey, KeyScope, SecretOperation};
use keylo_core::config::{HelloMode, KeyloConfig};
use keylo_core::gate::{verifier_name, AccessGate};
use keylo_core::platform;
use keylo_core::links::{self, VaultEnvironment};
use keylo_core::refs::SecretReference;
use keylo_core::secrets::{SecretDraft, SecretInfo};
use keylo_core::store::{normalize_name, SecretStore};
use keylo_core::types::{self, SecretTypeCatalog, SecretTypeDefinition};
use keylo_core::categories::CategoryCatalog;
use keylo_core::import::{self, ImportOptions};
use keylo_core::{backup, eq_ic, paths, search, Error};
use terminal::info;
use zeroize::Zeroizing;

const FLAGS: &[&str] = &[
    "clip", "yes", "overwrite", "delete-originals", "flat", "plain", "all", "json", "force", "dry-run",
    "password-stdin", "both", "add-to-claude", "help", "stdio", "ask", "no-ask", "check", "set",
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
keylo otp NAME [--clip] | NAME --set     A login's current two-factor code; --set stores its setup key
keylo set NAME [--category C] [--username U] [--notes N] [--file FILE]
                                        Add or update (value is prompted, piped, or read from FILE)
keylo set NAME --type T [--field F=V]... [--category C] [--notes N] [--file FILE]
                                        Add a typed secret (the main secret field is prompted)
keylo edit NAME [--rename NEW] [--category C] [--username U] [--notes N] [--field F=V]...
keylo rm NAME [--yes]                   Delete a secret
keylo run --env VAR=NAME [...] -- CMD [ARGS]
                                        Run CMD with secrets as environment variables
                                        (NAME:FIELD maps one field, e.g. prod-db:password;
                                        NAME@ENV picks an environment of a per-environment link)
keylo link NAME --item ITEM [--provider 1password|aws] [--vault V] [--account A] [--field F] [--category C]
                                        Link to an item in another vault (read live, never copied)
keylo link --search QUERY [--provider P] [--account A]   Find items to link
                                        (aws: --profile P --region R, else the provider settings)
keylo link NAME --provider aws --item SECRET --environment ENV [--env-name ENV=OTHER-NAME]...
                                        Link per environment: NAME@dev, NAME@prod… read SECRET from
                                        each environment's account (see keylo provider env)
keylo push PROVIDER [NAME...] [--category C] [--all] [--yes]
                                        Copy secrets into 1Password or AWS Secrets Manager
keylo provider list | status ID | set ID KEY VALUE
keylo provider env aws [list | set ENV PROFILE REGION [--ask|--no-ask] | remove ENV | default ENV]
                                        Environments (dev, uat, prod…) for per-environment links
keylo keys                              List access keys (let tools use secrets without {verifier})
keylo keys create NAME [--all | --category C... --secret S...] [--expires-days N] [--add-to-claude]
keylo keys revoke NAME
keylo import PATH... [--category C | --flat] [--overwrite] [--delete-originals] [--plain]
                                        Import files as secrets (a folder's subfolders become
                                        categories; types are guessed unless --plain)
keylo import EXPORT.csv [--category C] [--overwrite] [--dry-run] [--delete-originals]
                                        Import another password manager's CSV export as logins
keylo export-passwords FILE.csv [--format bitwarden|browser] [--category C] [--force]
                                        Export as a CSV another password manager imports (plain
                                        text: delete it after importing)
keylo backup FILE [--force] [--password-stdin]
                                        Encrypted, password-protected backup of everything
keylo restore FILE [--overwrite] [--dry-run] [--password-stdin]
                                        Restore a backup (existing secrets are skipped unless --overwrite)
keylo mcp                               The MCP server for AI agents
keylo unlock | lock | status | version
keylo passphrase set | change | remove  Master passphrase for the vault (Windows), on top of your
                                        Windows account; needed to open it on a copied disk
keylo sync [status | code]              Sync now with your other devices (a shared folder; see status)
keylo sync create FOLDER [--name N]     Start syncing: a new vault in a folder your devices share
keylo sync join FOLDER [--name N]       Join it from another device (asks for the code)
keylo sync rename NAME | forget DEVICE | leave
keylo update [--check] [--yes]          Check for a newer Keylo and install it (Windows: the app and
                                        keylo, in place; macOS: from the app; Linux: the release page)
keylo config [hello session|always|never | session-minutes N | clipboard-seconds N | audit-days N|forever]",
        store = p.store_name(),
        verifier = p.verifier_name()
    )
}

fn main() -> ExitCode {
    keylo_platform::install();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // A store that needs a passphrase (Linux's vault file) may ask on the terminal, except from the
    // MCP server (its stdin and stdout are the agent's) and the clipboard clearer.
    let command = argv.first().map(|a| a.to_lowercase()).unwrap_or_default();
    keylo_platform::set_terminal_prompts(!matches!(command.as_str(), "mcp" | "__clip-clear"));
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
        "otp" | "totp" => otp_cmd(&mut c, &args),
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
        "passphrase" => passphrase_cmd(&mut c, &args),
        "lock" => {
            args.throw_on_unknown(None)?;
            c.gate.lock();
            keylo_platform::lock_store();
            info("Locked.");
            Ok(0)
        }
        "status" => status(&c, &args),
        "update" => update_cmd(&args),
        "sync" => sync_cmd::sync_cmd(&mut c, &args),
        "config" => config_cmd(&mut c, &args),
        "__clip-clear" => clip_clear(&args),
        "__hello-selftest" => {
            args.throw_on_unknown(None)?;
            info(&keylo_platform::hello_selftest()?);
            Ok(0)
        }
        "import" => import_cmd(&mut c, &args),
        "backup" | "export" => backup_cmd(&mut c, &args),
        "restore" => restore_cmd(&mut c, &args),
        "export-passwords" => export_passwords_cmd(&mut c, &args),
        "link" => vaults::link(&mut c, &args),
        "push" => vaults::push(&mut c, &args),
        "provider" | "providers" => vaults::provider_cmd(&mut c, &args),
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
        let names: Vec<String> = secrets.iter().map(|s| s.name.clone()).collect();
        self.authorize_uses(op, secrets, what, false, &names)
    }

    /// As [`authorize`], for uses that may be in an environment: with `always_ask` (an "always ask"
    /// environment such as prod) the key doesn't count. `logged` names them for the audit log
    /// ("orders-db@prod").
    pub fn authorize_uses(&mut self, op: SecretOperation, secrets: &[SecretInfo], what: &str, always_ask: bool, logged: &[String]) -> CliResult<()> {
        if let Some(key) = self.key() {
            if !always_ask && key.allows(op, secrets) {
                access::audit(op.as_str(), logged, Some(&key), "access key")?;
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

    /// "NAME", "NAME:FIELD", "NAME@ENV" or "NAME@ENV:FIELD", and for a per-environment link the
    /// environment it reads from (the named one, else the default).
    pub fn find_reference(&self, text: &str) -> CliResult<(SecretInfo, SecretReference, Option<VaultEnvironment>)> {
        // Reach the store first, so a locked vault or a wrong passphrase says so instead of "not found".
        self.store.exists(text.trim())?;
        let r = SecretReference::parse(text, |n| self.store.exists(n).unwrap_or(false))
            .ok_or_else(|| CliError::Keylo(Error::NotFound(text.to_string())))?;
        let info = self.store.find(&r.name)?.ok_or_else(|| CliError::Keylo(Error::NotFound(r.name.clone())))?;
        let env = links::environment_for(&info, &self.config, r.environment.as_deref())?;
        Ok((info, r, env))
    }

    /// A secret's main value, or one field, as text (a linked secret's read from its vault, in
    /// `environment` for a per-environment link).
    pub fn field_value(&self, info: &SecretInfo, field: Option<&str>, environment: Option<&str>) -> CliResult<Zeroizing<String>> {
        if let Some(link) = links::read(info) {
            let values = links::resolve(info, &self.config, environment)?;
            return Ok(Zeroizing::new(links::pick(info, &link, &values, field)?));
        }
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

    let (info, reference, env) = c.find_reference(&name)?;
    if field.is_none() {
        field = reference.field.map(|f| f.to_lowercase());
    }
    if let Some(link) = links::read(&info) {
        let label = match &env {
            Some(e) => format!("{}@{}", info.name, e.name),
            None => info.name.clone(),
        };
        let always_ask = env.as_ref().is_some_and(|e| e.always_ask);
        c.authorize_uses(SecretOperation::Get, std::slice::from_ref(&info), &format!("read '{label}'"), always_ask, std::slice::from_ref(&label))?;
        let values = links::resolve(&info, &c.config, env.as_ref().map(|e| e.name.as_str()))?;
        if both {
            let in_env = env.as_ref().map(|e| format!(", environment {}", e.name)).unwrap_or_default();
            println!("type: link ({}: {}{in_env})", link.target.provider, link.title);
            for (id, v) in &values {
                println!("{id}: {v}");
            }
            return Ok(0);
        }
        let value = Zeroizing::new(links::pick(&info, &link, &values, field.as_deref())?);
        if let Some(path) = out_file {
            std::fs::write(&path, value.as_bytes())?;
            terminal::info(&format!("Wrote it to {}", absolute(&path)));
            return Ok(0);
        }
        if clip {
            return copy_with_timeout(c, &value, "Value");
        }
        println!("{}", *value);
        return Ok(0);
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

/// keylo update [--check] [--yes]: the newest release, and on Windows installs it in place (the app and
/// this command; the same signed zip and checks as the app's Install).
fn update_cmd(args: &Args) -> CliResult<i32> {
    use keylo_core::updates;
    let check_only = args.flag("check");
    let yes = args.flag("yes");
    args.throw_on_unknown(Some(0))?;

    let manifest = updates::check()?;
    if !manifest.is_newer() {
        info(&format!("Keylo is up to date ({}).", updates::CURRENT));
        return Ok(0);
    }
    let latest = manifest.latest().to_string();
    info(&format!("Keylo {latest} is available (you have {}).", updates::CURRENT));
    if check_only {
        return Ok(0);
    }
    let dir = updates::program_dir()?;
    if let Some(reason) = updates::install_blocker(&dir) {
        info(&format!("{reason}\nDownload it from {}", updates::RELEASES_PAGE));
        return Ok(1);
    }
    if !cfg!(windows) {
        info(&format!("Open Keylo and choose Install and restart, or download it from {}", updates::RELEASES_PAGE));
        return Ok(1);
    }
    let Some(download) = manifest.download() else {
        info(&format!("The release has no update for this computer. Download it from {}", updates::RELEASES_PAGE));
        return Ok(1);
    };
    if !yes && !terminal::confirm(&format!("Install Keylo {latest} in {}?", dir.display())) {
        info("Not updated.");
        return Ok(1);
    }
    updates::remove_old_programs(&dir);
    info("Downloading…");
    let zip = updates::download_verified(download)?;
    updates::swap_in_place(&zip, &dir)?;
    info(&format!(
        "Updated to Keylo {latest}. If the app is open, restart it; keylo mcp servers that are running update when Claude Code restarts them."
    ));
    Ok(0)
}

/// keylo otp NAME [--clip]: a secret's current two-factor code. keylo otp NAME --set: stores the
/// setup key (asked for, so it stays out of shell history).
fn otp_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let name = args.positional(0, "secret name")?;
    let clip = args.flag("clip");
    let set = args.flag("set");
    args.throw_on_unknown(Some(1))?;
    if clip && set {
        usage!("--set stores a setup key; --clip copies a code. Use one.");
    }

    let found = c.store.find(&name)?.ok_or_else(|| Error::NotFound(name.clone()))?;
    if links::is_linked(&found) {
        fail!("'{name}' is linked to another vault; Keylo doesn't keep one-time codes for linked secrets.");
    }
    let Some(t) = c.types.find(found.type_id.as_deref())? else {
        fail!("'{name}' is a plain secret. One-time codes belong to logins: keylo set NAME --type login, then keylo otp NAME --set.")
    };
    let Some(field) = t.fields.iter().find(|f| f.kind == types::FieldKind::Totp).cloned() else {
        fail!("{} secrets have no one-time code field ('{name}' is one). Logins do, and custom types can.", t.name)
    };

    if set {
        c.browse()?;
        let key = terminal::read_secret("Setup key or otpauth:// link (from the site's two-factor setup): ", false)?;
        let key = String::from_utf8_lossy(&key).trim().to_string();
        let totp = keylo_core::totp::Totp::parse(&key)?;
        let secret = c.store.get(&found.name)?;
        let mut fields = types::read_fields(&t, &found, &secret.value, false);
        fields.insert(field.id.clone(), key);
        let draft = types::typed_draft(&t, &found.name, &fields, found.category.clone(), found.notes.clone(), found.icon.clone(), found.color.clone())?;
        c.store.save(&draft, Some(&found.name))?;
        let now = totp.now();
        info(&format!("Saved. To finish turning on two-factor sign-in, enter the code {} ({}s left) on the site.", now.code, now.seconds_left));
        return Ok(0);
    }

    c.authorize(SecretOperation::Get, std::slice::from_ref(&found), &format!("read the one-time code of '{name}'"))?;
    let secret = c.store.get(&found.name)?;
    let Some(key) = types::read_fields(&t, &found, &secret.value, false).remove(&field.id) else {
        fail!("'{name}' has no one-time code yet. Add its setup key with: keylo otp {name} --set")
    };
    let now = keylo_core::totp::Totp::parse(&key)?.now();
    if clip {
        copy_with_timeout(c, &now.code, "Code")?;
    } else {
        println!("{}", now.code);
    }
    info(&format!("Valid for {} more seconds.", now.seconds_left));
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

fn import_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let paths = args.positionals_from(0);
    let category = args.option("category");
    let mut options = ImportOptions::new();
    options.overwrite = args.flag("overwrite");
    options.subfolder_categories = !args.flag("flat");
    options.infer_types = !args.flag("plain");
    let delete_originals = args.flag("delete-originals");
    let dry_run = args.flag("dry-run");
    args.throw_on_unknown(None)?;
    if paths.is_empty() {
        usage!("Give one or more files or folders to import.");
    }
    if args.flag("flat") && category.is_some() {
        usage!("Use --category or --flat, not both.");
    }
    // One CSV exported from another password manager: its rows become logins.
    if paths.len() == 1 && options.infer_types {
        let path = std::path::PathBuf::from(&paths[0]);
        if path.is_file() && keylo_core::pm_import::detect(&path).is_some() {
            return import_passwords(c, &path, category.as_deref(), options.overwrite, dry_run, delete_originals);
        }
    }
    if dry_run {
        usage!("--dry-run is for password exports (a CSV from another password manager) and restore.");
    }
    options.category = category;
    c.browse()?;

    let result = import::import(&c.store, &c.types, &paths, &options)?;
    for item in &result.imported {
        let t = item.type_id.as_ref().map(|t| format!("  ({t})")).unwrap_or_default();
        let cat = item.category.as_ref().map(|c| format!("  [{c}]")).unwrap_or_default();
        info(&format!("  + {}{t}{cat}", item.name));
    }
    for skip in &result.skipped {
        info(&format!("  - {}: {}", skip.source_path, skip.reason));
    }
    info(&format!("Imported {}, skipped {}.", result.imported.len(), result.skipped.len()));

    if delete_originals && !result.imported.is_empty() {
        let failed = import::delete_originals(&result.imported);
        for f in &failed {
            info(&format!("  ! couldn't delete {}: {}", f.source_path, f.reason));
        }
        info(&format!("Deleted {} original file(s).", result.imported.len() - failed.len()));
    } else if !result.imported.is_empty() {
        info("The original files are untouched. Re-run with --delete-originals once you've checked the import.");
    }
    Ok(if result.skipped.is_empty() { 0 } else { 1 })
}

/// keylo import EXPORT.csv: another password manager's export, one login (or note) per row.
fn import_passwords(c: &mut Context, path: &std::path::Path, category: Option<&str>, overwrite: bool, dry_run: bool, delete: bool) -> CliResult<i32> {
    use keylo_core::pm_import;
    c.browse()?;
    let result = if dry_run { pm_import::plan(path, category, &c.store)? } else { pm_import::import(path, category, overwrite, &c.store)? };
    info(&format!("Export from: {}.", result.format));
    for item in &result.items {
        let mark = if item.exists && !overwrite { "=" } else { "+" };
        let mut extra = Vec::new();
        if item.type_id != "login" {
            extra.push(item.type_id.clone());
        }
        if let Some(u) = &item.username {
            extra.push(u.clone());
        }
        if item.has_one_time_code {
            extra.push("one-time code".into());
        }
        if item.exists {
            extra.push(if overwrite { "replaces the existing one".into() } else { "exists; skipped (--overwrite replaces it)".into() });
        }
        let cat = item.category.as_ref().map(|c| format!("  [{c}]")).unwrap_or_default();
        info(&format!("  {mark} {}{}{cat}", item.name, if extra.is_empty() { String::new() } else { format!("  ({})", extra.join(", ")) }));
        for w in &item.warnings {
            info(&format!("      {w}"));
        }
    }
    for s in &result.skipped {
        let what = if s.title.is_empty() { format!("row {}", s.row) } else { format!("row {} ({})", s.row, s.title) };
        info(&format!("  - {what}: {}", s.reason));
    }
    if dry_run {
        let would = result.items.iter().filter(|i| !i.exists || overwrite).count();
        info(&format!("Would import {would}, skip {}. Nothing was changed.", result.items.len() - would + result.skipped.len()));
        return Ok(0);
    }
    info(&format!("Imported {}, skipped {}.", result.imported, result.items.len() - result.imported + result.skipped.len()));
    if delete && result.imported > 0 {
        std::fs::remove_file(path)?;
        info(&format!("Deleted {} (it held every password in plain text).", path.display()));
    } else {
        info(&format!(
            "{} holds every password in plain text: delete it (and empty the recycle bin) once you've checked the import, or re-run with --delete-originals.",
            path.display()
        ));
    }
    Ok(if result.skipped.is_empty() { 0 } else { 1 })
}

fn backup_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let path = backup::with_extension(std::path::Path::new(&absolute(&args.positional(0, "backup file")?)));
    let force = args.flag("force");
    let from_stdin = args.flag("password-stdin");
    args.throw_on_unknown(Some(1))?;
    if path.exists() && !force {
        usage!("{} exists. Use --force to replace it.", path.display());
    }

    // Exports every value, so it always verifies: no session shortcut.
    c.gate.confirm(0, "Keylo: back up all secrets")?;
    let password = terminal::read_password("Backup password: ", true, from_stdin)?;
    if let Some(problem) = backup::check_password(&password) {
        usage!("{problem}");
    }

    info("Encrypting\u{2026}");
    let contents = backup::collect(&c.store, &CategoryCatalog::default(), &c.types, &paths::data_dir())?;
    let s = backup::write(&contents, &path, &password, backup::DEFAULT_ITERATIONS)?;
    info(&format!(
        "Backed up {} secrets, {} categories and {} icons to {} ({:.1} KB).",
        s.secrets, s.categories, s.icons, s.path, s.bytes as f64 / 1024.0
    ));
    info("Keep the password somewhere other than Keylo. Without it the backup can't be opened.");
    Ok(0)
}

fn export_passwords_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    use keylo_core::pm_export::{self, ExportFormat};
    let mut path = std::path::PathBuf::from(absolute(&args.positional(0, "export file")?));
    if path.extension().is_none() {
        path.set_extension("csv");
    }
    let format = match args.option("format") {
        None => ExportFormat::Bitwarden,
        Some(f) => match ExportFormat::parse(&f) {
            Some(f) => f,
            None => usage!("Unknown format '{f}'. Use bitwarden or browser."),
        },
    };
    let category = args.option("category");
    let force = args.flag("force");
    args.throw_on_unknown(Some(1))?;
    if path.exists() && !force {
        usage!("{} exists. Use --force to replace it.", path.display());
    }

    // Writes values in plain text, so it always verifies: no session shortcut.
    c.gate.confirm(0, "Keylo: export passwords in plain text")?;
    let result = pm_export::export(&path, format, category.as_deref(), &c.store, &c.types)?;
    info(&format!("Exported {} secrets to {} ({} format).", result.exported, result.path, result.format));
    if !result.skipped.is_empty() {
        info(&format!("Left out {}:", result.skipped.len()));
        for s in &result.skipped {
            info(&format!("  {}: {}", s.name, s.reason));
        }
    }
    info("The file holds every exported password in plain text. Delete it once it's imported.");
    Ok(0)
}

fn restore_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let path = std::path::PathBuf::from(absolute(&args.positional(0, "backup file")?));
    let overwrite = args.flag("overwrite");
    let dry_run = args.flag("dry-run");
    let from_stdin = args.flag("password-stdin");
    args.throw_on_unknown(Some(1))?;
    if !path.is_file() {
        usage!("{} doesn't exist.", path.display());
    }
    c.browse()?;
    let password = terminal::read_password("Backup password: ", false, from_stdin)?;

    info("Decrypting\u{2026}");
    let contents = backup::read(&path, &password)?;
    let mut existing = 0;
    for s in &contents.secrets {
        if c.store.exists(&s.name)? {
            existing += 1;
        }
    }
    let total = contents.secrets.len();
    info(&format!(
        "Backup from {}: {total} secrets ({existing} already here), {} categories, {} icons.",
        contents.created_at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"),
        contents.categories.len(),
        contents.icons.len()
    ));
    if dry_run {
        let verb = if existing > 0 && !overwrite { "skip" } else { "replace" };
        info(&format!("Would add {} and {verb} {existing}. Nothing was changed (--dry-run).", total - existing));
        return Ok(0);
    }

    let mut catalog = CategoryCatalog::default();
    let r = backup::restore(&c.store, &mut catalog, &c.types, &paths::data_dir(), &contents, overwrite)?;
    let hint = if r.skipped > 0 && !overwrite { " (use --overwrite to replace them)" } else { "" };
    info(&format!(
        "Restored: {} added, {} replaced, {} skipped{hint}; {} new categories.",
        r.added, r.replaced, r.skipped, r.categories_added
    ));
    for e in &r.errors {
        info(&format!("  ! {e}"));
    }
    Ok(if r.errors.is_empty() { 0 } else { 1 })
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
        let (info, r, environment) = c.find_reference(&m[eq + 1..])?;
        pairs.push((m[..eq].to_string(), info, r.field, environment));
    }
    let mut infos: Vec<SecretInfo> = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    for (_, i, _, e) in &pairs {
        if !infos.iter().any(|x| eq_ic(&x.name, &i.name)) {
            infos.push(i.clone());
        }
        let label = match e {
            Some(e) => format!("{}@{}", i.name, e.name),
            None => i.name.clone(),
        };
        if !labels.iter().any(|l| eq_ic(l, &label)) {
            labels.push(label);
        }
    }
    let always_ask = pairs.iter().any(|(_, _, _, e)| e.as_ref().is_some_and(|e| e.always_ask));
    c.authorize_uses(SecretOperation::Run, &infos, &format!("run with {}", labels.join(", ")), always_ask, &labels)?;

    let mut env = BTreeMap::new();
    for (var, info, field, environment) in &pairs {
        env.insert(var.clone(), c.field_value(info, field.as_deref(), environment.as_ref().map(|e| e.name.as_str()))?.to_string());
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
            let add_to_claude = args.flag("add-to-claude");
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
            if add_to_claude {
                keylo_core::claude_code::register(&self_path(), &token)?;
                info(&format!(
                    "Created '{name}' and added Keylo to Claude Code (user scope) with it. Restart Claude Code, or run /mcp, to load it."
                ));
                return Ok(0);
            }
            info(&format!("Created '{name}'. This is the only time the key is shown:"));
            println!("{token}");
            info("Register it with Claude Code (user scope; never put it in a project's .mcp.json):");
            info(&format!("  {}", keylo_core::claude_code::add_command(&self_path(), &token)));
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
    let from_stdin = args.flag("password-stdin");
    args.throw_on_unknown(None)?;
    // A store with its own passphrase (Linux's vault file) first.
    if let Some(message) = keylo_platform::unlock_store()? {
        info(&message);
    }
    // A master passphrase (the Windows vault): ask for it when the vault isn't already unlocked.
    if keylo_platform::vault_has_passphrase()? && !keylo_platform::unlock_vault(None)? {
        let pass = terminal::read_password("Master passphrase: ", false, from_stdin)?;
        keylo_platform::unlock_vault(Some(&pass))?;
        info("Vault unlocked.");
    }
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
    if let Some(store) = keylo_platform::store_status() {
        println!("Store: {store}");
    }
    Ok(0)
}

fn passphrase_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let action = args.positional(0, "set, change or remove")?.to_lowercase();
    let from_stdin = args.flag("password-stdin");
    args.throw_on_unknown(Some(1))?;
    // Changing how the vault is protected always verifies your identity first.
    c.gate.confirm(0, "Keylo: change the master passphrase")?;
    let has = keylo_platform::vault_has_passphrase()?;
    match action.as_str() {
        "set" => {
            if has {
                usage!("A master passphrase is already set. Use 'keylo passphrase change'.");
            }
            let new = terminal::read_password("New master passphrase: ", true, from_stdin)?;
            keylo_platform::set_vault_passphrase(None, Some(&new))?;
            info("Master passphrase set. The vault now needs it, plus your Windows account, to open.");
            info("Keep it somewhere safe: without it the vault can't be opened on another machine.");
        }
        "change" => {
            if !has {
                usage!("No master passphrase is set. Use 'keylo passphrase set'.");
            }
            let current = terminal::read_password("Current master passphrase: ", false, from_stdin)?;
            let new = terminal::read_password("New master passphrase: ", true, from_stdin)?;
            keylo_platform::set_vault_passphrase(Some(&current), Some(&new))?;
            info("Master passphrase changed.");
        }
        "remove" => {
            if !has {
                usage!("No master passphrase is set.");
            }
            let current = terminal::read_password("Current master passphrase: ", false, from_stdin)?;
            keylo_platform::set_vault_passphrase(Some(&current), None)?;
            info("Master passphrase removed. The vault now opens with your Windows account alone.");
        }
        _ => usage!("passphrase set | change | remove"),
    }
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
