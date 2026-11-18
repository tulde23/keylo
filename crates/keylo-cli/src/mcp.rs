//! A Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0), so agents such as
//! Claude Code can find and use secrets. Only protocol messages go to stdout. Keylo never returns
//! secret values to agents: they reach commands as environment variables and are redacted from
//! the output.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use keylo_core::access::{self, AccessKey, SecretOperation};
use keylo_core::approval::{self, ApprovalRequest};
use keylo_core::config::KeyloConfig;
use keylo_core::gate::AccessGate;
use keylo_core::platform;
use keylo_core::redactor::OutputRedactor;
use keylo_core::links::{self, aws, environments, VaultEnvironment};
use keylo_core::refs::SecretReference;
use keylo_core::secrets::SecretInfo;
use keylo_core::store::SecretStore;
use keylo_core::types::{self, SecretTypeCatalog, SecretTypeDefinition};
use keylo_core::{eq_ic, search, Error};
use serde_json::{json, Map, Value};

use crate::args::CliResult;
use crate::runner;
use crate::Context;

const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_CAPTURE: usize = 1_000_000;
const MAX_SHOWN: usize = 30_000;

fn machine() -> &'static str {
    if cfg!(target_os = "macos") {
        "Mac"
    } else if cfg!(target_os = "linux") {
        "Linux machine"
    } else {
        "Windows PC"
    }
}

fn instructions() -> String {
    format!(
        "Keylo holds the user's secrets (API keys, passwords, tokens) on this {}.
- Find secrets with search_secrets. Each result says what your access key allows: \"run\" or \"needs approval\".
- Secrets have types (login, api_key, database, ssh_key, server, email_account, credit_card, and more: list_types has them all; plus the user's custom ones) with named fields; search results include each
  secret's field schema. Address one field as \"name:field\" (e.g. \"prod-db:connection_string\"); a bare name means its main value.
- Some secrets are links (type \"link\") to items in another vault such as 1Password or AWS Secrets Manager; they work the same way and are read
  live from that vault, which may ask the user to unlock it.
- Some links are per environment (search_secrets lists their \"environments\"): add \"@env\" to choose one, e.g.
  \"orders-db@uat\" or \"orders-db@prod:password\"; without it the default environment is used. Environments marked
  \"always ask\" (usually prod) open an approval window every time, whatever your key covers.
- Prefer run_with_secrets: values reach the command as environment variables and are redacted from its output, so they never enter this conversation.
- Keylo never returns secret values to agents. To use one, run a command with run_with_secrets.
- Using a secret outside your key's scope asks the user to approve it (with {}); an approval
  lasts for their Keylo session (15 minutes by default). If they deny it, don't retry; ask them.
- request_access asks the user to add secrets to your key permanently.
Never write secret values into files, commits or messages unless the user asks.",
        machine(),
        platform::current().verifier_name()
    )
}

/// "keylo mcp" typed in a terminal: say what it's for and how to connect an agent.
pub fn explain(config: &KeyloConfig) {
    let keys = config.access_keys.len();
    let tools: Vec<String> = definitions()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| format!("  {:<18}{}", t["name"].as_str().unwrap_or(""), t["title"].as_str().unwrap_or("")))
        .collect();
    println!(
        "keylo mcp is Keylo's MCP server. You don't run it yourself: an AI agent such as Claude Code
starts it and talks to it over stdin/stdout, so on its own it would just wait.

It lets agents use your secrets without seeing them: Keylo passes them to the agent's command as
environment variables and redacts them from the output. Each agent has an access key that sets what
it may use without asking; anything else needs your approval with {verifier}, and every use is logged.

Claude Code: {claude}.
Access keys: {keys}.

Set it up:
  keylo keys create \"Claude Code\" --category dev --add-to-claude     (or --all for every secret)
or register a key yourself:
  claude mcp add keylo --scope user --env {var}=<the key> -- \"{exe}\" mcp

Tools it gives agents:
{tools}

Testing? keylo mcp --stdio runs the server in this terminal anyway (JSON-RPC, one message per line).",
        verifier = platform::current().verifier_name(),
        var = access::ENVIRONMENT_VARIABLE,
        exe = crate::self_path(),
        tools = tools.join("\n"),
        claude = keylo_core::claude_code::inspect(config, &crate::self_path()).describe()
    );
}

struct Server {
    store: SecretStore,
    types: SecretTypeCatalog,
    out: Mutex<std::io::Stdout>,
    // Every value handed out, redacted from all later output too.
    redactor: Mutex<OutputRedactor>,
    // Approvals last for the session length, per operation and secret.
    approved: Mutex<HashMap<(SecretOperation, String), DateTime<Local>>>,
    // One approval window at a time.
    approval: Mutex<()>,
}

struct ToolError(String);

impl From<Error> for ToolError {
    fn from(e: Error) -> Self {
        ToolError(e.to_string())
    }
}

type ToolResult = Result<String, ToolError>;

macro_rules! tool_fail {
    ($($arg:tt)*) => { return Err(ToolError(format!($($arg)*))) };
}

pub fn serve(_c: Context) -> CliResult<i32> {
    let server = Arc::new(Server {
        store: SecretStore::default(),
        types: SecretTypeCatalog::default(),
        out: Mutex::new(std::io::stdout()),
        redactor: Mutex::new(OutputRedactor::new()),
        approved: Mutex::new(HashMap::new()),
        approval: Mutex::new(()),
    });

    let mut handles = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(_) => {
                server.send(&error(Value::Null, -32700, "Parse error"));
                continue;
            }
        };
        let requests: Vec<Value> = match message {
            Value::Array(batch) => batch.into_iter().filter(Value::is_object).collect(),
            Value::Object(_) => vec![message],
            _ => vec![],
        };
        // Requests are handled concurrently, so a ping isn't stuck behind an approval prompt.
        for request in requests {
            let s = Arc::clone(&server);
            handles.push(std::thread::spawn(move || s.handle(request)));
        }
        handles.retain(|h| !h.is_finished());
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(0)
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

impl Server {
    fn send(&self, message: &Value) {
        let mut out = self.out.lock().unwrap();
        let _ = writeln!(out, "{message}");
        let _ = out.flush();
    }

    fn handle(&self, request: Value) {
        let Some(id) = request.get("id").cloned() else { return }; // a notification
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": definitions() })),
            "tools/call" => self.call_tool(&params),
            _ => Err((-32601, format!("Method not found: {method}"))),
        };
        match result {
            Ok(r) => self.send(&json!({ "jsonrpc": "2.0", "id": id, "result": r })),
            Err((code, m)) => self.send(&error(id, code, &m)),
        }
    }

    fn call_tool(&self, params: &Value) -> Result<Value, (i32, String)> {
        let Some(name) = params.get("name").and_then(Value::as_str) else { return Err((-32602, "Missing tool name.".into())) };
        let empty = Map::new();
        let args = params.get("arguments").and_then(Value::as_object).unwrap_or(&empty);
        let result = match name {
            "search_secrets" => self.search(args),
            "list_categories" => self.list_categories(),
            "list_types" => self.list_types(),
            "run_with_secrets" => self.run(args),
            "request_access" => self.request_access(args),
            "list_aws_profiles" => self.list_aws_profiles(),
            "list_aws_secrets" => self.list_aws_secrets(args),
            "check_for_updates" => self.check_for_updates(),
            _ => return Err((-32602, format!("Unknown tool: {name}"))),
        };
        // Tool failures go back to the agent as results it can act on.
        let (text, is_error) = match result {
            Ok(t) => (t, false),
            Err(ToolError(m)) => (m, true),
        };
        Ok(json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }))
    }

    // ------------------------------------------------------------------------ browse

    fn search(&self, args: &Map<String, Value>) -> ToolResult {
        let (_, key) = load_key()?;
        let query = opt_str(args, "query");
        let category = opt_str(args, "category");
        let limit = opt_int(args, "limit").unwrap_or(50).clamp(1, 200) as usize;
        let all = self.store.list()?;
        let matches = search::filter(&all, query.as_deref(), category.as_deref());
        let results: Vec<Value> = matches
            .iter()
            .take(limit)
            .map(|s| {
                let covered = key.covers(s);
                let t = self.type_of(s);
                let mut r = Map::new();
                r.insert("name".into(), json!(s.name));
                r.insert("type".into(), json!(t.as_ref().map(|t| t.id.clone()).unwrap_or_else(|| "plain".into())));
                if let Some(c) = &s.category {
                    r.insert("category".into(), json!(c));
                }
                r.insert("fields".into(), schema(t.as_ref(), s));
                if covered {
                    if let Some(d) = details(t.as_ref(), s) {
                        r.insert("details".into(), d);
                    }
                    if let Some(n) = &s.notes {
                        r.insert("notes".into(), json!(n));
                    }
                }
                r.insert("access".into(), json!(if covered { "run" } else { "needs approval" }));
                if let Some(e) = environments_of(s) {
                    r.insert("environments".into(), e);
                }
                Value::Object(r)
            })
            .collect();
        let header = if matches.len() > limit {
            format!("{} matches; showing {limit}.\n", matches.len())
        } else {
            format!("{} match(es).\n", matches.len())
        };
        Ok(header + &serde_json::to_string(&results).unwrap())
    }

    /// A secret's type: its catalog type, a schema built from a link's fields, or None for plain.
    fn type_of(&self, s: &SecretInfo) -> Option<SecretTypeDefinition> {
        if let Some(link) = links::read(s) {
            return Some(links::as_type(&link, &links::provider_name(&link.target.provider)));
        }
        self.types.find(s.type_id.as_deref()).ok().flatten()
    }

    /// AWS profiles (names, regions, how they sign in; never keys), the regions, and what Keylo's AWS provider uses.
    /// Whether a newer Keylo is out. Read-only: installing is left to the person (the app's Install
    /// and restart, or `keylo update`), never to an agent.
    fn check_for_updates(&self) -> ToolResult {
        use keylo_core::updates;
        let manifest = updates::check().map_err(|e| ToolError(e.to_string()))?;
        let available = manifest.is_newer();
        let how = if !available {
            "Nothing to do.".to_string()
        } else if cfg!(windows) {
            "Tell the user. They can choose Install and restart in the Keylo app, or run 'keylo update' in a terminal. Don't run it for them.".to_string()
        } else if cfg!(target_os = "macos") {
            "Tell the user. They can choose Install and restart in the Keylo app.".to_string()
        } else {
            format!("Tell the user. They can download the new .deb or tarball from {}.", updates::RELEASES_PAGE)
        };
        let result = json!({
            "current": updates::CURRENT,
            "latest": manifest.latest(),
            "updateAvailable": available,
            "notes": manifest.notes,
            "releasePage": updates::RELEASES_PAGE,
            "howToUpdate": how,
        });
        Ok(serde_json::to_string(&result).unwrap())
    }

    fn list_aws_profiles(&self) -> ToolResult {
        let (config, _) = load_key()?;
        let settings = links::provider_settings(&config, "aws");
        let envs: Vec<Value> = environments::read(&settings)
            .into_iter()
            .map(|e| json!({ "name": e.name, "profile": e.profile, "region": e.region, "alwaysAsk": e.always_ask }))
            .collect();
        let result = json!({
            "awsCli": if aws::cli_installed() { "installed".to_string() } else { format!("not found on PATH (Keylo reads AWS secrets through it; to install: {})", aws::install_hint()) },
            "keylo": {
                "profile": links::setting(&settings, "profile"),
                "region": links::setting(&settings, "region"),
                "note": "Linked AWS secrets each keep the profile and region they were linked with.",
            },
            "environmentRegion": aws::environment_region(),
            "environments": envs,
            "defaultEnvironment": environments::default(&settings),
            "profiles": aws::profiles(),
            "regions": aws::REGIONS,
        });
        Ok(serde_json::to_string(&result).unwrap())
    }

    /// The secrets in AWS Secrets Manager for a profile and region: names, ARNs, descriptions and
    /// tags, never values, grouped by their first path segment, and which are already linked in Keylo.
    fn list_aws_secrets(&self, args: &Map<String, Value>) -> ToolResult {
        let (config, _) = load_key()?;
        let settings = links::provider_settings(&config, "aws");
        let mut profile = opt_str(args, "profile").or_else(|| links::setting(&settings, "profile").map(str::to_string));
        let mut region = opt_str(args, "region").or_else(|| links::setting(&settings, "region").map(str::to_string));
        let environment = opt_str(args, "environment");
        if let Some(name) = &environment {
            let Some(e) = environments::find(&settings, name) else {
                let names: Vec<String> = environments::read(&settings).into_iter().map(|e| e.name).collect();
                tool_fail!("There's no AWS environment '{name}'. Environments: {}.", names.join(", "))
            };
            (profile, region) = (e.profile, e.region);
        }
        let provider = aws::Aws::new(std::sync::Arc::new(links::process::SystemRunner::default()));
        let query = opt_str(args, "query");
        let (used_region, secrets) = provider.list_secrets(profile.as_deref(), region.as_deref(), query.as_deref())?;

        // Keylo secrets linked to AWS, by ARN (or by name, for per-environment links).
        let mut linked: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for s in self.store.list()? {
            if let Some(l) = links::read(&s).filter(|l| l.target.provider == "aws") {
                linked.entry(l.target.item_id).or_default().push(s.name);
            }
        }
        let mut projects: Vec<(String, usize)> = Vec::new();
        for s in &secrets {
            let p = s.name.split_once('/').map(|(p, _)| p.to_string()).unwrap_or_else(|| "(no prefix)".into());
            match projects.iter_mut().find(|x| x.0 == p) {
                Some(x) => x.1 += 1,
                None => projects.push((p, 1)),
            }
        }
        let list: Vec<Value> = secrets
            .iter()
            .map(|s| {
                let mut o = json!({ "name": s.name, "arn": s.arn });
                if let Some(d) = &s.description {
                    o["description"] = json!(d);
                }
                if !s.tags.is_empty() {
                    o["tags"] = json!(s.tags);
                }
                let names: Vec<&String> = linked.get(&s.arn).into_iter().chain(linked.get(&s.name)).flatten().collect();
                if !names.is_empty() {
                    o["linkedInKeyloAs"] = json!(names);
                }
                o
            })
            .collect();
        let result = json!({
            "environment": environment,
            "profile": profile.unwrap_or_else(|| "(default credentials)".into()),
            "region": used_region,
            "count": secrets.len(),
            "projects": projects.into_iter().map(|(p, n)| json!({ "project": p, "secrets": n })).collect::<Vec<_>>(),
            "secrets": list,
        });
        Ok(serde_json::to_string(&result).unwrap())
    }

    fn list_types(&self) -> ToolResult {
        load_key()?;
        let types: Vec<Value> = self
            .types
            .all()?
            .iter()
            .map(|t| {
                let primary = t.primary().map(|p| p.id.clone());
                let fields: Vec<Value> = t
                    .fields
                    .iter()
                    .map(|f| {
                        let mut o = json!({ "name": f.id, "label": f.label, "kind": format!("{:?}", f.kind), "secret": f.is_secret() });
                        if Some(&f.id) == primary.as_ref() {
                            o["main"] = json!(true);
                        }
                        o
                    })
                    .collect();
                json!({ "id": t.id, "name": t.name, "fields": fields })
            })
            .collect();
        Ok(serde_json::to_string(&types).unwrap())
    }

    fn list_categories(&self) -> ToolResult {
        let (_, key) = load_key()?;
        let mut groups: Vec<(String, usize, usize)> = Vec::new();
        for s in self.store.list()? {
            let name = s.category.clone().unwrap_or_else(|| "(none)".into());
            let covered = key.covers(&s) as usize;
            match groups.iter_mut().find(|g| eq_ic(&g.0, &name)) {
                Some(g) => {
                    g.1 += 1;
                    g.2 += covered;
                }
                None => groups.push((name, 1, covered)),
            }
        }
        groups.sort_by_key(|g| g.0.to_lowercase());
        let list: Vec<Value> = groups
            .into_iter()
            .map(|(c, n, u)| json!({ "category": c, "secrets": n, "usableWithoutApproval": u }))
            .collect();
        Ok(serde_json::to_string(&list).unwrap())
    }

    // ------------------------------------------------------------------------ values

    fn run(&self, args: &Map<String, Value>) -> ToolResult {
        let (_, key) = load_key()?;
        let command = req_str(args, "command")?;
        let shell = opt_str(args, "shell").unwrap_or_else(|| default_shell().into()).to_lowercase();
        let dir = opt_str(args, "working_directory");
        let timeout = Duration::from_secs(opt_int(args, "timeout_seconds").unwrap_or(120).clamp(1, 600) as u64);
        let reason = opt_str(args, "reason");

        let Some(env) = args.get("env").and_then(Value::as_object).filter(|e| !e.is_empty()) else {
            tool_fail!("env must map at least one environment variable to a secret, e.g. {{\"GITHUB_TOKEN\": \"github-token\"}}.")
        };
        let mut mappings = Vec::new();
        for (var, source) in env {
            let Some(source) = source.as_str() else { tool_fail!("env.{var} must be a secret name.") };
            mappings.push((var.clone(), self.resolve(source)?));
        }
        let uses: Vec<SecretUse> = mappings.iter().map(|(_, u)| u.clone()).collect();
        self.authorize(&key, SecretOperation::Run, &uses, reason.as_deref(), Some(&format!("[{shell}] {command}")))?;

        // Each secret (and environment) is read once, however many variables use it.
        let mut read: HashMap<String, BTreeMap<String, String>> = HashMap::new();
        let mut environment = BTreeMap::new();
        for (var, u) in &mappings {
            let label = u.label().to_lowercase();
            if !read.contains_key(&label) {
                let values = self.read_all(u)?;
                read.insert(label.clone(), values);
            }
            environment.insert(var.clone(), self.pick(&u.info, &read[&label], u.field.as_deref())?);
        }
        for values in read.values_mut() {
            for v in values.values_mut() {
                zeroize::Zeroize::zeroize(v);
            }
        }
        let result = run_shell(&shell, &command, dir.as_deref(), &environment, timeout);
        for v in environment.values_mut() {
            zeroize::Zeroize::zeroize(v);
        }
        let r = result?;

        let mut output = if r.timed_out {
            format!("Timed out after {}s; the process was killed.\n", timeout.as_secs())
        } else {
            format!("Exit code: {}\n", r.code.map(|c| c.to_string()).unwrap_or_default())
        };
        let redactor = self.redactor.lock().unwrap();
        append_stream(&mut output, "stdout", &r.stdout, r.stdout_cut, &redactor);
        append_stream(&mut output, "stderr", &r.stderr, r.stderr_cut, &redactor);
        Ok(output.trim_end().to_string())
    }

    fn request_access(&self, args: &Map<String, Value>) -> ToolResult {
        let (_, key) = load_key()?;
        let reason = req_str(args, "reason")?;
        let Some(names) = args.get("names").and_then(Value::as_array).filter(|n| !n.is_empty()) else {
            tool_fail!("names must list at least one secret.")
        };
        let mut secrets: Vec<SecretInfo> = Vec::new();
        for n in names {
            let Some(n) = n.as_str() else { tool_fail!("names must be strings.") };
            let info = self.resolve(n)?.info;
            if !secrets.iter().any(|s| eq_ic(&s.name, &info.name)) {
                secrets.push(info);
            }
        }
        let missing: Vec<String> = secrets.iter().filter(|s| !key.covers(s)).map(|s| s.name.clone()).collect();
        if missing.is_empty() {
            let all: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
            return Ok(format!("Your key already covers {}.", all.join(", ")));
        }
        let choice = self.ask(&key, "permanent access to", &missing, Some(&reason), None, true, true);
        if choice == Approval::Always {
            Ok(format!("Approved: {} added to the key '{}'.", missing.join(", "), key.name))
        } else {
            Err(ToolError("The user declined. Don't ask again unless they bring it up.".into()))
        }
    }

    /// The key's own scope, a recent approval, or else ask the user. A use in an "always ask"
    /// environment (prod) skips the key's scope and can't be allowed for good.
    fn authorize(
        &self,
        key: &AccessKey,
        op: SecretOperation,
        uses: &[SecretUse],
        reason: Option<&str>,
        command: Option<&str>,
    ) -> Result<(), ToolError> {
        let mut secrets: Vec<SecretInfo> = Vec::new();
        // Approvals and grants are per secret, except in "always ask" environments ("orders-db@prod");
        // the audit log always records the environment.
        let mut names: Vec<String> = Vec::new();
        let mut logged: Vec<String> = Vec::new();
        for u in uses {
            if !secrets.iter().any(|s| eq_ic(&s.name, &u.info.name)) {
                secrets.push(u.info.clone());
            }
            let name = if u.always_ask() { u.label() } else { u.info.name.clone() };
            if !names.iter().any(|n| eq_ic(n, &name)) {
                names.push(name);
            }
            if !logged.iter().any(|n| eq_ic(n, &u.label())) {
                logged.push(u.label());
            }
        }
        let always_ask = uses.iter().any(SecretUse::always_ask);
        if !always_ask && key.allows(op, &secrets) {
            access::audit(op.as_str(), &logged, Some(key), "access key")?;
            return Ok(());
        }
        let now = Local::now();
        let recent = {
            let approved = self.approved.lock().unwrap();
            names.iter().all(|n| approved.get(&(op, n.to_lowercase())).is_some_and(|until| *until > now))
        };
        if recent {
            access::audit(op.as_str(), &logged, Some(key), "approved earlier this session")?;
            return Ok(());
        }
        let choice = self.ask(key, "use", &names, reason, command, !always_ask, false);
        if choice == Approval::Denied {
            tool_fail!("The user denied access to {}. Don't retry; ask them if it's needed.", names.join(", "));
        }
        let minutes = KeyloConfig::load().map(|c| c.session_minutes).unwrap_or(15);
        let until = Local::now() + chrono::Duration::minutes(minutes);
        {
            let mut approved = self.approved.lock().unwrap();
            for n in &names {
                approved.insert((op, n.to_lowercase()), until);
            }
        }
        let via = if choice == Approval::Always { "approved (added to key)" } else { "approved for the session" };
        access::audit(op.as_str(), &logged, Some(key), via)?;
        Ok(())
    }

    /// Asks the user (one window at a time), then confirms with the identity check. "Always"
    /// adds the secrets to the key.
    #[allow(clippy::too_many_arguments)]
    fn ask(
        &self,
        key: &AccessKey,
        verb: &str,
        names: &[String],
        reason: Option<&str>,
        command: Option<&str>,
        can_always: bool,
        grant_only: bool,
    ) -> Approval {
        let _one = self.approval.lock().unwrap();

        // The Keylo app's approval window, when the app is installed next to keylo: it verifies the
        // user and adds "always" grants itself, and answers with its exit code.
        if let Some(app) = app_path() {
            let request = ApprovalRequest {
                operation: ApprovalRequest::op_code(SecretOperation::Run),
                secrets: names.to_vec(),
                key_id: Some(key.id.clone()),
                key_name: Some(key.name.clone()),
                reason: reason.map(str::to_string),
                command: command.map(str::to_string),
                can_always_allow: can_always,
                grant_only,
            };
            return match run_approval_app(&app, &request) {
                Some(approval::ALLOWED_ALWAYS) => Approval::Always,
                Some(approval::ALLOWED_ONCE) => Approval::Once,
                _ => Approval::Denied,
            };
        }

        let what = if names.len() == 1 { "a secret".to_string() } else { format!("{} secrets", names.len()) };
        let title = format!("{} wants {verb} {what}", if key.name.is_empty() { "An agent" } else { &key.name });
        let mut message = names.join(", ");
        if let Some(c) = command.filter(|c| !c.is_empty()) {
            message += &format!("\n\nCommand: {}", clip(c));
        }
        if let Some(r) = reason.filter(|r| !r.is_empty()) {
            message += &format!("\n\nReason given by the agent: “{}”", clip(r.trim()));
        }
        let mut choice = approval_dialog(&title, &message, can_always && !grant_only);
        if grant_only && choice == Approval::Once {
            choice = Approval::Always;
        }
        if choice == Approval::Denied {
            return choice;
        }
        let Ok(config) = KeyloConfig::load() else { return Approval::Denied };
        let gate = AccessGate::new(&config);
        if gate.confirm(0, &format!("Keylo: allow '{}' to {verb} {}", key.name, names.join(", "))).is_err() {
            return Approval::Denied;
        }
        if choice == Approval::Always {
            let Ok(mut fresh) = KeyloConfig::load() else { return Approval::Once };
            if !access::grant(&mut fresh, &key.id, names) || fresh.save().is_err() {
                return Approval::Once;
            }
        }
        choice
    }

    // ------------------------------------------------------------------------ helpers

    /// "name", "name:field", "name@env" or "name@env:field"; an exact secret name wins (names may
    /// contain ':' and '@').
    fn resolve(&self, source: &str) -> Result<SecretUse, ToolError> {
        // Reach the store first, so a locked vault says so instead of "not found".
        self.store.exists(source.trim())?;
        let r = SecretReference::parse(source, |n| self.store.exists(n).unwrap_or(false))
            .ok_or_else(|| ToolError(Error::NotFound(source.into()).to_string()))?;
        let info = self.store.find(&r.name)?.ok_or_else(|| ToolError(Error::NotFound(r.name.clone()).to_string()))?;
        let env = links::environment_for(&info, &KeyloConfig::load()?, r.environment.as_deref())?;
        Ok(SecretUse { info, field: r.field, env })
    }

    /// Every field of a secret: plain ones as username/value, typed ones by field id, linked ones
    /// read live from their vault. Each secret value is registered for redaction.
    fn read_all(&self, u: &SecretUse) -> Result<BTreeMap<String, String>, ToolError> {
        let info = &u.info;
        if let Some(link) = links::read(info) {
            // Everything except known non-secret fields is redacted.
            let values = links::resolve(info, &KeyloConfig::load()?, u.env.as_ref().map(|e| e.name.as_str()))?;
            let mut redactor = self.redactor.lock().unwrap();
            for (id, v) in &values {
                let plain = link.fields.iter().any(|f| !f.secret && eq_ic(&f.id, id));
                if !plain || !links::looks_public(id) {
                    redactor.add(&format!("{}:{id}", info.name), v);
                }
            }
            return Ok(values);
        }
        let secret = self.store.get(&info.name)?;
        let mut all = BTreeMap::new();
        let mut redactor = self.redactor.lock().unwrap();
        match self.type_of(info) {
            None => {
                if let Some(u) = &info.username {
                    all.insert("username".into(), u.clone());
                }
                let Some(v) = types::decode_text(&secret.value) else { tool_fail!("'{}' is binary; it can't be used as text.", info.name) };
                redactor.add(&info.name, &v);
                all.insert("value".into(), v);
            }
            Some(t) => {
                let fields = types::read_fields(&t, info, &secret.value, true);
                for f in &t.fields {
                    if let Some(v) = fields.get(&f.id) {
                        if f.is_secret() {
                            redactor.add(&format!("{}:{}", info.name, f.id), v);
                        }
                        all.insert(f.id.clone(), v.clone());
                    }
                }
            }
        }
        Ok(all)
    }

    /// One field: the main value when `field` is None or "value".
    fn pick(&self, info: &SecretInfo, all: &BTreeMap<String, String>, field: Option<&str>) -> Result<String, ToolError> {
        if let Some(link) = links::read(info) {
            return Ok(links::pick(info, &link, all, field)?);
        }
        let t = self.type_of(info);
        let lower = field.map(str::to_lowercase);
        if matches!(lower.as_deref(), Some("username" | "key")) {
            return info.username.clone().ok_or_else(|| ToolError(format!("'{}' has no username.", info.name)));
        }
        let id = match lower.as_deref() {
            None | Some("value") => t.as_ref().and_then(|t| t.primary()).map(|p| p.id.clone()).unwrap_or_else(|| "value".into()),
            Some(f) => f.to_string(),
        };
        if let Some(v) = all.get(&id) {
            return Ok(v.clone());
        }
        let keys: Vec<&str> = all.keys().map(String::as_str).collect();
        if t.as_ref().and_then(|t| t.field(&id)).is_none() && id != "value" {
            tool_fail!("'{}' has no field '{id}'. Fields: {}.", info.name, keys.join(", "));
        }
        tool_fail!("'{}' has no {id} set.", info.name)
    }
}

fn initialize(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
    let version = if PROTOCOL_VERSIONS.contains(&requested) { requested } else { PROTOCOL_VERSIONS[0] };
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "keylo", "title": "Keylo", "version": keylo_core::version::VERSION },
        "instructions": instructions(),
    })
}

fn load_key() -> Result<(KeyloConfig, AccessKey), ToolError> {
    let config = KeyloConfig::load()?;
    let var = access::ENVIRONMENT_VARIABLE;
    let Some(key) = access::from_environment(&config).cloned() else {
        if access::is_present_in_environment() {
            tool_fail!("The access key in {var} isn't valid: it was revoked, has expired, or was mistyped. Ask the user to create a new one in Keylo (keylo keys create).");
        }
        tool_fail!("Keylo's MCP server has no access key. Ask the user to create one (keylo keys create) and add it to this server's {var}.");
    };
    Ok((config, key))
}

fn schema(t: Option<&SecretTypeDefinition>, s: &SecretInfo) -> Value {
    match t {
        None if s.username.is_none() => json!([{ "name": "value", "secret": true }]),
        None => json!([{ "name": "username", "secret": false }, { "name": "value", "secret": true }]),
        Some(t) => {
            let primary = t.primary().map(|p| p.id.clone());
            Value::Array(
                t.fields
                    .iter()
                    .map(|f| {
                        let mut o = json!({ "name": f.id, "label": f.label, "secret": f.is_secret() });
                        if Some(&f.id) == primary.as_ref() {
                            o["main"] = json!(true);
                        }
                        o
                    })
                    .collect(),
            )
        }
    }
}

/// One use of a secret: which field, and for a per-environment link which environment.
#[derive(Clone)]
struct SecretUse {
    info: SecretInfo,
    field: Option<String>,
    env: Option<VaultEnvironment>,
}

impl SecretUse {
    /// "orders-db", or "orders-db@prod" for a per-environment link.
    fn label(&self) -> String {
        match &self.env {
            Some(e) => format!("{}@{}", self.info.name, e.name),
            None => self.info.name.clone(),
        }
    }

    fn always_ask(&self) -> bool {
        self.env.as_ref().is_some_and(|e| e.always_ask)
    }
}

/// For a per-environment link: its environments ("name@env" picks one), the default, and which always ask.
fn environments_of(s: &SecretInfo) -> Option<Value> {
    let link = links::read(s).filter(|l| l.is_per_environment())?;
    let settings = links::provider_settings(&KeyloConfig::load().ok()?, &link.target.provider);
    let all = environments::read(&settings);
    Some(json!({
        "names": all.iter().map(|e| e.name.clone()).collect::<Vec<_>>(),
        "default": environments::default(&settings),
        "alwaysAsk": all.iter().filter(|e| e.always_ask).map(|e| e.name.clone()).collect::<Vec<_>>(),
        "usage": format!("Use \"{0}@ENV\" or \"{0}@ENV:field\"; without @ENV the default environment is used.", s.name),
    }))
}

fn details(t: Option<&SecretTypeDefinition>, s: &SecretInfo) -> Option<Value> {
    if let Some(link) = links::read(s) {
        let vault = match &link.r#where {
            Some(w) => format!("{} ({w})", link.target.provider),
            None => link.target.provider.clone(),
        };
        return Some(json!({ "linked_to": link.title, "vault": vault }));
    }
    let mut d = Map::new();
    if let Some(u) = &s.username {
        let id = t.and_then(|t| t.username_field()).map(|f| f.id.clone()).unwrap_or_else(|| "username".into());
        d.insert(id, json!(u));
    }
    for (k, v) in &s.fields {
        d.insert(k.clone(), json!(v));
    }
    (!d.is_empty()).then_some(Value::Object(d))
}

fn opt_str(args: &Map<String, Value>, name: &str) -> Option<String> {
    args.get(name).and_then(Value::as_str).map(str::to_string)
}

fn req_str(args: &Map<String, Value>, name: &str) -> Result<String, ToolError> {
    match opt_str(args, name).filter(|s| !s.is_empty()) {
        Some(s) => Ok(s),
        None => Err(ToolError(format!("'{name}' is required."))),
    }
}

fn opt_int(args: &Map<String, Value>, name: &str) -> Option<i64> {
    args.get(name).and_then(Value::as_f64).map(|f| f as i64)
}

fn clip(text: &str) -> String {
    if text.chars().count() > 2000 {
        text.chars().take(2000).collect::<String>() + "…"
    } else {
        text.to_string()
    }
}

fn append_stream(output: &mut String, label: &str, text: &str, truncated: bool, redactor: &OutputRedactor) {
    if text.is_empty() {
        return;
    }
    // A capture cut mid-value could end with part of a secret that no longer matches; drop that tail.
    let mut text = text;
    if truncated {
        let mut end = text.len().saturating_sub(redactor.longest_value());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text = &text[..end];
    }
    let mut text = redactor.redact(text);
    let chars: Vec<char> = text.chars().collect();
    if chars.len() > MAX_SHOWN {
        let head: String = chars[..MAX_SHOWN / 2].iter().collect();
        let tail: String = chars[chars.len() - MAX_SHOWN / 2..].iter().collect();
        text = format!("{head}\n… [{} characters omitted] …\n{tail}", chars.len() - MAX_SHOWN);
    }
    output.push_str(&format!("--- {label}{} ---\n{}\n", if truncated { " (truncated)" } else { "" }, text.trim_end()));
}

// ---------------------------------------------------------------------------- shell commands

fn default_shell() -> &'static str {
    if cfg!(windows) {
        "powershell"
    } else if cfg!(target_os = "macos") {
        "zsh"
    } else {
        "bash"
    }
}

struct ShellResult {
    code: Option<i32>,
    stdout: String,
    stdout_cut: bool,
    stderr: String,
    stderr_cut: bool,
    timed_out: bool,
}

fn shell_command(shell: &str, command: &str) -> Result<Command, ToolError> {
    match shell {
        "powershell" | "pwsh" => {
            let exe = runner::resolve("pwsh").or_else(|| runner::resolve("powershell"));
            let exe = match exe {
                Some(e) => e,
                None if cfg!(windows) => "powershell.exe".into(),
                None => tool_fail!("PowerShell (pwsh) isn't installed. Use shell \"{}\" instead.", default_shell()),
            };
            let mut c = Command::new(exe);
            c.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
            c.arg(format!("[Console]::OutputEncoding = [Text.Encoding]::UTF8; $OutputEncoding = [Text.Encoding]::UTF8; {command}"));
            Ok(c)
        }
        #[cfg(windows)]
        "cmd" => {
            use std::os::windows::process::CommandExt;
            let mut c = Command::new(std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".into()));
            // /s /c "..." passes the command line through untouched.
            c.raw_arg(format!("/d /s /c \"{command}\""));
            Ok(c)
        }
        #[cfg(windows)]
        "bash" => {
            let Some(bash) = git_bash() else {
                tool_fail!("Git Bash wasn't found. Use shell \"powershell\" or \"cmd\", or install Git for Windows.")
            };
            let mut c = Command::new(bash);
            c.args(["-c", command]);
            Ok(c)
        }
        #[cfg(not(windows))]
        "bash" | "zsh" | "sh" => {
            let exe = runner::resolve(shell).unwrap_or_else(|| format!("/bin/{shell}").into());
            let mut c = Command::new(exe);
            c.args(["-c", command]);
            Ok(c)
        }
        _ => {
            if cfg!(windows) {
                tool_fail!("shell must be powershell, cmd or bash.")
            }
            tool_fail!("shell must be zsh, bash, sh or powershell (if installed).")
        }
    }
}

/// Git for Windows' bash; not System32\bash.exe, which is WSL.
#[cfg(windows)]
fn git_bash() -> Option<std::path::PathBuf> {
    if let Some(git) = runner::resolve("git") {
        if let Some(root) = git.parent().and_then(|p| p.parent()) {
            let c = root.join("bin").join("bash.exe");
            if c.is_file() {
                return Some(c);
            }
        }
    }
    let pf = std::path::PathBuf::from(std::env::var("ProgramFiles").unwrap_or_default()).join("Git").join("bin").join("bash.exe");
    pf.is_file().then_some(pf)
}

fn capture(mut reader: impl Read + Send + 'static) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let mut cut = false;
        let mut buf = [0u8; 8192];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            let room = MAX_CAPTURE.saturating_sub(data.len());
            if room == 0 {
                cut = true; // keep draining so the process doesn't block on a full pipe
                continue;
            }
            data.extend_from_slice(&buf[..n.min(room)]);
            if n > room {
                cut = true;
            }
        }
        (data, cut)
    })
}

fn run_shell(
    shell: &str,
    command: &str,
    dir: Option<&str>,
    env: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<ShellResult, ToolError> {
    let mut cmd = shell_command(shell, command)?;
    if let Some(d) = dir {
        if !std::path::Path::new(d).is_dir() {
            tool_fail!("working_directory '{d}' doesn't exist.");
        }
        cmd.current_dir(d);
    }
    // The key that let us run this stays with Keylo; the command doesn't need it.
    cmd.env_remove(access::ENVIRONMENT_VARIABLE);
    cmd.envs(env);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| ToolError(format!("Couldn't start {shell}: {e}")))?;
    let out = capture(child.stdout.take().unwrap());
    let err = capture(child.stderr.take().unwrap());

    let start = Instant::now();
    let mut timed_out = false;
    let code = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break status.code();
        }
        if start.elapsed() > timeout {
            timed_out = true;
            kill_tree(&mut child);
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };

    // Children that inherited the pipes can keep them open after the shell exits; don't wait forever.
    let within = |h: std::thread::JoinHandle<(Vec<u8>, bool)>| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !h.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if h.is_finished() { h.join().unwrap_or_default() } else { (Vec::new(), true) }
    };
    let (o, oc) = within(out);
    let (e, ec) = within(err);
    Ok(ShellResult {
        code,
        stdout: String::from_utf8_lossy(&o).into_owned(),
        stdout_cut: oc,
        stderr: String::from_utf8_lossy(&e).into_owned(),
        stderr_cut: ec,
        timed_out,
    })
}

fn kill_tree(child: &mut std::process::Child) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &child.id().to_string()])
            .creation_flags(0x0800_0000)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------- approval dialog

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    Denied,
    Once,
    Always,
}

/// The Keylo app next to this keylo (keylow.exe on Windows, keylow elsewhere), if installed.
fn app_path() -> Option<std::path::PathBuf> {
    let dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let app = dir.join(if cfg!(windows) { "keylow.exe" } else { "keylow" });
    app.is_file().then_some(app)
}

/// Opens the app's approval window and waits for its answer. The window denies by itself after
/// 5 minutes; this is a backstop if it never answers.
fn run_approval_app(app: &std::path::Path, request: &ApprovalRequest) -> Option<i32> {
    let mut child = Command::new(app)
        .args([approval::ARGUMENT, &request.encode()])
        .env_remove(access::ENVIRONMENT_VARIABLE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(6 * 60);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Without the app: a native message box.
#[cfg(windows)]
fn approval_dialog(title: &str, message: &str, can_always: bool) -> Approval {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::*;
    let text = if can_always {
        format!("{message}\n\nYes: allow once\nNo: always allow (adds it to this agent's key)\nCancel: deny")
    } else {
        format!("{message}\n\nYes: allow\nNo: deny")
    };
    let t: Vec<u16> = format!("Keylo: {title}").encode_utf16().chain([0]).collect();
    let m: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let style = if can_always { MB_YESNOCANCEL } else { MB_YESNO };
    let r = unsafe {
        MessageBoxW(None, PCWSTR(m.as_ptr()), PCWSTR(t.as_ptr()), style | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST | MB_DEFBUTTON3)
    };
    match r {
        IDYES => Approval::Once,
        IDNO if can_always => Approval::Always,
        _ => Approval::Denied,
    }
}

/// zenity / kdialog on Linux, an alert from keylo-mac on macOS.
#[cfg(not(windows))]
fn approval_dialog(title: &str, message: &str, can_always: bool) -> Approval {
    match keylo_platform::approval_dialog(title, message, can_always) {
        Ok(approval::ALLOWED_ALWAYS) => Approval::Always,
        Ok(approval::ALLOWED_ONCE) => Approval::Once,
        Ok(_) => Approval::Denied,
        Err(e) => {
            eprintln!("keylo: {e}");
            Approval::Denied
        }
    }
}

// ---------------------------------------------------------------------------- tool schemas

pub fn definitions() -> Value {
    json!([
      {
        "name": "search_secrets",
        "title": "Search secrets",
        "description": "Find the user's secrets by name, category, username, notes or non-secret field values (never secret values). Each result has its 'type' (login, api_key, database, credit_card… see list_types; a custom type; or plain), its 'fields' schema (which are secret; 'main' is the default value), and 'access': 'run' (usable with run_with_secrets) or 'needs approval' (using it asks the user). 'details' (non-secret field values such as host or url) and notes are only shown for secrets your access key covers.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": { "type": "string", "description": "Space-separated terms, all must match. 'cat:NAME' matches a category, 'type:ID' a type (e.g. type:database). Omit to list everything." },
            "category": { "type": "string", "description": "Only this category (exact name)." },
            "limit": { "type": "integer", "description": "Maximum results (default 50, max 200)." }
          }
        },
        "annotations": { "readOnlyHint": true, "openWorldHint": false }
      },
      {
        "name": "list_categories",
        "title": "List secret categories",
        "description": "Categories with how many secrets each has, and how many your access key can use without approval.",
        "inputSchema": { "type": "object", "properties": {} },
        "annotations": { "readOnlyHint": true, "openWorldHint": false }
      },
      {
        "name": "list_types",
        "title": "List secret types",
        "description": "The secret types (login, api_key, database, ssh_key, note, password, server, email_account, software_license, wireless_router, crypto_wallet, document, credit_card, bank_account, and the user's custom ones) with their fields: which are secret and which is the main value.",
        "inputSchema": { "type": "object", "properties": {} },
        "annotations": { "readOnlyHint": true, "openWorldHint": false }
      },
      {
        "name": "check_for_updates",
        "title": "Check for a Keylo update",
        "description": "Whether a newer version of Keylo has been released: this build's version, the latest one, and how the user can install it. Read-only; agents can't install updates (the user does, from the Keylo app or with 'keylo update').",
        "inputSchema": { "type": "object", "properties": {} },
        "annotations": { "readOnlyHint": true, "openWorldHint": true }
      },
      {
        "name": "list_aws_profiles",
        "title": "List AWS profiles and regions",
        "description": "Keylo's AWS environments (dev, uat, prod…: each a profile and region; secrets linked per environment are used as name@env), the AWS profiles set up on this computer (~/.aws/config and ~/.aws/credentials: name, region, and how each signs in, e.g. sso or access keys; never any keys), every AWS region, whether the aws CLI is installed, and the profile and region Keylo's AWS Secrets Manager provider uses. Useful before running aws commands with run_with_secrets, or to tell the user which profile to link secrets from.",
        "inputSchema": { "type": "object", "properties": {} },
        "annotations": { "readOnlyHint": true, "openWorldHint": false }
      },
      {
        "name": "list_aws_secrets",
        "title": "List secrets in AWS Secrets Manager",
        "description": "The secrets in AWS Secrets Manager for one profile and region (from list_aws_profiles; Keylo's configured ones by default): names, ARNs, descriptions and tags, never values. Also groups them by the first part of their name (\"project/db\" → \"project\") and says which are already linked in Keylo, under what name. To use one in a command it must first be linked in Keylo (ask the user: Link in the Keylo app, or keylo link --provider aws).",
        "inputSchema": {
          "type": "object",
          "properties": {
            "environment": { "type": "string", "description": "An environment from list_aws_profiles (dev, uat, prod…); overrides profile and region." },
            "profile": { "type": "string", "description": "AWS profile name (see list_aws_profiles)." },
            "region": { "type": "string", "description": "AWS region, e.g. us-east-1." },
            "query": { "type": "string", "description": "Only secrets whose name, description or tags contain every word." }
          }
        },
        "annotations": { "readOnlyHint": true, "openWorldHint": true }
      },
      {
        "name": "run_with_secrets",
        "title": "Run a command with secrets",
        "description": "Run a shell command with secrets as environment variables. This is the only way to use a secret: Keylo never returns values, and any that appear in the output are replaced with [keylo:name]. Returns the exit code, stdout and stderr. Secrets your key doesn't cover ask the user first.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "env": {
              "type": "object",
              "description": "Environment variable -> secret name, which maps its main value, or 'name:field' for one field (see the fields from search_secrets), or 'name@env' / 'name@env:field' for an environment of a per-environment link, e.g. {\"GITHUB_TOKEN\": \"github-token\", \"DB_URL\": \"prod-db:connection_string\", \"DB_USER\": \"prod-db:username\"}.",
              "additionalProperties": { "type": "string" }
            },
            "command": { "type": "string", "description": "The command line. Reference variables in the shell's syntax: $env:VAR (powershell), %VAR% (cmd), $VAR (bash, zsh, sh)." },
            "shell": { "type": "string", "enum": ["powershell", "cmd", "bash", "zsh", "sh"], "description": "Windows: powershell (default; pwsh if installed), cmd, or bash (Git Bash). macOS: zsh (default), bash, sh, or powershell if installed. Linux: bash (default), zsh, sh, or powershell if installed." },
            "working_directory": { "type": "string", "description": "Defaults to the server's working directory (the project Claude Code was started in)." },
            "timeout_seconds": { "type": "integer", "description": "Default 120, max 600. The process tree is killed on timeout." },
            "reason": { "type": "string", "description": "Why you need these secrets; shown to the user if approval is needed." }
          },
          "required": ["env", "command"]
        },
        "annotations": { "destructiveHint": true, "openWorldHint": true }
      },
      {
        "name": "request_access",
        "title": "Request access to secrets",
        "description": "Ask the user to add secrets to your access key permanently, so future uses don't need approval. The user confirms with their device sign-in.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "names": { "type": "array", "items": { "type": "string" }, "description": "Secret names." },
            "reason": { "type": "string", "description": "What you need them for; shown to the user." }
          },
          "required": ["names", "reason"]
        },
        "annotations": { "readOnlyHint": false, "openWorldHint": false }
      }
    ])
}
