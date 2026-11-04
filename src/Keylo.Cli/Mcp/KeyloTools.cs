using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keylo.Core;
using Keylo.Core.Security;

namespace Keylo.Cli.Mcp;

/// <summary>
/// The MCP tools. Every call needs the access key from KEYLO_ACCESS_KEY; config is reloaded per call
/// so revoking a key or changing its scope applies immediately.
/// </summary>
internal sealed class KeyloTools
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly SecretStore _store = new();
    private readonly SecretTypeCatalog _types = new();

    // Every value this server has handed out, redacted from all later command output too (so a
    // value written to a file by one command doesn't come back through another).
    private readonly OutputRedactor _redactor = new();
    private readonly Lock _redactorLock = new();

    private static readonly string[] Names = ["search_secrets", "list_categories", "list_types", "run_with_secrets", "get_secret", "request_access"];

    public static bool Exists(string name) => Names.Contains(name);

    public Task<string> CallAsync(string name, JsonObject args) => name switch
    {
        "search_secrets" => Task.FromResult(Search(args)),
        "list_categories" => Task.FromResult(ListCategories()),
        "list_types" => Task.FromResult(ListTypes()),
        "run_with_secrets" => RunAsync(args),
        "get_secret" => GetAsync(args),
        "request_access" => RequestAccessAsync(args),
        _ => throw new ArgumentException($"Unknown tool: {name}"),
    };

    private static (KeyloConfig Config, AccessKey Key) LoadKey()
    {
        var config = KeyloConfig.Load();
        var key = AccessKeys.FromEnvironment(config) ?? throw new KeyloException(AccessKeys.IsPresentInEnvironment
            ? $"The access key in {AccessKeys.EnvironmentVariable} isn't valid: it was revoked, has expired, or was mistyped. Ask the user to create a new one in Keylo (Settings → Access keys)."
            : $"Keylo's MCP server has no access key. Ask the user to create one in Keylo (Settings → Access keys) and add it to this server's {AccessKeys.EnvironmentVariable}.");
        return (config, key);
    }

    private static string Access(AccessKey key, SecretInfo secret) =>
        !key.Covers(secret) ? "needs approval" : key.AllowGet ? "run, get" : "run";

    // ------------------------------------------------------------------ browse

    private string Search(JsonObject args)
    {
        var (_, key) = LoadKey();
        var query = OptionalString(args, "query");
        var category = OptionalString(args, "category");
        var limit = Math.Clamp(OptionalInt(args, "limit") ?? 50, 1, 200);

        var matches = SecretSearch.Filter(_store.List(), query, category).ToList();
        var results = matches.Take(limit).Select(s =>
        {
            var covered = key.Covers(s);
            var type = _types.Find(s.Type);
            return new
            {
                name = s.Name,
                type = type?.Id ?? "plain",
                category = s.Category,
                // The schema: which fields exist and which are secret (usable via run_with_secrets/get_secret).
                fields = Schema(type, s),
                // Values of non-secret fields, and notes, only for secrets this key may use.
                details = covered ? Details(type, s) : null,
                notes = covered ? s.Notes : null,
                access = Access(key, s),
            };
        });

        var header = matches.Count > limit ? $"{matches.Count} matches; showing {limit}.\n" : $"{matches.Count} match(es).\n";
        return header + JsonSerializer.Serialize(results, Json);
    }

    private static object[] Schema(SecretTypeDefinition? type, SecretInfo secret) => type is null
        ? secret.Username is null
            ? [new { name = "value", secret = true }]
            : [new { name = "username", secret = false }, new { name = "value", secret = true }]
        : type.Fields.Select(f => (object)new { name = f.Id, label = f.Label, secret = f.IsSecret, main = f == type.Primary ? true : (bool?)null }).ToArray();

    private static Dictionary<string, string>? Details(SecretTypeDefinition? type, SecretInfo secret)
    {
        var details = new Dictionary<string, string>();
        if (secret.Username is not null) details[type?.UsernameField?.Id ?? "username"] = secret.Username;
        foreach (var (id, value) in secret.Fields ?? new Dictionary<string, string>()) details[id] = value;
        return details.Count > 0 ? details : null;
    }

    private string ListTypes()
    {
        LoadKey();
        var types = _types.All().Select(t => new
        {
            id = t.Id,
            name = t.Name,
            fields = t.Fields.Select(f => new { name = f.Id, label = f.Label, kind = f.Kind.ToString(), secret = f.IsSecret, main = f == t.Primary ? true : (bool?)null }),
        });
        return JsonSerializer.Serialize(types, Json);
    }

    private string ListCategories()
    {
        var (_, key) = LoadKey();
        var categories = _store.List()
            .GroupBy(s => s.Category ?? "(none)", StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new { category = g.Key, secrets = g.Count(), usableWithoutApproval = g.Count(key.Covers) });
        return JsonSerializer.Serialize(categories, Json);
    }

    // ------------------------------------------------------------------ values

    private async Task<string> RunAsync(JsonObject args)
    {
        var (_, key) = LoadKey();
        var command = RequiredString(args, "command");
        var shell = (OptionalString(args, "shell") ?? "powershell").ToLowerInvariant();
        var workingDirectory = OptionalString(args, "working_directory");
        var timeout = TimeSpan.FromSeconds(Math.Clamp(OptionalInt(args, "timeout_seconds") ?? 120, 1, 600));
        var reason = OptionalString(args, "reason");

        if (args["env"] is not JsonObject env || env.Count == 0)
            throw new ArgumentException("env must map at least one environment variable to a secret, e.g. {\"GITHUB_TOKEN\": \"github-token\"}.");

        var mappings = env.Select(pair =>
        {
            if (pair.Value?.GetValueKind() != JsonValueKind.String) throw new ArgumentException($"env.{pair.Key} must be a secret name.");
            var (info, field) = ResolveSource(pair.Value.GetValue<string>());
            return (Variable: pair.Key, Info: info, Field: field);
        }).ToList();

        var secrets = mappings.Select(m => m.Info).DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
        await AuthorizeAsync(key, SecretOperation.Run, secrets, reason, $"[{shell}] {command}");

        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (variable, info, field) in mappings)
            environment[variable] = Pick(info, ReadAll(info), field);

        var result = await ShellCommand.RunAsync(shell, command, workingDirectory, environment, timeout);

        var output = new StringBuilder();
        output.AppendLine(result.TimedOut ? $"Timed out after {timeout.TotalSeconds:0}s; the process was killed." : $"Exit code: {result.ExitCode}");
        lock (_redactorLock)
        {
            AppendStream(output, "stdout", result.Stdout, result.StdoutTruncated, _redactor);
            AppendStream(output, "stderr", result.Stderr, result.StderrTruncated, _redactor);
        }
        return output.ToString().TrimEnd();
    }

    private async Task<string> GetAsync(JsonObject args)
    {
        var (_, key) = LoadKey();
        var name = RequiredString(args, "name");
        var reason = OptionalString(args, "reason");
        var info = _store.Find(name) ?? throw new SecretNotFoundException(name);

        await AuthorizeAsync(key, SecretOperation.Get, [info], reason, command: null);

        var all = ReadAll(info);
        var field = OptionalString(args, "field");
        if (field is not null) return Pick(info, all, field);

        var text = new StringBuilder();
        text.Append($"type: {info.Type ?? "plain"}");
        foreach (var (id, value) in all) text.Append($"\n{id}: {value}");
        return text.ToString();
    }

    private async Task<string> RequestAccessAsync(JsonObject args)
    {
        var (_, key) = LoadKey();
        var reason = RequiredString(args, "reason");
        if (args["names"] is not JsonArray names || names.Count == 0) throw new ArgumentException("names must list at least one secret.");

        var secrets = names.Select(n => n?.GetValue<string>() ?? throw new ArgumentException("names must be strings."))
            .Select(n => _store.Find(n) ?? throw new SecretNotFoundException(n))
            .DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var missing = secrets.Where(s => !key.Covers(s)).ToList();
        if (missing.Count == 0) return $"Your key already covers {string.Join(", ", secrets.Select(s => s.Name))}.";

        var result = await Approvals.RequestAsync(new ApprovalRequest(
            SecretOperation.Run, missing.Select(s => s.Name).ToList(), key.Id, key.Name, reason, Command: null, CanAlwaysAllow: true, GrantOnly: true));

        return result == ApprovalResult.AllowedAlways
            ? $"Approved: {string.Join(", ", missing.Select(s => s.Name))} added to the key '{key.Name}' ({(key.AllowGet ? "run and get" : "run only")})."
            : throw new AccessDeniedException("The user declined. Don't ask again unless they bring it up.");
    }

    /// <summary>The key's own scope, or else a Keylo approval window (with Windows Hello).</summary>
    private static async Task AuthorizeAsync(AccessKey key, SecretOperation operation, IReadOnlyList<SecretInfo> secrets, string? reason, string? command)
    {
        var names = secrets.Select(s => s.Name).ToList();
        if (key.Allows(operation, secrets))
        {
            AuditLog.Write(operation.ToString().ToLowerInvariant(), names, key, "access key");
            return;
        }

        // "Always" adds secrets to the key's scope; for a get that only helps if the key may print values.
        var canAlways = operation == SecretOperation.Run || key.AllowGet;
        var result = await Approvals.RequestAsync(new ApprovalRequest(operation, names, key.Id, key.Name, reason, command, canAlways));
        if (result == ApprovalResult.Denied)
            throw new AccessDeniedException($"The user denied access to {string.Join(", ", names)}. Don't retry; ask them if it's needed.");

        AuditLog.Write(operation.ToString().ToLowerInvariant(), names, key, result == ApprovalResult.AllowedAlways ? "approved (added to key)" : "approved once");
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>"name" or "name:field"; an exact secret name wins (names may contain ':').</summary>
    private (SecretInfo Info, string? Field) ResolveSource(string source)
    {
        if (_store.Find(source) is { } exact) return (exact, null);
        var colon = source.LastIndexOf(':');
        if (colon > 0 && colon < source.Length - 1 && _store.Find(source[..colon]) is { } info)
            return (info, source[(colon + 1)..]);
        throw new SecretNotFoundException(source);
    }

    /// <summary>
    /// Every field of a secret, in schema order: plain secrets as username/value, typed ones by
    /// field id. Each secret field value is registered for redaction.
    /// </summary>
    private Dictionary<string, string> ReadAll(SecretInfo info)
    {
        var secret = _store.Get(info.Name);
        var type = _types.Find(info.Type);
        var all = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (type is null)
        {
            if (info.Username is not null) all["username"] = info.Username;
            var value = DecodeText(secret.Value) ?? throw new KeyloException($"'{info.Name}' is binary; it can't be used as text.");
            all["value"] = value;
            lock (_redactorLock) _redactor.Add(info.Name, value);
            return all;
        }

        var fields = TypedSecrets.ReadFields(type, info, secret.Value);
        foreach (var field in type.Fields)
        {
            if (!fields.TryGetValue(field.Id, out var value)) continue;
            all[field.Id] = value;
            if (field.IsSecret) lock (_redactorLock) _redactor.Add($"{info.Name}:{field.Id}", value);
        }
        return all;
    }

    /// <summary>One field: the main value when <paramref name="field"/> is null or "value".</summary>
    private string Pick(SecretInfo info, Dictionary<string, string> all, string? field)
    {
        var type = _types.Find(info.Type);
        if (field?.ToLowerInvariant() is "username" or "key")
            return info.Username ?? throw new KeyloException($"'{info.Name}' has no username.");

        var id = field is null or "value" ? type?.Primary?.Id ?? "value" : field;
        if (all.TryGetValue(id, out var value)) return value;
        throw new KeyloException(type?.Field(id) is null && id != "value"
            ? $"'{info.Name}' has no field '{id}'. Fields: {string.Join(", ", all.Keys)}."
            : $"'{info.Name}' has no {id} set.");
    }

    private const int MaxShown = 30_000;

    private static void AppendStream(StringBuilder output, string label, string text, bool truncated, OutputRedactor redactor)
    {
        if (text.Length == 0) return;

        // A capture cut mid-value could end with part of a secret that no longer matches; drop that tail.
        if (truncated) text = text[..Math.Max(0, text.Length - redactor.LongestValue)];
        text = redactor.Redact(text);
        if (text.Length > MaxShown)
            text = $"{text[..(MaxShown / 2)]}\n… [{text.Length - MaxShown:N0} characters omitted] …\n{text[^(MaxShown / 2)..]}";

        output.AppendLine($"--- {label}{(truncated ? " (truncated)" : "")} ---");
        output.AppendLine(text.TrimEnd());
    }

    private static string? DecodeText(byte[] value)
    {
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(value);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static string RequiredString(JsonObject args, string name) =>
        OptionalString(args, name) is { Length: > 0 } value ? value : throw new ArgumentException($"'{name}' is required.");

    private static string? OptionalString(JsonObject args, string name) =>
        args[name] is JsonValue value && value.GetValueKind() == JsonValueKind.String ? value.GetValue<string>() : null;

    private static int? OptionalInt(JsonObject args, string name) =>
        args[name] is JsonValue value && value.GetValueKind() == JsonValueKind.Number ? (int)value.GetValue<double>() : null;

    // ------------------------------------------------------------------ schemas

    public static JsonArray Definitions() => (JsonArray)JsonNode.Parse("""
        [
          {
            "name": "search_secrets",
            "title": "Search secrets",
            "description": "Find the user's secrets by name, category, username, notes or non-secret field values (never secret values). Each result has its 'type' (login, api_key, database, ssh_key, note, a custom type, or plain), its 'fields' schema (which are secret; 'main' is the default value), and 'access': 'run' (usable with run_with_secrets), 'run, get' (also get_secret), or 'needs approval' (using it asks the user). 'details' (non-secret field values such as host or url) and notes are only shown for secrets your access key covers.",
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
            "description": "The secret types (login, api_key, database, ssh_key, note and the user's custom ones) with their fields: which are secret and which is the main value.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
          },
          {
            "name": "run_with_secrets",
            "title": "Run a command with secrets",
            "description": "Run a shell command with secrets as environment variables. Preferred over get_secret: values never enter the conversation, and any that appear in the output are replaced with [keylo:name]. Returns the exit code, stdout and stderr. Secrets your key doesn't cover ask the user first.",
            "inputSchema": {
              "type": "object",
              "properties": {
                "env": {
                  "type": "object",
                  "description": "Environment variable -> secret name, which maps its main value, or 'name:field' for one field (see the fields from search_secrets), e.g. {\"GITHUB_TOKEN\": \"github-token\", \"DB_URL\": \"prod-db:connection_string\", \"DB_USER\": \"prod-db:username\"}.",
                  "additionalProperties": { "type": "string" }
                },
                "command": { "type": "string", "description": "The command line. Reference variables in the shell's syntax: $env:VAR (powershell), %VAR% (cmd), $VAR (bash)." },
                "shell": { "type": "string", "enum": ["powershell", "cmd", "bash"], "description": "Default powershell (pwsh if installed). bash is Git Bash." },
                "working_directory": { "type": "string", "description": "Defaults to the server's working directory (the project Claude Code was started in)." },
                "timeout_seconds": { "type": "integer", "description": "Default 120, max 600. The process tree is killed on timeout." },
                "reason": { "type": "string", "description": "Why you need these secrets; shown to the user if approval is needed." }
              },
              "required": ["env", "command"]
            },
            "annotations": { "destructiveHint": true, "openWorldHint": true }
          },
          {
            "name": "get_secret",
            "title": "Get a secret's value",
            "description": "Return a secret's fields as 'field: value' lines (plain secrets: username and value), or just one field. Values become part of this conversation, so only use this when a value itself is needed; otherwise use run_with_secrets. Needs a key that allows 'get', or the user's approval.",
            "inputSchema": {
              "type": "object",
              "properties": {
                "name": { "type": "string", "description": "Exact secret name (see search_secrets)." },
                "field": { "type": "string", "description": "Only this field (e.g. 'password', 'connection_string'); returns the bare value." },
                "reason": { "type": "string", "description": "Why you need the value; shown to the user if approval is needed." }
              },
              "required": ["name"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
          },
          {
            "name": "request_access",
            "title": "Request access to secrets",
            "description": "Ask the user to add secrets to your access key permanently, so future uses don't need approval. Shows a Keylo window; the user confirms with Windows Hello.",
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
        ]
        """)!;
}
