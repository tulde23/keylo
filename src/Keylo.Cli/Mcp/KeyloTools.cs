using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Keylo.Core;
using Keylo.Core.Providers;
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
    private readonly Keylo.Core.Providers.ProviderRegistry _registry = new();

    /// <summary>A secret's type: its catalog type, a schema built from a link's fields, or null for plain.</summary>
    private SecretTypeDefinition? TypeOf(SecretInfo secret) =>
        LinkedSecrets.Read(secret) is { } link
            ? LinkedSecrets.AsType(link, _registry.FindLinked(link.Target.Provider)?.DisplayName ?? link.Target.Provider)
            : _types.Find(secret.Type);

    // Every value this server has handed out, redacted from all later command output too (so a
    // value written to a file by one command doesn't come back through another).
    private readonly OutputRedactor _redactor = new();
    private readonly Lock _redactorLock = new();

    private static readonly string[] Names = ["search_secrets", "list_categories", "list_types", "run_with_secrets", "get_secret", "request_access", "list_aws_profiles", "list_aws_secrets"];

    public static bool Exists(string name) => Names.Contains(name);

    public Task<string> CallAsync(string name, JsonObject args) => name switch
    {
        "search_secrets" => Task.FromResult(Search(args)),
        "list_categories" => Task.FromResult(ListCategories()),
        "list_types" => Task.FromResult(ListTypes()),
        "run_with_secrets" => RunAsync(args),
        "get_secret" => GetAsync(args),
        "request_access" => RequestAccessAsync(args),
        "list_aws_profiles" => Task.FromResult(ListAwsProfiles()),
        "list_aws_secrets" => ListAwsSecretsAsync(args),
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
            var type = TypeOf(s);
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
                environments = Environments(s),
            };
        });

        var header = matches.Count > limit ? $"{matches.Count} matches; showing {limit}.\n" : $"{matches.Count} match(es).\n";
        return header + JsonSerializer.Serialize(results, Json);
    }

    /// <summary>For a per-environment link: its environments ("name@env" picks one), the default, and which always ask.</summary>
    private static object? Environments(SecretInfo secret)
    {
        if (LinkedSecrets.Read(secret) is not { IsPerEnvironment: true } link) return null;
        var settings = KeyloConfig.Load().Providers.GetValueOrDefault(link.Target.Provider) ?? new Dictionary<string, string>();
        return new
        {
            names = VaultEnvironments.Read(settings).Select(e => e.Name),
            @default = VaultEnvironments.Default(settings),
            alwaysAsk = VaultEnvironments.Read(settings).Where(e => e.AlwaysAsk).Select(e => e.Name),
            usage = $"Use \"{secret.Name}@ENV\" or \"{secret.Name}@ENV:field\"; without @ENV the default environment is used.",
        };
    }

    private static object[] Schema(SecretTypeDefinition? type, SecretInfo secret) => type is null
        ? secret.Username is null
            ? [new { name = "value", secret = true }]
            : [new { name = "username", secret = false }, new { name = "value", secret = true }]
        : type.Fields.Select(f => (object)new { name = f.Id, label = f.Label, secret = f.IsSecret, main = f == type.Primary ? true : (bool?)null }).ToArray();

    private static Dictionary<string, string>? Details(SecretTypeDefinition? type, SecretInfo secret)
    {
        if (LinkedSecrets.Read(secret) is { } link)
            return new Dictionary<string, string>
            {
                ["linked_to"] = link.Title,
                ["vault"] = link.Target.Provider + (link.Where is { Length: > 0 } where ? $" ({where})" : ""),
            };

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

    /// <summary>AWS profiles (names, regions, how they sign in; never keys), the regions, and what Keylo's AWS provider uses.</summary>
    private static string ListAwsProfiles()
    {
        var (config, _) = LoadKey();
        var settings = config.Providers.GetValueOrDefault("aws") ?? new Dictionary<string, string>();
        var cli = Keylo.Core.Providers.AwsSetup.CliPath();
        var result = new
        {
            awsCli = cli is not null ? "installed" : "not found on PATH (needed only to sign in with SSO: aws sso login)",
            keylo = new
            {
                profile = settings.GetValueOrDefault("profile") is { Length: > 0 } p ? p : null,
                region = settings.GetValueOrDefault("region") is { Length: > 0 } r ? r : null,
                note = "Linked AWS secrets each keep the profile and region they were linked with.",
            },
            environmentRegion = Keylo.Core.Providers.AwsSetup.EnvironmentRegion,
            environments = VaultEnvironments.Read(settings).Select(e => new { name = e.Name, profile = e.Profile, region = e.Region, alwaysAsk = e.AlwaysAsk }),
            defaultEnvironment = VaultEnvironments.Default(settings),
            profiles = Keylo.Core.Providers.AwsSetup.Profiles().Select(p => new { name = p.Name, region = p.Region, signIn = p.SignIn }),
            regions = Keylo.Core.Providers.AwsSetup.Regions(),
        };
        return JsonSerializer.Serialize(result, Json);
    }

    /// <summary>
    /// The secrets in AWS Secrets Manager for a profile and region: names, ARNs, descriptions and tags,
    /// never values, grouped by their first path segment ("project/db" → "project"), and which are
    /// already linked in Keylo (by secret name there).
    /// </summary>
    private async Task<string> ListAwsSecretsAsync(JsonObject args)
    {
        var (config, _) = LoadKey();
        if (_registry.FindLinked("aws") is not Keylo.Core.Providers.AwsSecretsManagerProvider aws)
            throw new KeyloException("The AWS Secrets Manager provider isn't available.");
        var settings = config.Providers.GetValueOrDefault("aws") ?? new Dictionary<string, string>();
        var profile = OptionalString(args, "profile") ?? (settings.GetValueOrDefault("profile") is { Length: > 0 } p ? p : null);
        var region = OptionalString(args, "region") ?? (settings.GetValueOrDefault("region") is { Length: > 0 } r ? r : null);
        var environmentName = OptionalString(args, "environment");
        if (environmentName is not null)
        {
            var env = VaultEnvironments.Find(settings, environmentName)
                      ?? throw new KeyloException($"There's no AWS environment '{environmentName}'. Environments: {string.Join(", ", VaultEnvironments.Read(settings).Select(e => e.Name))}.");
            (profile, region) = (env.Profile, env.Region);
        }

        var (usedRegion, secrets) = await aws.ListSecretsAsync(profile, region, OptionalString(args, "query"));
        var linked = _store.List()
            .Select(s => (Name: s.Name, Link: LinkedSecrets.Read(s)))
            .Where(s => s.Link?.Target.Provider == aws.Id)
            .GroupBy(s => s.Link!.Target.ItemId)  // an ARN, or a secret name for per-environment links
            .ToDictionary(g => g.Key, g => g.Select(s => s.Name).ToList());

        var result = new
        {
            environment = environmentName,
            profile = profile ?? "(default credentials)",
            region = usedRegion,
            count = secrets.Count,
            projects = secrets.GroupBy(s => s.Name.Contains('/') ? s.Name[..s.Name.IndexOf('/')] : "(no prefix)")
                .Select(g => new { project = g.Key, secrets = g.Count() }),
            secrets = secrets.Select(s => new
            {
                name = s.Name,
                arn = s.Arn,
                description = s.Description,
                tags = s.Tags.Count > 0 ? s.Tags : null,
                linkedInKeyloAs = linked.GetValueOrDefault(s.Arn) ?? linked.GetValueOrDefault(s.Name),
            }),
        };
        return JsonSerializer.Serialize(result, Json);
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
        var shell = (OptionalString(args, "shell") ?? ShellCommand.DefaultShell).ToLowerInvariant();
        var workingDirectory = OptionalString(args, "working_directory");
        var timeout = TimeSpan.FromSeconds(Math.Clamp(OptionalInt(args, "timeout_seconds") ?? 120, 1, 600));
        var reason = OptionalString(args, "reason");

        if (args["env"] is not JsonObject env || env.Count == 0)
            throw new ArgumentException("env must map at least one environment variable to a secret, e.g. {\"GITHUB_TOKEN\": \"github-token\"}.");

        var mappings = env.Select(pair =>
        {
            if (pair.Value?.GetValueKind() != JsonValueKind.String) throw new ArgumentException($"env.{pair.Key} must be a secret name.");
            var use = ResolveSource(pair.Value.GetValue<string>());
            return (Variable: pair.Key, Use: use);
        }).ToList();

        var uses = mappings.Select(m => m.Use).DistinctBy(u => u.Label, StringComparer.OrdinalIgnoreCase).ToList();
        await AuthorizeAsync(key, SecretOperation.Run, uses, reason, $"[{shell}] {command}");

        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (variable, use) in mappings)
            environment[variable] = Pick(use.Info, ReadAll(use), use.Field);

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
        var use = ResolveSource(name);
        var info = use.Info;

        await AuthorizeAsync(key, SecretOperation.Get, [use], reason, command: null);

        var all = ReadAll(use);
        var field = OptionalString(args, "field") ?? use.Field;
        if (field is not null) return Pick(info, all, field);

        var text = new StringBuilder();
        text.Append($"type: {info.Type ?? "plain"}");
        foreach (var (id, value) in all) text.Append($"\n{id}: {value}");
        if (LinkedSecrets.Read(info) is { } linkInfo)
            text.Insert(0, $"linked to: {linkInfo.Title} ({linkInfo.Target.Provider}{(use.Environment is { } e ? $", environment {e.Name}" : "")})\n");
        return text.ToString();
    }

    private async Task<string> RequestAccessAsync(JsonObject args)
    {
        var (_, key) = LoadKey();
        var reason = RequiredString(args, "reason");
        if (args["names"] is not JsonArray names || names.Count == 0) throw new ArgumentException("names must list at least one secret.");

        var secrets = names.Select(n => n?.GetValue<string>() ?? throw new ArgumentException("names must be strings."))
            .Select(n => ResolveSource(n).Info)
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

    // Approvals last for the Hello session length (config.sessionMinutes), per secret: a get
    // approval also covers running with it, not the other way round.
    private readonly Dictionary<(SecretOperation Operation, string Name), DateTimeOffset> _approved = new();
    private readonly Lock _approvedLock = new();

    private bool ApprovedRecently(SecretOperation operation, IEnumerable<string> names)
    {
        var now = DateTimeOffset.Now;
        lock (_approvedLock)
            return names.All(n =>
                (_approved.TryGetValue((operation, n.ToLowerInvariant()), out var until) && until > now) ||
                (operation == SecretOperation.Run && _approved.TryGetValue((SecretOperation.Get, n.ToLowerInvariant()), out var getUntil) && getUntil > now));
    }

    /// <summary>
    /// The key's own scope, a recent approval, or else a Keylo approval window (with Windows Hello).
    /// A use in an "always ask" environment (prod) skips the key's scope and can't be allowed for good.
    /// </summary>
    private async Task AuthorizeAsync(AccessKey key, SecretOperation operation, IReadOnlyList<SecretUse> uses, string? reason, string? command)
    {
        var secrets = uses.Select(u => u.Info).ToList();
        var alwaysAsk = uses.Any(u => u.Environment?.AlwaysAsk == true);
        // Approvals and grants are per secret, except in "always ask" environments ("orders-db@prod");
        // the audit log always records the environment.
        var names = uses.Select(u => u.Environment?.AlwaysAsk == true ? u.Label : u.Info.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var logged = uses.Select(u => u.Label).ToList();
        var verb = operation.ToString().ToLowerInvariant();
        if (!alwaysAsk && key.Allows(operation, secrets))
        {
            AuditLog.Write(verb, logged, key, "access key");
            return;
        }
        if (ApprovedRecently(operation, names))
        {
            AuditLog.Write(verb, logged, key, "approved earlier this session");
            return;
        }

        // "Always" adds secrets to the key's scope; for a get that only helps if the key may print values.
        var canAlways = !alwaysAsk && (operation == SecretOperation.Run || key.AllowGet);
        var result = await Approvals.RequestAsync(new ApprovalRequest(operation, names, key.Id, key.Name, reason, command, canAlways));
        if (result == ApprovalResult.Denied)
            throw new AccessDeniedException($"The user denied access to {string.Join(", ", names)}. Don't retry; ask them if it's needed.");

        var until = DateTimeOffset.Now.AddMinutes(KeyloConfig.Load().SessionMinutes);
        lock (_approvedLock)
            foreach (var name in names) _approved[(operation, name.ToLowerInvariant())] = until;
        AuditLog.Write(verb, logged, key, result == ApprovalResult.AllowedAlways ? "approved (added to key)" : "approved for the session");
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>One use of a secret: which field, and for a per-environment link which environment.</summary>
    private sealed record SecretUse(SecretInfo Info, string? Field, VaultEnvironment? Environment)
    {
        /// <summary>"orders-db", or "orders-db@prod" for a per-environment link.</summary>
        public string Label => Environment is null ? Info.Name : $"{Info.Name}@{Environment.Name}";
    }

    /// <summary>"name", "name:field", "name@env" or "name@env:field"; an exact secret name wins (names may contain ':' and '@').</summary>
    private SecretUse ResolveSource(string source)
    {
        var reference = SecretReference.Parse(source, n => _store.Find(n) is not null) ?? throw new SecretNotFoundException(source);
        var info = _store.Find(reference.Name)!;
        return new SecretUse(info, reference.Field, LinkedSecrets.EnvironmentFor(info, KeyloConfig.Load(), reference.Environment));
    }

    /// <summary>
    /// Every field of a secret, in schema order: plain secrets as username/value, typed ones by
    /// field id. Each secret field value is registered for redaction.
    /// </summary>
    private Dictionary<string, string> ReadAll(SecretUse use)
    {
        var info = use.Info;
        if (LinkedSecrets.Read(info) is { } link)
        {
            // Read live from the linked vault (and environment); everything except known non-secret fields is redacted.
            var values = LinkedSecrets.ResolveAsync(info, _registry, KeyloConfig.Load(), use.Environment?.Name).GetAwaiter().GetResult();
            var plain = link.Fields.Where(f => !f.Secret).Select(f => f.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var (id, value) in values)
                if (!plain.Contains(id) || !LinkedSecrets.LooksPublic(id)) lock (_redactorLock) _redactor.Add($"{info.Name}:{id}", value);
            return values;
        }

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
        if (LinkedSecrets.Read(info) is { } link)
        {
            var linkedId = field?.ToLowerInvariant() switch { null or "value" => link.MainField, "key" => "username", _ => field };
            return linkedId is not null && all.TryGetValue(linkedId, out var linked)
                ? linked
                : throw new KeyloException($"'{info.Name}' has no {(field is null ? "value" : $"field '{field}'")}. Fields: {string.Join(", ", all.Keys)}.");
        }

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
            "description": "Run a shell command with secrets as environment variables. Preferred over get_secret: values never enter the conversation, and any that appear in the output are replaced with [keylo:name]. Returns the exit code, stdout and stderr. Secrets your key doesn't cover ask the user first.",
            "inputSchema": {
              "type": "object",
              "properties": {
                "env": {
                  "type": "object",
                  "description": "Environment variable -> secret name, which maps its main value, or 'name:field' for one field (see the fields from search_secrets), e.g. {\"GITHUB_TOKEN\": \"github-token\", \"DB_URL\": \"prod-db:connection_string\", \"DB_USER\": \"prod-db:username\"}.",
                  "additionalProperties": { "type": "string" }
                },
                "command": { "type": "string", "description": "The command line. Reference variables in the shell's syntax: $env:VAR (powershell), %VAR% (cmd), $VAR (bash, zsh, sh)." },
                "shell": { "type": "string", "enum": ["powershell", "cmd", "bash", "zsh", "sh"], "description": "Windows: powershell (default; pwsh if installed), cmd, or bash (Git Bash). macOS: zsh (default), bash, sh, or powershell if installed." },
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
