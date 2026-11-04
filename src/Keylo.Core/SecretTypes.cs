using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keylo.Core;

public enum FieldKind
{
    /// <summary>Plain text, readable without unlocking (stored as a credential attribute, max 256 bytes).</summary>
    Text,

    /// <summary>The account name / key id; stored as the credential's own username, shown as "Key". At most one per type.</summary>
    Username,

    Url,
    Number,

    /// <summary>Secret, single line. The first secret field is the type's main value.</summary>
    Password,

    /// <summary>Secret, multi-line (private keys, notes, certificates).</summary>
    SecretText,
}

public sealed class FieldDefinition
{
    /// <summary>Identifier used by the CLI and MCP ("password", "host"): lowercase letters, digits, underscores.</summary>
    public string Id { get; set; } = "";

    public string Label { get; set; } = "";

    [JsonConverter(typeof(JsonStringEnumConverter<FieldKind>))]
    public FieldKind Kind { get; set; } = FieldKind.Text;

    /// <summary>Suggested values (e.g. database engines); free text is still allowed.</summary>
    public List<string>? Options { get; set; }

    [JsonIgnore] public bool IsSecret => Kind is FieldKind.Password or FieldKind.SecretText;

    /// <summary>"Host name" → "host_name".</summary>
    public static string IdFor(string label)
    {
        var id = new string(label.Trim().ToLowerInvariant().Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_').ToArray());
        while (id.Contains("__")) id = id.Replace("__", "_");
        return id.Trim('_');
    }
}

/// <summary>
/// A kind of secret with named fields, like 1Password's item categories. Secret fields live in the
/// encrypted value (as JSON); the others are credential metadata, so they can be searched and shown
/// (also to agents whose access key covers the secret) without unlocking.
/// </summary>
public sealed class SecretTypeDefinition
{
    /// <summary>Stored on each secret. Plain secrets (one value, no type) have none.</summary>
    public string Id { get; set; } = "";

    public string Name { get; set; } = "";

    /// <summary>Default icon (a Fluent symbol name, or an uploaded image id) for secrets of this type.</summary>
    public string? Icon { get; set; }

    /// <summary>Default tile colour ("#RRGGBB") for secrets of this type.</summary>
    public string? Color { get; set; }

    public List<FieldDefinition> Fields { get; set; } = [];

    [JsonIgnore] public bool IsBuiltIn { get; init; }

    [JsonIgnore] public FieldDefinition? Primary => Fields.FirstOrDefault(f => f.IsSecret);

    [JsonIgnore] public FieldDefinition? UsernameField => Fields.FirstOrDefault(f => f.Kind == FieldKind.Username);

    public FieldDefinition? Field(string id) => Fields.FirstOrDefault(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Checks a custom type before saving; null when fine.</summary>
    public string? Problem()
    {
        if (string.IsNullOrWhiteSpace(Name)) return "A type needs a name.";
        if (Fields.Count == 0) return $"'{Name}' needs at least one field.";
        if (Primary is null) return $"'{Name}' needs at least one secret field (Password or Secret text).";
        if (Fields.Count(f => f.Kind == FieldKind.Username) > 1) return $"'{Name}' can have only one Username field.";
        if (Fields.Count > 40) return $"'{Name}' has too many fields (max 40).";
        if (Fields.FirstOrDefault(f => f.Id.Length == 0) is { } unnamed) return $"Every field in '{Name}' needs a label{(unnamed.Label.Length > 0 ? $" ('{unnamed.Label}' has no letters or digits)" : "")}.";
        if (Fields.GroupBy(f => f.Id).FirstOrDefault(g => g.Count() > 1) is { } dup) return $"'{Name}' has two fields called '{dup.Key}'.";
        return null;
    }
}

/// <summary>
/// Built-in types plus the user's own, from types.json in the data folder, which also holds the
/// icon and colour chosen for built-in types.
/// </summary>
public sealed class SecretTypeCatalog
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static readonly IReadOnlyList<SecretTypeDefinition> BuiltIn =
    [
        new()
        {
            Id = "login", Name = "Login", Icon = "Person24", IsBuiltIn = true,
            Fields =
            [
                new() { Id = "username", Label = "Username", Kind = FieldKind.Username },
                new() { Id = "password", Label = "Password", Kind = FieldKind.Password },
                new() { Id = "url", Label = "Website", Kind = FieldKind.Url },
            ],
        },
        new()
        {
            Id = "api_key", Name = "API key", Icon = "Key24", IsBuiltIn = true,
            Fields =
            [
                new() { Id = "key_id", Label = "Key ID", Kind = FieldKind.Username },
                new() { Id = "secret", Label = "Secret", Kind = FieldKind.Password },
                new() { Id = "endpoint", Label = "Endpoint", Kind = FieldKind.Url },
            ],
        },
        new()
        {
            Id = "database", Name = "Database", Icon = "Database24", IsBuiltIn = true,
            Fields =
            [
                new() { Id = "engine", Label = "Engine", Kind = FieldKind.Text, Options = ["postgres", "mysql", "sqlserver", "mongodb", "redis", "other"] },
                new() { Id = "host", Label = "Host", Kind = FieldKind.Text },
                new() { Id = "port", Label = "Port", Kind = FieldKind.Number },
                new() { Id = "database", Label = "Database", Kind = FieldKind.Text },
                new() { Id = "username", Label = "Username", Kind = FieldKind.Username },
                new() { Id = "password", Label = "Password", Kind = FieldKind.Password },
                new() { Id = "connection_string", Label = "Connection string", Kind = FieldKind.SecretText },
            ],
        },
        new()
        {
            Id = "ssh_key", Name = "SSH key", Icon = "Server24", IsBuiltIn = true,
            Fields =
            [
                new() { Id = "username", Label = "Username", Kind = FieldKind.Username },
                new() { Id = "private_key", Label = "Private key", Kind = FieldKind.SecretText },
                new() { Id = "passphrase", Label = "Passphrase", Kind = FieldKind.Password },
                new() { Id = "host", Label = "Host", Kind = FieldKind.Text },
                new() { Id = "public_key", Label = "Public key", Kind = FieldKind.Text },
            ],
        },
        new()
        {
            Id = "note", Name = "Secure note", Icon = "Note24", IsBuiltIn = true,
            Fields = [new() { Id = "note", Label = "Note", Kind = FieldKind.SecretText }],
        },
    ];

    private readonly string _path;

    public SecretTypeCatalog(string? dataDirectory = null) =>
        _path = Path.Combine(dataDirectory ?? KeyloPaths.DefaultDataDirectory, "types.json");

    private sealed class TypesFile
    {
        public List<SecretTypeDefinition> Custom { get; set; } = [];
        public Dictionary<string, CategoryStyle> BuiltInStyles { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private TypesFile Read()
    {
        if (!File.Exists(_path)) return new TypesFile();
        try
        {
            return JsonSerializer.Deserialize<TypesFile>(File.ReadAllText(_path), Json) ?? new TypesFile();
        }
        catch (JsonException ex)
        {
            throw new KeyloException($"types.json is invalid: {ex.Message}");
        }
    }

    private void Write(TypesFile file)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(file, Json));
    }

    public IReadOnlyList<SecretTypeDefinition> Custom() => Read().Custom;

    /// <summary>Built-in types with the user's icon and colour applied.</summary>
    public IReadOnlyList<SecretTypeDefinition> BuiltInStyled()
    {
        var styles = Read().BuiltInStyles;
        return BuiltIn.Select(b => styles.TryGetValue(b.Id, out var style)
            ? new SecretTypeDefinition { Id = b.Id, Name = b.Name, Fields = b.Fields, IsBuiltIn = true, Icon = style.Icon ?? b.Icon, Color = style.Color }
            : b).ToList();
    }

    public IReadOnlyList<SecretTypeDefinition> All() => [.. BuiltInStyled(), .. Custom()];

    /// <summary>Icon and colour for built-in types (their fields are fixed).</summary>
    public void SaveBuiltInStyles(IReadOnlyDictionary<string, (string? Icon, string? Color)> styles)
    {
        var file = Read();
        file.BuiltInStyles = styles
            .Where(p => BuiltIn.Any(b => b.Id == p.Key))
            .Where(p => p.Value.Color is not null || p.Value.Icon != BuiltIn.First(b => b.Id == p.Key).Icon)
            .ToDictionary(p => p.Key, p => new CategoryStyle { Icon = p.Value.Icon, Color = p.Value.Color }, StringComparer.OrdinalIgnoreCase);
        Write(file);
    }

    public SecretTypeDefinition? Find(string? id) =>
        id is null ? null : All().FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Find by id or display name ("login", "API key").</summary>
    public SecretTypeDefinition? Resolve(string idOrName) =>
        All().FirstOrDefault(t => t.Id.Equals(idOrName, StringComparison.OrdinalIgnoreCase) || t.Name.Equals(idOrName, StringComparison.OrdinalIgnoreCase));

    /// <summary>Replaces the custom types. Ids are derived from names and must not clash with built-ins.</summary>
    public void SaveCustom(IReadOnlyList<SecretTypeDefinition> types)
    {
        foreach (var type in types)
        {
            type.Name = type.Name.Trim();
            if (string.IsNullOrEmpty(type.Id)) type.Id = FieldDefinition.IdFor(type.Name);
            foreach (var field in type.Fields)
            {
                field.Label = field.Label.Trim();
                // Ids are fixed once set (secrets store data under them); relabeling keeps the id.
                if (string.IsNullOrEmpty(field.Id)) field.Id = FieldDefinition.IdFor(field.Label);
                if (field.Options is { Count: 0 }) field.Options = null;
            }
            if (type.Problem() is { } problem) throw new KeyloException(problem);
            if (type.Id.Length == 0) throw new KeyloException($"'{type.Name}' needs letters or digits in its name.");
            if (BuiltIn.Any(b => b.Id == type.Id)) throw new KeyloException($"'{type.Name}' clashes with the built-in type '{BuiltIn.First(b => b.Id == type.Id).Name}'.");
        }
        if (types.GroupBy(t => t.Id).FirstOrDefault(g => g.Count() > 1) is { } dup)
            throw new KeyloException($"Two types are called '{dup.First().Name}'.");

        var file = Read();
        file.Custom = [.. types];
        Write(file);
    }
}

/// <summary>Converts between a typed secret's fields and how they're stored.</summary>
public static class TypedSecrets
{
    /// <summary>
    /// Builds the draft for a typed secret: the Username field becomes the credential username,
    /// other non-secret fields metadata, secret fields the (JSON) value. Empty fields are dropped.
    /// </summary>
    public static SecretDraft Draft(SecretTypeDefinition type, string name, IReadOnlyDictionary<string, string?> fields,
        string? category = null, string? notes = null, string? icon = null, string? color = null)
    {
        string? username = null;
        var visible = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var secret = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var field in type.Fields)
        {
            if (!fields.TryGetValue(field.Id, out var value) || string.IsNullOrEmpty(value)) continue;
            if (field.Kind == FieldKind.Username) username = value.Trim();
            else if (field.IsSecret) secret[field.Id] = value;
            else visible[field.Id] = value.Trim();
        }

        if (fields.Keys.FirstOrDefault(k => type.Field(k) is null) is { } unknown)
            throw new KeyloException($"'{type.Name}' has no field '{unknown}'. Fields: {string.Join(", ", type.Fields.Select(f => f.Id))}.");

        return new SecretDraft(name, JsonSerializer.SerializeToUtf8Bytes(secret), category, username, notes, icon, color, type.Id, visible);
    }

    /// <summary>
    /// Every field's value: metadata plus the decrypted secret fields, and (with <paramref name="derive"/>)
    /// a database connection string built from the other fields when none is stored. Pass false when
    /// the fields will be saved back, so the derived string doesn't become a stale stored one.
    /// </summary>
    public static Dictionary<string, string> ReadFields(SecretTypeDefinition type, SecretInfo info, byte[] value, bool derive = true)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (type.UsernameField is { } user && info.Username is not null) fields[user.Id] = info.Username;
        foreach (var (id, text) in info.Fields ?? new Dictionary<string, string>()) fields[id] = text;

        try
        {
            foreach (var (id, text) in JsonSerializer.Deserialize<Dictionary<string, string>>(value) ?? [])
                fields[id] = text;
        }
        catch (JsonException)
        {
            // A value that isn't JSON (e.g. a plain secret whose type was set by hand) becomes the main field.
            if (type.Primary is { } primary && Encoding.UTF8.GetString(value) is { Length: > 0 } raw) fields[primary.Id] = raw;
        }

        if (derive && type.Id == "database" && !fields.ContainsKey("connection_string") && ConnectionString(fields) is { } derived)
            fields["connection_string"] = derived;
        return fields;
    }

    /// <summary>The main value of a secret as text: the primary field for typed secrets, the value itself otherwise.</summary>
    public static string? MainValue(SecretTypeDefinition? type, Secret secret)
    {
        if (type is null) return DecodeText(secret.Value);
        return type.Primary is { } primary && ReadFields(type, secret.Info, secret.Value).TryGetValue(primary.Id, out var main) ? main : "";
    }

    /// <summary>
    /// A connection string built from a database secret's fields, for engines with a standard form.
    /// Used only when the secret doesn't store its own.
    /// </summary>
    public static string? ConnectionString(IReadOnlyDictionary<string, string> f)
    {
        if (!f.TryGetValue("host", out var host)) return null;
        f.TryGetValue("port", out var port);
        f.TryGetValue("database", out var db);
        f.TryGetValue("username", out var user);
        f.TryGetValue("password", out var pass);
        f.TryGetValue("engine", out var engine);

        string Url(string scheme) =>
            $"{scheme}://{(user is null ? "" : Uri.EscapeDataString(user) + (pass is null ? "" : ":" + Uri.EscapeDataString(pass)) + "@")}{host}{(port is null ? "" : ":" + port)}/{db}";

        return engine?.ToLowerInvariant() switch
        {
            "postgres" or "postgresql" => Url("postgresql"),
            "mysql" or "mariadb" => Url("mysql"),
            "mongodb" => Url("mongodb"),
            "redis" => Url("redis"),
            "sqlserver" or "mssql" => $"Server={host}{(port is null ? "" : "," + port)};Database={db};User Id={user};Password={pass};TrustServerCertificate=True;",
            _ => null,
        };
    }

    public static string? DecodeText(byte[] value)
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
}
