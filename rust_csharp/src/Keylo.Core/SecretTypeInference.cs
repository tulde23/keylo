using System.Text;
using System.Text.RegularExpressions;

namespace Keylo.Core;

/// <summary>A guessed type for an imported file, and its value split into that type's fields.</summary>
public sealed record InferredType(string TypeId, Dictionary<string, string?> Fields);

/// <summary>
/// Guesses a secret type for an imported file from its name, extension and (text) content. Only
/// confident guesses are made; anything else stays a plain secret, which is always safe.
/// </summary>
public static partial class SecretTypeInference
{
    private const int MaxTextBytes = 64 * 1024;

    /// <summary>The type to use for <paramref name="fileName"/> with <paramref name="content"/>, or null for plain.</summary>
    public static InferredType? Infer(string fileName, byte[] content)
    {
        if (content.Length == 0 || content.Length > MaxTextBytes || TypedSecrets.DecodeText(content) is not { } text || text.Contains('\0'))
            return null;

        var name = Path.GetFileNameWithoutExtension(fileName).ToLowerInvariant();
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        var value = text.Trim();
        if (value.Length == 0 || extension is ".pub" or ".crt" or ".cer") return null;

        // SSH / PEM private keys, by content.
        if (PrivateKey().IsMatch(value))
            return new InferredType("ssh_key", new() { ["private_key"] = text.TrimEnd() + "\n" });
        if (name is "id_rsa" or "id_ed25519" or "id_ecdsa" or "id_dsa" && value.Contains("PRIVATE KEY", StringComparison.Ordinal))
            return new InferredType("ssh_key", new() { ["private_key"] = text.TrimEnd() + "\n" });

        var singleLine = !value.Contains('\n');

        // Database: a connection URL or string, by content; or a db-ish name.
        if (singleLine && ParseDatabaseUrl(value) is { } fields) return new InferredType("database", fields);
        if (singleLine && SqlServerString().IsMatch(value))
            return new InferredType("database", new() { ["engine"] = "sqlserver", ["connection_string"] = value });
        if (singleLine && Words(name).Overlaps(["db", "database", "conn", "connection", "dsn", "postgres", "mysql", "mongo", "mongodb", "redis"]))
            return new InferredType("database", new() { ["connection_string"] = value });

        if (!singleLine) return null;
        var words = Words(name);

        if (words.Overlaps(["password", "passwd", "pwd", "pass", "login"]))
            return new InferredType("login", new() { ["password"] = value });

        if (words.Overlaps(["token", "apikey", "secret", "pat", "key", "bearer"]) || name.Contains("api_key") || name.Contains("api-key"))
            return new InferredType("api_key", new() { ["secret"] = value });

        return null;
    }

    /// <summary>"postgres://user:pass@host:5432/app" → engine, host, port, database, username, password, connection_string.</summary>
    public static Dictionary<string, string?>? ParseDatabaseUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return null;
        var engine = uri.Scheme.ToLowerInvariant() switch
        {
            "postgres" or "postgresql" => "postgres",
            "mysql" or "mariadb" => "mysql",
            "mongodb" or "mongodb+srv" => "mongodb",
            "redis" or "rediss" => "redis",
            "sqlserver" or "mssql" => "sqlserver",
            _ => null,
        };
        if (engine is null) return null;

        var fields = new Dictionary<string, string?> { ["engine"] = engine, ["connection_string"] = value };
        if (uri.Host.Length > 0) fields["host"] = uri.Host;
        if (!uri.IsDefaultPort && uri.Port > 0) fields["port"] = uri.Port.ToString();
        if (uri.AbsolutePath.Trim('/') is { Length: > 0 } db) fields["database"] = Uri.UnescapeDataString(db);
        if (uri.UserInfo.Length > 0)
        {
            var parts = uri.UserInfo.Split(':', 2);
            fields["username"] = Uri.UnescapeDataString(parts[0]);
            if (parts.Length == 2) fields["password"] = Uri.UnescapeDataString(parts[1]);
        }
        return fields;
    }

    /// <summary>"github-api_token.prod" → {github, api, token, prod}.</summary>
    private static HashSet<string> Words(string name) =>
        Separators().Split(name).Where(w => w.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(@"^-----BEGIN ([A-Z]+ )?PRIVATE KEY-----")]
    private static partial Regex PrivateKey();

    [GeneratedRegex(@"^(Server|Data Source)=[^;]+;.*(Password|Pwd)=", RegexOptions.IgnoreCase)]
    private static partial Regex SqlServerString();

    [GeneratedRegex(@"[^a-z0-9]+")]
    private static partial Regex Separators();
}
