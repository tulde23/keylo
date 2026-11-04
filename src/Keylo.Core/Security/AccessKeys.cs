using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keylo.Core.Security;

/// <summary>What a caller is doing with secrets, for access-key checks.</summary>
public enum SecretOperation
{
    /// <summary>Listing or searching names and details (never values).</summary>
    Browse,

    /// <summary>Handing values to a child process as environment variables (keylo run).</summary>
    Run,

    /// <summary>Printing, copying or exporting a value (keylo get).</summary>
    Get,
}

/// <summary>
/// Lets a tool such as Claude Code use a set of secrets without Windows Hello. The tool presents the
/// key in the <see cref="AccessKeys.EnvironmentVariable"/> environment variable; Keylo stores only
/// its SHA-256 hash. Run-only unless <see cref="AllowGet"/>: an agent that prints a secret puts it in
/// its conversation, while <c>keylo run</c> hands it straight to the command.
/// </summary>
public sealed class AccessKey
{
    /// <summary>Short public id (not secret), shown in the audit log and used to find the key again.</summary>
    public string Id { get; set; } = "";

    public string Name { get; set; } = "";

    /// <summary>Lowercase hex SHA-256 of the full key.</summary>
    public string Hash { get; set; } = "";

    public List<string> Categories { get; set; } = [];

    public List<string> Secrets { get; set; } = [];

    public bool AllowGet { get; set; }

    public DateTimeOffset Created { get; set; }

    public DateTimeOffset? Expires { get; set; }

    public bool IsExpired(DateTimeOffset now) => Expires is { } expires && expires <= now;

    public bool Covers(SecretInfo secret) =>
        Secrets.Contains(secret.Name, StringComparer.OrdinalIgnoreCase) ||
        (secret.Category is not null && Categories.Contains(secret.Category, StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Whether this key alone allows <paramref name="operation"/> on every one of
    /// <paramref name="secrets"/>. Browsing is always allowed (callers then see what they may use).
    /// </summary>
    public bool Allows(SecretOperation operation, IReadOnlyCollection<SecretInfo> secrets) => operation switch
    {
        SecretOperation.Browse => true,
        SecretOperation.Get when !AllowGet => false,
        _ => secrets.Count > 0 && secrets.All(Covers),
    };
}

public static class AccessKeys
{
    public const string EnvironmentVariable = "KEYLO_ACCESS_KEY";
    private const string TokenPrefix = "kyl_";

    /// <summary>Creates a key; the returned token is shown once and never stored.</summary>
    public static (AccessKey Key, string Token) Create(string name, DateTimeOffset? expires = null)
    {
        var token = TokenPrefix + Base64Url(RandomNumberGenerator.GetBytes(32));
        var key = new AccessKey
        {
            Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant(),
            Name = name.Trim(),
            Hash = HashOf(token),
            Created = DateTimeOffset.Now,
            Expires = expires,
        };
        return (key, token);
    }

    /// <summary>The unexpired key matching <paramref name="token"/>, or null.</summary>
    public static AccessKey? Find(KeyloConfig config, string? token)
    {
        token = token?.Trim();
        if (string.IsNullOrEmpty(token) || !token.StartsWith(TokenPrefix, StringComparison.Ordinal)) return null;

        var hash = Encoding.ASCII.GetBytes(HashOf(token));
        var now = DateTimeOffset.Now;
        return config.AccessKeys.FirstOrDefault(k =>
            !k.IsExpired(now) && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(k.Hash), hash));
    }

    /// <summary>The key this process was given through <see cref="EnvironmentVariable"/>, if valid.</summary>
    public static AccessKey? FromEnvironment(KeyloConfig config) =>
        Find(config, Environment.GetEnvironmentVariable(EnvironmentVariable));

    /// <summary>Whether this process was given a key at all (valid or not), for clearer errors.</summary>
    public static bool IsPresentInEnvironment =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(EnvironmentVariable));

    /// <summary>Adds secrets to a key's scope, e.g. after "Always allow" in an approval.</summary>
    public static bool Grant(KeyloConfig config, string keyId, IEnumerable<string> secrets)
    {
        var key = config.AccessKeys.FirstOrDefault(k => k.Id == keyId);
        if (key is null) return false;
        foreach (var secret in secrets)
            if (!key.Secrets.Contains(secret, StringComparer.OrdinalIgnoreCase)) key.Secrets.Add(secret);
        return true;
    }

    internal static string HashOf(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Append-only record of every access that skipped Windows Hello.</summary>
public static class AuditLog
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string PathIn(string dataDirectory) => Path.Combine(dataDirectory, "audit.log");

    /// <param name="via">How it was allowed: the access key's name, or "approved" for a one-off approval.</param>
    public static void Write(string operation, IEnumerable<string> secrets, AccessKey? key, string via, string? dataDirectory = null)
    {
        var entry = new
        {
            time = DateTimeOffset.Now,
            operation,
            secrets = secrets.ToArray(),
            key = key?.Name,
            keyId = key?.Id,
            via,
            chain = ProcessAncestry.Current().Take(6).Select(p => $"{p.ExecutableName}({p.ProcessId})").ToArray(),
        };

        var dir = dataDirectory ?? KeyloPaths.DefaultDataDirectory;
        Directory.CreateDirectory(dir);
        File.AppendAllText(PathIn(dir), JsonSerializer.Serialize(entry, Json) + Environment.NewLine);
    }
}
