namespace Keylo.Core.Providers;

/// <summary>
/// A named environment of a vault (dev, uat, prod…): which profile and region to read it with on
/// this computer. <see cref="AlwaysAsk"/> makes every use from it ask the user, whatever an access
/// key covers.
/// </summary>
public sealed record VaultEnvironment(string Name, string? Profile, string? Region, bool AlwaysAsk);

/// <summary>
/// Environments are kept in a provider's settings (config.json, so per computer: each machine maps
/// "prod" to its own profile), as "env:NAME" = "profile|region|ask", plus "default_environment".
/// Links made "per environment" store only the secret's name; the environment picks the account.
/// </summary>
public static class VaultEnvironments
{
    public const string Prefix = "env:";
    public const string DefaultKey = "default_environment";

    public static IReadOnlyList<VaultEnvironment> Read(IReadOnlyDictionary<string, string> settings) =>
        settings
            .Where(s => s.Key.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) && s.Key.Length > Prefix.Length)
            .Select(s =>
            {
                var parts = s.Value.Split('|');
                string? Part(int i) => parts.Length > i && parts[i].Trim() is { Length: > 0 } p ? p : null;
                return new VaultEnvironment(s.Key[Prefix.Length..], Part(0), Part(1), Part(2) == "ask");
            })
            .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public static VaultEnvironment? Find(IReadOnlyDictionary<string, string> settings, string name) =>
        Read(settings).FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The configured default, else the only environment, else null.</summary>
    public static string? Default(IReadOnlyDictionary<string, string> settings)
    {
        var all = Read(settings);
        if (settings.GetValueOrDefault(DefaultKey) is { Length: > 0 } name && all.Any(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) return name;
        return all.Count == 1 ? all[0].Name : null;
    }

    /// <summary>Writes <paramref name="environments"/> into <paramref name="settings"/>, replacing any there.</summary>
    public static void Write(IDictionary<string, string> settings, IEnumerable<VaultEnvironment> environments, string? defaultEnvironment)
    {
        foreach (var key in settings.Keys.Where(k => k.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)).ToList()) settings.Remove(key);
        foreach (var e in environments)
        {
            if (!IsValidName(e.Name)) throw new KeyloException($"'{e.Name}' isn't a valid environment name: use letters, digits, '-' and '_'.");
            settings[Prefix + e.Name] = $"{e.Profile?.Trim()}|{e.Region?.Trim()}|{(e.AlwaysAsk ? "ask" : "")}";
        }
        if (string.IsNullOrWhiteSpace(defaultEnvironment)) settings.Remove(DefaultKey);
        else settings[DefaultKey] = defaultEnvironment.Trim();
    }

    public static bool IsValidName(string name) =>
        name.Length is > 0 and <= 32 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    /// <summary>New environments named like production start as "always ask".</summary>
    public static bool LooksLikeProduction(string name) =>
        name.Equals("prod", StringComparison.OrdinalIgnoreCase) || name.Equals("production", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("prd", StringComparison.OrdinalIgnoreCase) || name.StartsWith("prod-", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// A reference to a secret as the CLI and agents write it: "name", "name:field", "name@env" or
/// "name@env:field". An exact secret name always wins (names may contain ':' and '@').
/// </summary>
public sealed record SecretReference(string Name, string? Environment, string? Field)
{
    /// <summary>The name with its environment, for approvals and the audit log: "orders-db@prod".</summary>
    public string Display => Environment is null ? Name : $"{Name}@{Environment}";

    public static SecretReference? Parse(string text, Func<string, bool> exists)
    {
        text = text.Trim();
        if (exists(text)) return new(text, null, null);
        if (SplitEnvironment(text, exists) is { } withEnv) return withEnv;

        var colon = text.LastIndexOf(':');
        if (colon <= 0 || colon == text.Length - 1) return null;
        var (head, field) = (text[..colon], text[(colon + 1)..]);
        if (exists(head)) return new(head, null, field);
        return SplitEnvironment(head, exists) is { } r ? r with { Field = field } : null;
    }

    private static SecretReference? SplitEnvironment(string text, Func<string, bool> exists)
    {
        var at = text.LastIndexOf('@');
        if (at <= 0 || at == text.Length - 1) return null;
        var (name, env) = (text[..at], text[(at + 1)..]);
        return VaultEnvironments.IsValidName(env) && exists(name) ? new(name, env, null) : null;
    }
}
