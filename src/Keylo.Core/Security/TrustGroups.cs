using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keylo.Core.Security;

/// <summary>What a caller is doing with secrets, for trust-group matching.</summary>
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
/// Lets named callers use a set of secrets without Windows Hello, e.g. Claude Code using the "dev"
/// category. Run-only unless <see cref="AllowGet"/>: an agent that prints a secret puts it in its
/// conversation, while <c>keylo run</c> hands it straight to the command.
/// </summary>
public sealed class TrustGroup
{
    public string Name { get; set; } = "";

    /// <summary>Executable names, matched against any process in the caller chain (e.g. "claude.exe").</summary>
    public List<string> Callers { get; set; } = [];

    public List<string> Categories { get; set; } = [];

    public List<string> Secrets { get; set; } = [];

    public bool AllowGet { get; set; }

    public bool Covers(SecretInfo secret) =>
        Secrets.Contains(secret.Name, StringComparer.OrdinalIgnoreCase) ||
        (secret.Category is not null && Categories.Contains(secret.Category, StringComparer.OrdinalIgnoreCase));

    /// <summary>The nearest process in the caller chain that this group trusts, if any.</summary>
    public AncestorProcess? FindCaller(IReadOnlyList<AncestorProcess> ancestry) =>
        ancestry.FirstOrDefault(p => Callers.Any(c => string.Equals(Normalize(c), Normalize(p.ExecutableName), StringComparison.OrdinalIgnoreCase)));

    private static string Normalize(string exe) => exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exe : exe + ".exe";
}

public sealed record TrustDecision(TrustGroup Group, AncestorProcess Caller);

public static class TrustPolicy
{
    /// <summary>
    /// The group that lets this caller perform <paramref name="operation"/> on every one of
    /// <paramref name="secrets"/> without prompting, or null. Every secret must be covered by the
    /// same group, so one trusted secret can't be used to carry an untrusted one along.
    /// </summary>
    public static TrustDecision? Find(
        KeyloConfig config,
        SecretOperation operation,
        IReadOnlyCollection<SecretInfo> secrets,
        IReadOnlyList<AncestorProcess> ancestry)
    {
        foreach (var group in config.TrustGroups)
        {
            if (operation == SecretOperation.Get && !group.AllowGet) continue;
            if (group.FindCaller(ancestry) is not { } caller) continue;
            if (operation != SecretOperation.Browse && (secrets.Count == 0 || !secrets.All(group.Covers))) continue;

            return new TrustDecision(group, caller);
        }

        return null;
    }

    /// <summary>Groups whose callers match, for showing a trusted caller only the secrets it may use.</summary>
    public static IReadOnlyList<TrustGroup> GroupsFor(KeyloConfig config, IReadOnlyList<AncestorProcess> ancestry) =>
        config.TrustGroups.Where(g => g.FindCaller(ancestry) is not null).ToList();
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

    public static void Write(
        string operation,
        IEnumerable<string> secrets,
        TrustDecision decision,
        IReadOnlyList<AncestorProcess> ancestry,
        string? dataDirectory = null)
    {
        var entry = new
        {
            time = DateTimeOffset.Now,
            operation,
            secrets = secrets.ToArray(),
            group = decision.Group.Name,
            caller = decision.Caller.ExecutableName,
            chain = ancestry.Select(p => $"{p.ExecutableName}({p.ProcessId})").ToArray(),
        };

        var dir = dataDirectory ?? KeyloPaths.DefaultDataDirectory;
        Directory.CreateDirectory(dir);
        File.AppendAllText(PathIn(dir), JsonSerializer.Serialize(entry, Json) + Environment.NewLine);
    }
}
