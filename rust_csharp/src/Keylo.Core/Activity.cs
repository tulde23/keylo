using System.Text.Json;
using Keylo.Core.Security;

namespace Keylo.Core;

/// <summary>One use of a secret: by you in the app, or by a tool (from the audit log).</summary>
/// <param name="Who">"You", or the access key's name for a tool.</param>
/// <param name="Action">viewed, copied, exported, run, get.</param>
public sealed record RecentUse(string Name, DateTimeOffset Time, string Who, string Action);

/// <summary>
/// Pinned secrets (pins.json) and recently used ones: your own views and copies (recent.json) merged
/// with tools' uses from the audit log. Holds names and times only, never values.
/// </summary>
public sealed class Activity(string? dataDirectory = null)
{
    private const int MaxOwnUses = 200;
    private const int AuditLinesScanned = 1000;

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    private readonly string _dir = dataDirectory ?? KeyloPaths.DefaultDataDirectory;
    private string PinsPath => Path.Combine(_dir, "pins.json");
    private string RecentPath => Path.Combine(_dir, "recent.json");

    // ------------------------------------------------------------------ pins

    public IReadOnlyList<string> Pins() => Load<List<string>>(PinsPath) ?? [];

    public bool IsPinned(string name) => Pins().Contains(name, StringComparer.OrdinalIgnoreCase);

    public void SetPinned(string name, bool pinned)
    {
        var pins = Pins().Where(p => !p.Equals(name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (pinned) pins.Add(name);
        Save(PinsPath, pins);
    }

    // ------------------------------------------------------------------ recent

    public void RecordUse(string name, string action)
    {
        var uses = Load<List<RecentUse>>(RecentPath) ?? [];
        uses.Add(new RecentUse(name, DateTimeOffset.Now, "You", action));
        Save(RecentPath, uses.TakeLast(MaxOwnUses).ToList());
    }

    /// <summary>The latest use of each secret, newest first: yours and tools' (from the audit log).</summary>
    public IReadOnlyList<RecentUse> Recent(int limit = 8) =>
        (Load<List<RecentUse>>(RecentPath) ?? []).Concat(ToolUses())
            .GroupBy(u => u.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.MaxBy(u => u.Time)!)
            .OrderByDescending(u => u.Time)
            .Take(limit)
            .ToList();

    private IEnumerable<RecentUse> ToolUses()
    {
        var path = AuditLog.PathIn(_dir);
        if (!File.Exists(path)) yield break;

        string[] lines;
        try
        {
            lines = File.ReadLines(path).TakeLast(AuditLinesScanned).ToArray();
        }
        catch (IOException)
        {
            yield break;
        }

        foreach (var line in lines)
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(line); }
            catch (JsonException) { continue; }

            using (doc)
            {
                var root = doc.RootElement;
                if (!root.TryGetProperty("time", out var t) || !t.TryGetDateTimeOffset(out var time)) continue;
                var who = root.TryGetProperty("key", out var k) && k.GetString() is { Length: > 0 } key ? key : "A tool";
                var action = root.TryGetProperty("operation", out var o) ? o.GetString() ?? "used" : "used";
                if (!root.TryGetProperty("secrets", out var secrets) || secrets.ValueKind != JsonValueKind.Array) continue;
                foreach (var s in secrets.EnumerateArray())
                    if (s.GetString() is { Length: > 0 } name) yield return new RecentUse(name, time, who, action);
            }
        }
    }

    // ------------------------------------------------------------------ upkeep

    /// <summary>Keeps pins and your own history pointing at a renamed secret.</summary>
    public void Renamed(string oldName, string newName)
    {
        if (oldName.Equals(newName, StringComparison.Ordinal)) return;
        var pins = Pins().Select(p => p.Equals(oldName, StringComparison.OrdinalIgnoreCase) ? newName : p).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        Save(PinsPath, pins);
        var uses = (Load<List<RecentUse>>(RecentPath) ?? []).Select(u => u.Name.Equals(oldName, StringComparison.OrdinalIgnoreCase) ? u with { Name = newName } : u).ToList();
        Save(RecentPath, uses);
    }

    /// <summary>Forgets a deleted secret's pin and your history of it (the audit log is left alone).</summary>
    public void Removed(IEnumerable<string> names)
    {
        var gone = names.ToHashSet(StringComparer.OrdinalIgnoreCase);
        Save(PinsPath, Pins().Where(p => !gone.Contains(p)).ToList());
        Save(RecentPath, (Load<List<RecentUse>>(RecentPath) ?? []).Where(u => !gone.Contains(u.Name)).ToList());
    }

    private static T? Load<T>(string path)
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json) : default;
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return default; // A damaged file only loses pins/history, never secrets.
        }
    }

    private void Save<T>(string path, T value)
    {
        Directory.CreateDirectory(_dir);
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value, Json));
        File.Move(temp, path, overwrite: true);
    }
}
