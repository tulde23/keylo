using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keylo.Core;

public enum HelloMode
{
    /// <summary>Verify once, then trust this user for <see cref="KeyloConfig.SessionMinutes"/> (CLI and UI share it).</summary>
    Session,

    /// <summary>Verify on every value access (reveal, copy, run, export).</summary>
    Always,

    /// <summary>No Windows Hello prompt; rely on the Windows login (DPAPI) alone.</summary>
    Never,
}

public sealed class KeyloConfig
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public HelloMode Hello { get; set; } = HelloMode.Session;
    public int SessionMinutes { get; set; } = 15;
    public int ClipboardSeconds { get; set; } = 30;

    /// <summary>Callers allowed to use some secrets without Windows Hello. See <see cref="Security.TrustGroup"/>.</summary>
    public List<Security.TrustGroup> TrustGroups { get; set; } = [];

    /// <summary>Per-provider settings, e.g. { "1password": { "vault": "Private" } }.</summary>
    public Dictionary<string, Dictionary<string, string>> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public static string PathIn(string dataDirectory) => Path.Combine(dataDirectory, "config.json");

    public static KeyloConfig Load(string? dataDirectory = null)
    {
        var path = PathIn(dataDirectory ?? KeyloPaths.DefaultDataDirectory);
        if (!File.Exists(path)) return new KeyloConfig();

        try
        {
            return (JsonSerializer.Deserialize<KeyloConfig>(File.ReadAllText(path), Json) ?? new KeyloConfig()).Clamp();
        }
        catch (JsonException ex)
        {
            throw new KeyloException($"config.json is invalid: {ex.Message}");
        }
    }

    public void Save(string? dataDirectory = null)
    {
        var dir = dataDirectory ?? KeyloPaths.DefaultDataDirectory;
        Directory.CreateDirectory(dir);
        File.WriteAllText(PathIn(dir), JsonSerializer.Serialize(Clamp(), Json));
    }

    private KeyloConfig Clamp()
    {
        SessionMinutes = Math.Clamp(SessionMinutes, 1, 24 * 60);
        ClipboardSeconds = Math.Clamp(ClipboardSeconds, 5, 600);
        return this;
    }
}
