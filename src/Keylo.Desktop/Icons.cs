using FluentIcons.Common;

namespace Keylo.Desktop;

/// <summary>
/// Keylo stores icons by WPF-UI's names ("Key24", "MusicNote124", "CalendarLtr24"); FluentIcons names
/// the same glyphs without the size ("Key", "MusicNote1", "Calendar").
/// </summary>
public static class Icons
{
    private static readonly string[] Sizes = ["10", "12", "16", "20", "24", "28", "32", "48"];
    private static readonly Dictionary<string, Symbol?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static Symbol? Find(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.StartsWith("img", StringComparison.Ordinal)) return null;
        lock (Cache)
        {
            if (Cache.TryGetValue(name, out var cached)) return cached;
            return Cache[name] = Resolve(name);
        }
    }

    private static Symbol? Resolve(string name)
    {
        foreach (var candidate in Candidates(name))
            if (Enum.TryParse<Symbol>(candidate, ignoreCase: true, out var symbol) && Enum.IsDefined(symbol))
                return symbol;
        return null;
    }

    private static IEnumerable<string> Candidates(string name)
    {
        var bare = Sizes.FirstOrDefault(s => name.Length > s.Length && name.EndsWith(s, StringComparison.Ordinal)) is { } size
            ? name[..^size.Length] : name;
        yield return bare;
        if (bare.EndsWith("Ltr", StringComparison.Ordinal) || bare.EndsWith("Rtl", StringComparison.Ordinal)) yield return bare[..^3];
        yield return name;
    }
}
