namespace Keylo.Core.Security;

/// <summary>
/// Replaces secret values in command output with <c>[keylo:name]</c> before an agent sees it.
/// It catches accidental leaks (a command that echoes its token, a verbose error), not deliberate
/// ones: a command can still transform a value (base64, reversed) so it no longer matches.
/// </summary>
public sealed class OutputRedactor
{
    /// <summary>Shorter values would match ordinary text, so they aren't redacted.</summary>
    public const int MinLength = 4;

    private readonly Dictionary<string, string> _labels = new(StringComparer.Ordinal);

    public int LongestValue { get; private set; }

    public void Add(string name, string value)
    {
        // Values imported from files often end with a newline the output won't repeat.
        foreach (var variant in new[] { value, value.Trim() })
        {
            if (variant.Length < MinLength || _labels.ContainsKey(variant)) continue;
            _labels[variant] = $"[keylo:{name}]";
            LongestValue = Math.Max(LongestValue, variant.Length);
        }
    }

    public string Redact(string text)
    {
        // Longest first, so a value containing another is replaced whole.
        foreach (var (value, label) in _labels.OrderByDescending(p => p.Key.Length))
            text = text.Replace(value, label, StringComparison.Ordinal);
        return text;
    }
}
