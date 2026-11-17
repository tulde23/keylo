namespace Keylo.Cli;

public sealed class UsageException(string message) : Exception(message);

/// <summary>
/// Minimal argument reader: positionals, "--name value" options, repeatable options, boolean
/// flags, and "--" ending option parsing (everything after it is <see cref="Rest"/>).
/// </summary>
public sealed class Args
{
    private readonly List<string> _positionals = [];
    private readonly Dictionary<string, List<string>> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _consumed = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string> Rest { get; }

    public Args(IEnumerable<string> args, IEnumerable<string> flagNames)
    {
        var flags = new HashSet<string>(flagNames, StringComparer.OrdinalIgnoreCase);
        var list = args.ToList();
        var rest = new List<string>();

        for (var i = 0; i < list.Count; i++)
        {
            var arg = list[i];
            if (arg == "--")
            {
                rest.AddRange(list.Skip(i + 1));
                break;
            }

            if (arg.StartsWith("--") && arg.Length > 2)
            {
                var name = arg[2..];
                string? inline = null;
                var eq = name.IndexOf('=');
                if (eq > 0)
                {
                    inline = name[(eq + 1)..];
                    name = name[..eq];
                }

                if (flags.Contains(name))
                {
                    _flags.Add(name);
                    continue;
                }

                var value = inline ?? (i + 1 < list.Count ? list[++i] : throw new UsageException($"--{name} needs a value."));
                if (!_options.TryGetValue(name, out var values)) _options[name] = values = [];
                values.Add(value);
                continue;
            }

            _positionals.Add(arg);
        }

        Rest = rest;
    }

    public int PositionalCount => _positionals.Count;

    public string Positional(int index, string what) =>
        index < _positionals.Count ? _positionals[index] : throw new UsageException($"Missing {what}.");

    public string? OptionalPositional(int index) => index < _positionals.Count ? _positionals[index] : null;

    public IReadOnlyList<string> PositionalsFrom(int index) => _positionals.Skip(index).ToList();

    public bool Flag(string name)
    {
        _consumed.Add(name);
        return _flags.Contains(name);
    }

    public string? Option(string name)
    {
        _consumed.Add(name);
        return _options.TryGetValue(name, out var values) ? values[^1] : null;
    }

    public IReadOnlyList<string> Options(string name)
    {
        _consumed.Add(name);
        return _options.TryGetValue(name, out var values) ? values : [];
    }

    /// <summary>
    /// Rejects options the command didn't read and, when <paramref name="maxPositionals"/> is given,
    /// extra positionals, so typos and misplaced values aren't silently ignored.
    /// </summary>
    public void ThrowOnUnknown(int? maxPositionals = null)
    {
        var unknown = _options.Keys.Concat(_flags).FirstOrDefault(k => !_consumed.Contains(k));
        if (unknown is not null) throw new UsageException($"Unknown option --{unknown}.");
        if (maxPositionals is { } max && _positionals.Count > max)
            throw new UsageException($"Unexpected argument '{_positionals[max]}'.");
    }
}
