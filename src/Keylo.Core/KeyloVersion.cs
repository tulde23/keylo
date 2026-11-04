using System.Globalization;
using System.Reflection;

namespace Keylo.Core;

/// <summary>
/// The build's version, from its informational version "1.0.0+20261104.d9670af" (stamped by
/// build.ps1: date and git commit). Plain dotnet builds may carry only a commit, or nothing.
/// </summary>
public sealed record KeyloVersion(string Version, DateOnly? BuildDate, string? Commit)
{
    public static KeyloVersion Of(Assembly assembly)
    {
        var info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                   ?? assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        var plus = info.IndexOf('+');
        if (plus < 0) return new KeyloVersion(info, null, null);

        var version = info[..plus];
        var meta = info[(plus + 1)..].Split('.');
        DateOnly? date = meta.Length >= 2 && DateOnly.TryParseExact(meta[0], "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
        var commit = date is null ? meta[0] : meta[1];
        return new KeyloVersion(version, date, commit);
    }

    public override string ToString() =>
        Version + (BuildDate is { } d ? $" · built {d:yyyy-MM-dd}" : "") + (Commit is { Length: > 0 } c ? $" · {c}" : "");
}
