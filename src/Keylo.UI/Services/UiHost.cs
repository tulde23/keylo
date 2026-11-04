using Keylo.Core.Platform;

namespace Keylo.App.Services;

/// <summary>A repeating UI-thread timer (DispatcherTimer in WPF and Avalonia).</summary>
public interface IUiTimer
{
    TimeSpan Interval { get; set; }
    void Start();
    void Stop();
}

/// <summary>A file picker filter: "Keylo backup" with extensions like ".keylo-backup".</summary>
public sealed record FileFilter(string Name, params string[] Extensions);

/// <summary>
/// What the shared view models need from the UI toolkit: WPF on Windows, Avalonia on macOS. Icons,
/// brushes and images are handed back as the toolkit's own objects and only ever bound in its views.
/// </summary>
public interface IUiHost
{
    /// <summary>The icon for a Fluent icon name ("Key24"), else <paramref name="fallback"/>'s; null when neither is known.</summary>
    object? Symbol(string? name, string? fallback);

    /// <summary>An uploaded image icon ("img…"), or null.</summary>
    object? Image(string? icon);

    /// <summary>The soft gradient behind avatar tiles, from a "#RRGGBB" colour.</summary>
    object Tile(string hex);

    /// <summary>A plain brush from "#RRGGBB", or null when it isn't a colour.</summary>
    object? Solid(string? hex);

    /// <summary>A transparent brush (tiles that show an image).</summary>
    object Transparent { get; }

    IUiTimer CreateTimer(TimeSpan interval, Action tick);

    /// <summary>Runs <paramref name="action"/> on the UI thread, later.</summary>
    void Post(Action action);

    /// <summary>Raised when the computer is locked or the session disconnects; Keylo locks too.</summary>
    event EventHandler? SessionLocked;

    Task<IReadOnlyList<string>> PickFilesAsync(string title, bool multiple, FileFilter? filter = null);
    Task<string?> PickFolderAsync(string title);
    Task<string?> PickSaveFileAsync(string title, string fileName, FileFilter? filter = null);

    /// <summary>Opens a text file in an editor (the audit log).</summary>
    void OpenTextFile(string path);

    /// <summary>Opens a folder or URL with the system's handler.</summary>
    void Open(string target);
}

/// <summary>The app's <see cref="IUiHost"/>, set once at startup before any view model is made.</summary>
public static class Ui
{
    private static IUiHost? _host;

    public static IUiHost Host => _host ?? throw new InvalidOperationException("No UI host installed. Call Ui.Install at startup.");

    public static void Install(IUiHost host) => _host = host;

    /// <summary>"Windows Hello", "Touch ID".</summary>
    public static string Verifier => KeyloPlatform.Current.VerifierName;

    /// <summary>"Windows Credential Manager", "macOS Keychain".</summary>
    public static string Store => KeyloPlatform.Current.StoreName;
}

/// <summary>The icons and colours offered for secrets and categories, by name.</summary>
public static class IconPalette
{
    /// <summary>
    /// Fluent icon names (WPF-UI's SymbolRegular spelling). Checked by eye: a few names, e.g.
    /// KeyMultiple and Calendar, map to the wrong glyph in WPF-UI's bundled font.
    /// </summary>
    public static IReadOnlyList<string> Icons { get; } =
    [
        "Key24", "LockClosed24", "Shield24",
        "ShieldKeyhole24", "Fingerprint24", "Password24", "Certificate24",
        "Cloud24", "Server24", "Database24", "Storage24",
        "Globe24", "Router24", "Wifi124", "PlugConnected24",
        "Code24", "WindowConsole20", "Branch24", "Bug24",
        "Bot24", "Cube24", "Box24", "Apps24",
        "Desktop24", "Laptop24", "Phone24", "Link24",
        "Mail24", "Chat24", "Person24", "People24",
        "Organization24", "Building24", "Briefcase24", "BuildingBank24",
        "Payment24", "Wallet24", "Money24", "Cart24",
        "DataBarVertical24", "Document24", "Archive24", "Book24",
        "Folder24", "Tag24", "Settings24", "Wrench24",
        "Home24", "Heart24", "Star24", "Gift24",
        "Games24", "MusicNote124", "Video24", "Camera24",
        "Airplane24", "VehicleCar24", "Map24", "CalendarLtr24",
        "Rocket24", "Flash24", "LeafOne24", "Lightbulb24",
        "Beaker24", "HatGraduation24", "Food24", "PuzzlePiece24",
        "Diamond24", "Flag24", "Trophy24",
    ];

    public static IReadOnlyList<string> Colors { get; } =
    [
        "#6366F1", "#8B5CF6", "#EC4899", "#EF4444", "#F97316", "#F59E0B",
        "#10B981", "#14B8A6", "#0EA5E9", "#3B82F6", "#64748B", "#A16207",
    ];

    public static bool IsColor(string? hex) =>
        hex is { Length: 7 } && hex[0] == '#' && hex.Skip(1).All(Uri.IsHexDigit);

    /// <summary>The first of <paramref name="candidates"/> that's a colour, else null.</summary>
    public static string? FirstColor(params string?[] candidates) => candidates.FirstOrDefault(IsColor);

    /// <summary>A stable colour per name, so an uncoloured list is still scannable.</summary>
    public static string ColorFor(string name)
    {
        var hash = name.ToLowerInvariant().Aggregate(17, (h, c) => unchecked(h * 31 + c));
        return Colors[(hash & 0x7fffffff) % Colors.Count];
    }
}
