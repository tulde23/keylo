using System.Windows.Media;
using Wpf.Ui.Controls;

namespace Keylo.App;

/// <summary>The icons and colours offered for secrets and categories.</summary>
public static class IconCatalog
{
    /// <summary>
    /// Checked against WPF-UI's SymbolRegular (an unknown name crashes XAML at runtime) and by eye:
    /// a few names, e.g. KeyMultiple and Calendar, map to the wrong glyph in the bundled font.
    /// </summary>
    public static IReadOnlyList<SymbolRegular> Icons { get; } =
    [
        SymbolRegular.Key24, SymbolRegular.LockClosed24, SymbolRegular.Shield24,
        SymbolRegular.ShieldKeyhole24, SymbolRegular.Fingerprint24, SymbolRegular.Password24, SymbolRegular.Certificate24,
        SymbolRegular.Cloud24, SymbolRegular.Server24, SymbolRegular.Database24, SymbolRegular.Storage24,
        SymbolRegular.Globe24, SymbolRegular.Router24, SymbolRegular.Wifi124, SymbolRegular.PlugConnected24,
        SymbolRegular.Code24, SymbolRegular.WindowConsole20, SymbolRegular.Branch24, SymbolRegular.Bug24,
        SymbolRegular.Bot24, SymbolRegular.Cube24, SymbolRegular.Box24, SymbolRegular.Apps24,
        SymbolRegular.Desktop24, SymbolRegular.Laptop24, SymbolRegular.Phone24, SymbolRegular.Link24,
        SymbolRegular.Mail24, SymbolRegular.Chat24, SymbolRegular.Person24, SymbolRegular.People24,
        SymbolRegular.Organization24, SymbolRegular.Building24, SymbolRegular.Briefcase24, SymbolRegular.BuildingBank24,
        SymbolRegular.Payment24, SymbolRegular.Wallet24, SymbolRegular.Money24, SymbolRegular.Cart24,
        SymbolRegular.DataBarVertical24, SymbolRegular.Document24, SymbolRegular.Archive24, SymbolRegular.Book24,
        SymbolRegular.Folder24, SymbolRegular.Tag24, SymbolRegular.Settings24, SymbolRegular.Wrench24,
        SymbolRegular.Home24, SymbolRegular.Heart24, SymbolRegular.Star24, SymbolRegular.Gift24,
        SymbolRegular.Games24, SymbolRegular.MusicNote124, SymbolRegular.Video24, SymbolRegular.Camera24,
        SymbolRegular.Airplane24, SymbolRegular.VehicleCar24, SymbolRegular.Map24, SymbolRegular.CalendarLtr24,
        SymbolRegular.Rocket24, SymbolRegular.Flash24, SymbolRegular.LeafOne24, SymbolRegular.Lightbulb24,
        SymbolRegular.Beaker24, SymbolRegular.HatGraduation24, SymbolRegular.Food24, SymbolRegular.PuzzlePiece24,
        SymbolRegular.Diamond24, SymbolRegular.Flag24, SymbolRegular.Trophy24,
    ];

    public static IReadOnlyList<string> Colors { get; } =
    [
        "#6366F1", "#8B5CF6", "#EC4899", "#EF4444", "#F97316", "#F59E0B",
        "#10B981", "#14B8A6", "#0EA5E9", "#3B82F6", "#64748B", "#A16207",
    ];

    public static SymbolRegular ToSymbol(string? name, SymbolRegular fallback) =>
        name is not null && Enum.TryParse<SymbolRegular>(name, out var symbol) && Enum.IsDefined(symbol) ? symbol : fallback;

    public static Color? ToColor(string? hex)
    {
        if (hex is not { Length: 7 } || hex[0] != '#') return null;
        try
        {
            return (Color)ColorConverter.ConvertFromString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>A soft diagonal gradient from one colour, used for avatar tiles.</summary>
    public static Brush Tile(Color color)
    {
        var brush = new LinearGradientBrush(color, Color.Multiply(color, 0.72f), 45);
        brush.Freeze();
        return brush;
    }
}
