using System.Windows.Media;
using Wpf.Ui.Controls;

namespace Keylo.App;

/// <summary>The icons and colours offered for secrets and categories.</summary>
public static class IconCatalog
{
    /// <summary><see cref="Services.IconPalette.Icons"/> as WPF-UI symbols (an unknown name would crash XAML at runtime).</summary>
    public static IReadOnlyList<SymbolRegular> Icons { get; } =
        Services.IconPalette.Icons.Select(n => ToSymbol(n, SymbolRegular.Empty)).Where(s => s != SymbolRegular.Empty).ToList();


    public static IReadOnlyList<string> Colors => Services.IconPalette.Colors;

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
