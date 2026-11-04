using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Keylo.Core;

namespace Keylo.Desktop.Views;

/// <summary>Small converters for bindings Avalonia can't express directly.</summary>
public static class Convert
{
    public static readonly IValueConverter IsZero = new FuncValueConverter<int, bool>(n => n == 0);
    public static readonly IValueConverter IsPositive = new FuncValueConverter<int, bool>(n => n > 0);

    /// <summary>Taller boxes for multi-line fields (SSH keys, certificates).</summary>
    public static readonly IValueConverter MultilineHeight = new FuncValueConverter<bool, double>(multiline => multiline ? 88 : 0);

    public static readonly IValueConverter PinMenuText = new FuncValueConverter<bool, string>(pinned => pinned ? "Unpin from Home" : "Pin to Home");

    /// <summary>"#RRGGBB" → a brush (colour swatches).</summary>
    public static readonly IValueConverter ToBrush = new FuncValueConverter<string?, IBrush?>(hex =>
        hex is not null && Color.TryParse(hex, out var c) ? new ImmutableSolidColorBrush(c) : null);

    /// <summary>A category's colour, else the theme's secondary text colour.</summary>
    public static readonly IValueConverter BrushOrSecondary = new FuncValueConverter<object?, IBrush?>(value =>
        value as IBrush ?? Resource("TextSecondary") as IBrush);

    public static readonly IValueConverter HelloModeText = new FuncValueConverter<HelloMode, string>(mode => mode switch
    {
        HelloMode.Session => "Once per session",
        HelloMode.Always => "Every time a value is revealed or used",
        HelloMode.Never => OperatingSystem.IsMacOS() ? "Never (Mac login only)" : "Never (Windows sign-in only)",
        _ => mode.ToString(),
    });

    public static object? Resource(string key) =>
        Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out var value) ? value : null;
}
