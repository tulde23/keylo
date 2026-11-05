namespace Keylo.App.Services;

/// <summary>Keylo's colour themes, each drawn from the logo's violets.</summary>
public enum ThemeName { Twilight, QuietViolet, Aurora }

/// <summary>Light or dark, or whichever the system uses.</summary>
public enum ThemeMode { System, Light, Dark }

public sealed record ThemeOption(ThemeName Value, string Label, string Description);

public sealed record ThemeModeOption(ThemeMode Value, string Label);

/// <summary>
/// One theme in one mode, as "#RRGGBB" colours by role. Each app maps the roles onto its own
/// resources (AvaloniaUiHost, WpfTheme). Status colours (caution, success…) stay the toolkit's.
/// </summary>
public sealed record ThemeColors(
    string Base, string TopBar, string Layer, string Card, string Stroke,
    string ControlFill, string ControlFill2, string ControlStroke,
    string Hover, string Pressed, string Selected, string Divider, string Popup,
    string Text, string Text2, string Text3, string Section,
    string Accent, string AccentEnd, string OnAccent, string AccentText, string Info);

public static class Themes
{
    public const ThemeName DefaultTheme = ThemeName.Twilight;

    public static IReadOnlyList<ThemeOption> Options { get; } =
    [
        new(ThemeName.Twilight, "Twilight", "Violet-tinted surfaces and the logo's gradient. The default."),
        new(ThemeName.QuietViolet, "Quiet violet", "Near-neutral greys; violet only where it matters."),
        new(ThemeName.Aurora, "Aurora", "Neutral surfaces with orchid and violet accents."),
    ];

    public static IReadOnlyList<ThemeModeOption> ModeOptions { get; } =
    [
        new(ThemeMode.System, "Match system"),
        new(ThemeMode.Light, "Light"),
        new(ThemeMode.Dark, "Dark"),
    ];

    public static ThemeName ParseName(string? value) => Enum.TryParse<ThemeName>(value, true, out var name) ? name : DefaultTheme;

    public static ThemeMode ParseMode(string? value) => Enum.TryParse<ThemeMode>(value, true, out var mode) ? mode : ThemeMode.System;

    public static ThemeColors Get(ThemeName name, bool dark) => (name, dark) switch
    {
        (ThemeName.QuietViolet, true) => new(
            Base: "#1B1A21", TopBar: "#222029", Layer: "#1F1D26", Card: "#26242E", Stroke: "#34313E",
            ControlFill: "#2A2833", ControlFill2: "#32303C", ControlStroke: "#3A3746",
            Hover: "#2A2834", Pressed: "#24222D", Selected: "#2E2A3D", Divider: "#34313E", Popup: "#2A2832",
            Text: "#F4F2FA", Text2: "#B8B3C6", Text3: "#8C869B", Section: "#8C869B",
            Accent: "#A78BFA", AccentEnd: "#A78BFA", OnAccent: "#1C1033", AccentText: "#C4B5FD", Info: "#2A2540"),
        (ThemeName.QuietViolet, false) => new(
            Base: "#F5F4F8", TopBar: "#FFFFFF", Layer: "#FAF9FC", Card: "#FFFFFF", Stroke: "#E5E2EC",
            ControlFill: "#FFFFFF", ControlFill2: "#F1EFF5", ControlStroke: "#DCD8E4",
            Hover: "#EFEDF4", Pressed: "#E8E5EF", Selected: "#ECE6FB", Divider: "#E5E2EC", Popup: "#FFFFFF",
            Text: "#1C1A22", Text2: "#575262", Text3: "#6E6879", Section: "#6E6879",
            Accent: "#6D28D9", AccentEnd: "#6D28D9", OnAccent: "#FFFFFF", AccentText: "#6D28D9", Info: "#F1ECFD"),

        (ThemeName.Aurora, true) => new(
            Base: "#18171C", TopBar: "#1F1E24", Layer: "#1C1B21", Card: "#24232A", Stroke: "#34323B",
            ControlFill: "#28272E", ControlFill2: "#302F37", ControlStroke: "#3A3842",
            Hover: "#26252C", Pressed: "#212026", Selected: "#2C2238", Divider: "#34323B", Popup: "#26252C",
            Text: "#F5F4F7", Text2: "#B7B5BF", Text3: "#8B8894", Section: "#C4B5FD",
            Accent: "#C084FC", AccentEnd: "#C084FC", OnAccent: "#2A0A3D", AccentText: "#D8B4FE", Info: "#2A2236"),
        (ThemeName.Aurora, false) => new(
            Base: "#FAF9FB", TopBar: "#FFFFFF", Layer: "#FFFFFF", Card: "#FFFFFF", Stroke: "#E7E5EC",
            ControlFill: "#FFFFFF", ControlFill2: "#F2F1F5", ControlStroke: "#DEDBE5",
            Hover: "#F2F1F5", Pressed: "#EBE9EF", Selected: "#F3E8FF", Divider: "#E7E5EC", Popup: "#FFFFFF",
            Text: "#1B1A20", Text2: "#55525E", Text3: "#6C6977", Section: "#7E22CE",
            Accent: "#9333EA", AccentEnd: "#9333EA", OnAccent: "#FFFFFF", AccentText: "#7E22CE", Info: "#F3E8FF"),

        (_, true) => new( // Twilight
            Base: "#13101B", TopBar: "#1A1526", Layer: "#161220", Card: "#211A30", Stroke: "#31284A",
            ControlFill: "#241C36", ControlFill2: "#2D2442", ControlStroke: "#3A3054",
            Hover: "#231B33", Pressed: "#1E172C", Selected: "#2D2147", Divider: "#2C2442", Popup: "#211A30",
            Text: "#F5F1FF", Text2: "#BCB2D6", Text3: "#9086AB", Section: "#A99BD0",
            Accent: "#9333EA", AccentEnd: "#6D28D9", OnAccent: "#FFFFFF", AccentText: "#C4B5FD", Info: "#2D2147"),
        (_, false) => new(
            Base: "#F6F2FD", TopBar: "#FFFFFF", Layer: "#FBF9FE", Card: "#FFFFFF", Stroke: "#E2D8F4",
            ControlFill: "#FFFFFF", ControlFill2: "#F1EBFC", ControlStroke: "#D9CCF0",
            Hover: "#EEE6FB", Pressed: "#E6DCF8", Selected: "#E2D3FA", Divider: "#E2D8F4", Popup: "#FFFFFF",
            Text: "#1E1630", Text2: "#574A73", Text3: "#6B5F86", Section: "#6D28D9",
            Accent: "#9333EA", AccentEnd: "#5B21B6", OnAccent: "#FFFFFF", AccentText: "#6D28D9", Info: "#EDE5FA"),
    };
}
