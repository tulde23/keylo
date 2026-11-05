using System.Windows;
using System.Windows.Media;
using Keylo.App.Services;
using ThemeMode = Keylo.App.Services.ThemeMode;
using Microsoft.Win32;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Keylo.App;

/// <summary>
/// Keylo's themes (Keylo.UI's <see cref="Themes"/>) on WPF UI: its light or dark dictionary first,
/// then Keylo's colours over the brushes the app's views and WPF UI's controls draw with.
/// </summary>
internal static class WpfTheme
{
    private static ThemeName _name = Themes.DefaultTheme;
    private static ThemeMode _mode;
    private static bool _watching;

    /// <summary>The theme saved in ui.json (at startup, and for the approval window).</summary>
    public static void ApplySaved()
    {
        var state = UiState.Load();
        Apply(Themes.ParseName(state.Theme), Themes.ParseMode(state.Mode));
    }

    public static void Apply(ThemeName name, ThemeMode mode)
    {
        (_name, _mode) = (name, mode);
        if (!_watching)
        {
            _watching = true;
            // Match system: follow Windows when it switches (the setting arrives as a General change).
            SystemEvents.UserPreferenceChanged += (_, e) =>
            {
                if (_mode == ThemeMode.System && e.Category == UserPreferenceCategory.General)
                    Application.Current?.Dispatcher.BeginInvoke(() => Apply(_name, _mode));
            };
            // WPF UI sets each window's Background itself (from its own palette) as the window
            // appears; point it back at the theme's brush once it has loaded.
            EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent,
                new RoutedEventHandler((sender, _) => Paint((Window)sender)));
        }

        var dark = mode switch { ThemeMode.Dark => true, ThemeMode.Light => false, _ => SystemIsDark() };
        var theme = dark ? ApplicationTheme.Dark : ApplicationTheme.Light;
        var c = Themes.Get(name, dark);

        ApplicationThemeManager.Apply(theme, WindowBackdropType.None, updateAccent: false);
        ApplicationAccentColorManager.Apply(ColorOf(c.Accent), theme);

        Brush accent = c.Accent == c.AccentEnd
            ? Solid(c.Accent)
            : Frozen(new LinearGradientBrush(ColorOf(c.Accent), ColorOf(c.AccentEnd), 45));
        var brushes = new Dictionary<string, Brush>
        {
            ["ApplicationBackgroundBrush"] = Solid(c.Base),
            ["SolidBackgroundFillColorBaseBrush"] = Solid(c.Base),
            ["SolidBackgroundFillColorSecondaryBrush"] = Solid(c.Layer),
            ["SolidBackgroundFillColorTertiaryBrush"] = Solid(c.TopBar),
            ["SolidBackgroundFillColorQuarternaryBrush"] = Solid(c.Popup),
            ["LayerFillColorDefaultBrush"] = Solid(c.Layer),
            ["CardBackgroundFillColorDefaultBrush"] = Solid(c.Card),
            ["CardBackgroundFillColorSecondaryBrush"] = Solid(c.ControlFill2),
            ["CardStrokeColorDefaultBrush"] = Solid(c.Stroke),
            ["ControlFillColorDefaultBrush"] = Solid(c.ControlFill),
            ["ControlFillColorSecondaryBrush"] = Solid(c.ControlFill2),
            ["ControlFillColorTertiaryBrush"] = Solid(c.Pressed),
            ["ControlStrokeColorDefaultBrush"] = Solid(c.ControlStroke),
            ["SubtleFillColorSecondaryBrush"] = Solid(c.Hover),
            ["SubtleFillColorTertiaryBrush"] = Solid(c.Pressed),
            ["DividerStrokeColorDefaultBrush"] = Solid(c.Divider),
            ["TextFillColorPrimaryBrush"] = Solid(c.Text),
            ["TextFillColorSecondaryBrush"] = Solid(c.Text2),
            ["TextFillColorTertiaryBrush"] = Solid(c.Text3),
            ["AccentTextFillColorPrimaryBrush"] = Solid(c.AccentText),
            ["AccentTextFillColorSecondaryBrush"] = Solid(c.AccentText),
            ["AccentTextFillColorTertiaryBrush"] = Solid(c.AccentText),
            ["AccentFillColorDefaultBrush"] = accent,
            ["AccentButtonBackground"] = accent,
            ["AccentButtonBackgroundPointerOver"] = accent,
            ["AccentButtonBackgroundPressed"] = accent,
            ["AccentButtonForeground"] = Solid(c.OnAccent),
            ["AccentButtonForegroundPointerOver"] = Solid(c.OnAccent),
            ["AccentButtonForegroundPressed"] = Solid(c.OnAccent),
            ["TextOnAccentFillColorPrimaryBrush"] = Solid(c.OnAccent),
            // Keylo's own roles (App.xaml has their starting values).
            ["SelectedFillBrush"] = Solid(c.Selected),
            ["SectionTextBrush"] = Solid(c.Section),
            ["InfoFillBrush"] = Solid(c.Info),
        };
        var resources = Application.Current.Resources;
        foreach (var (key, brush) in brushes) resources[key] = brush;
        resources["ApplicationBackgroundColor"] = ColorOf(c.Base);
        foreach (Window window in Application.Current.Windows) Paint(window);
    }

    /// <summary>
    /// The theme's background on a window and its root panel. WPF UI sets each window's own Background
    /// as it appears, so the root panel (which fills the window) carries the colour as well.
    /// </summary>
    private static void Paint(Window window)
    {
        window.SetResourceReference(Window.BackgroundProperty, "ApplicationBackgroundBrush");
        if (window.Content is System.Windows.Controls.Panel { Background: null } root)
            root.SetResourceReference(System.Windows.Controls.Panel.BackgroundProperty, "ApplicationBackgroundBrush");
    }

    /// <summary>Windows' "apps" light/dark setting (Personalization → Colors).</summary>
    private static bool SystemIsDark() =>
        Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "AppsUseLightTheme", 1) is 0;

    private static Color ColorOf(string hex) => (Color)ColorConverter.ConvertFromString(hex);

    private static Brush Solid(string hex) => Frozen(new SolidColorBrush(ColorOf(hex)));

    private static Brush Frozen(Brush brush)
    {
        brush.Freeze();
        return brush;
    }
}
