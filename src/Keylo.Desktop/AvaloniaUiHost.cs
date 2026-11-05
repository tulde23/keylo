using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media;
using Avalonia.Media.Immutable;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using Avalonia.Threading;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.Desktop;

/// <summary>The shared view models' <see cref="IUiHost"/> for Avalonia: FluentIcons symbols, Avalonia brushes, storage pickers.</summary>
public sealed class AvaloniaUiHost : IUiHost
{
    private readonly Dictionary<string, IImage?> _images = new(StringComparer.OrdinalIgnoreCase);
#if !WINDOWS
    private DispatcherTimer? _lockWatch;
    private bool _wasLocked;
#endif

    public object? Symbol(string? name, string? fallback) => Icons.Find(name) ?? Icons.Find(fallback);

    /// <summary>An uploaded icon image ("img" + hash → icons/hash.png), cached.</summary>
    public object? Image(string? icon)
    {
        if (icon is not { Length: 35 } || !icon.StartsWith("img", StringComparison.Ordinal)) return null;
        if (_images.TryGetValue(icon, out var cached)) return cached;

        var path = Path.Combine(KeyloPaths.IconDirectory, icon[3..] + ".png");
        IImage? image = null;
        try
        {
            if (File.Exists(path)) image = new Bitmap(path);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
        {
        }
        return _images[icon] = image;
    }

    public object Tile(string hex)
    {
        var color = Color.TryParse(hex, out var c) ? c : Colors.SlateGray;
        var dark = Color.FromRgb((byte)(color.R * 0.72), (byte)(color.G * 0.72), (byte)(color.B * 0.72));
        return new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
            GradientStops = { new GradientStop(color, 0), new GradientStop(dark, 1) },
        }.ToImmutable();
    }

    public object? Solid(string? hex) => IconPalette.IsColor(hex) && Color.TryParse(hex, out var c) ? new ImmutableSolidColorBrush(c) : null;

    public object Transparent => Brushes.Transparent;

    public IUiTimer CreateTimer(TimeSpan interval, Action tick) => new Timer(interval, tick);

    public void Post(Action action) => Dispatcher.UIThread.Post(action);

    private EventHandler? _sessionLocked;

    /// <summary>On macOS, polled: Keylo locks once the screen does.</summary>
    public event EventHandler? SessionLocked
    {
        add
        {
            _sessionLocked += value;
#if !WINDOWS
            _lockWatch ??= StartLockWatch();
#endif
        }
        remove => _sessionLocked -= value;
    }

#if !WINDOWS
    private DispatcherTimer StartLockWatch()
    {
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        timer.Tick += (_, _) =>
        {
            var locked = Keylo.Platform.MacOS.MacSession.IsScreenLocked();
            if (locked && !_wasLocked) _sessionLocked?.Invoke(this, EventArgs.Empty);
            _wasLocked = locked;
        };
        timer.Start();
        return timer;
    }
#endif

    private static TopLevel? Window =>
        (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Windows.LastOrDefault(w => w.IsActive)
        ?? (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow;

    public async Task<IReadOnlyList<string>> PickFilesAsync(string title, bool multiple, FileFilter? filter = null)
    {
        if (Window?.StorageProvider is not { } storage) return [];
        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = multiple,
            FileTypeFilter = filter is null ? null : [Type(filter), FilePickerFileTypes.All],
        });
        return files.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
    }

    public async Task<string?> PickFolderAsync(string title)
    {
        if (Window?.StorageProvider is not { } storage) return null;
        var folders = await storage.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title });
        return folders.FirstOrDefault()?.TryGetLocalPath();
    }

    public async Task<string?> PickSaveFileAsync(string title, string fileName, FileFilter? filter = null)
    {
        if (Window?.StorageProvider is not { } storage) return null;
        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = fileName,
            DefaultExtension = filter?.Extensions.FirstOrDefault()?.TrimStart('.'),
            FileTypeChoices = filter is null ? null : [Type(filter)],
        });
        return file?.TryGetLocalPath();
    }

    private static FilePickerFileType Type(FileFilter filter) =>
        new(filter.Name) { Patterns = filter.Extensions.Select(e => "*" + e).ToList() };

    /// <summary>
    /// Fills App.axaml's Light and Dark resource dictionaries with the theme's colours (so a system
    /// light/dark switch needs nothing more), sets Fluent's accent, then picks the variant.
    /// </summary>
    public void ApplyTheme(ThemeName name, ThemeMode mode)
    {
        if (Application.Current is not { } app) return;

        foreach (var (variant, dark) in new[] { (ThemeVariant.Light, false), (ThemeVariant.Dark, true) })
        {
            var c = Themes.Get(name, dark);
            if (app.Resources.ThemeDictionaries.TryGetValue(variant, out var provider) && provider is IResourceDictionary d)
            {
                IBrush accent = c.Accent == c.AccentEnd
                    ? Brush(c.Accent)
                    : new LinearGradientBrush
                    {
                        StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                        EndPoint = new RelativePoint(1, 1, RelativeUnit.Relative),
                        GradientStops = { new GradientStop(Color.Parse(c.Accent), 0), new GradientStop(Color.Parse(c.AccentEnd), 1) },
                    };
                var set = new Dictionary<string, object>
                {
                    ["TextPrimary"] = Brush(c.Text), ["TextSecondary"] = Brush(c.Text2), ["TextTertiary"] = Brush(c.Text3),
                    ["SectionText"] = Brush(c.Section),
                    ["BaseFill"] = Brush(c.Base), ["TopBarFill"] = Brush(c.TopBar), ["LayerFill"] = Brush(c.Layer),
                    ["CardFill"] = Brush(c.Card), ["CardStroke"] = Brush(c.Stroke),
                    ["ControlFill"] = Brush(c.ControlFill), ["ControlFill2"] = Brush(c.ControlFill2), ["ControlStroke"] = Brush(c.ControlStroke),
                    ["SubtleHover"] = Brush(c.Hover), ["SubtlePressed"] = Brush(c.Pressed), ["SelectedFill"] = Brush(c.Selected),
                    ["Divider"] = Brush(c.Divider), ["PopupFill"] = Brush(c.Popup),
                    ["AccentFill"] = accent, ["AccentText"] = Brush(c.AccentText), ["OnAccent"] = Brush(c.OnAccent), ["InfoBg"] = Brush(c.Info),
                    // Fluent's accent buttons, with the theme's fill (the gradient, in Twilight) and text.
                    ["AccentButtonBackground"] = accent, ["AccentButtonBackgroundPointerOver"] = accent, ["AccentButtonBackgroundPressed"] = accent,
                    ["AccentButtonForeground"] = Brush(c.OnAccent), ["AccentButtonForegroundPointerOver"] = Brush(c.OnAccent),
                    ["AccentButtonForegroundPressed"] = Brush(c.OnAccent),
                    // Fluent's expander, recoloured to match the cards.
                    ["ExpanderHeaderBackground"] = Brush(c.Card), ["ExpanderHeaderBackgroundPointerOver"] = Brush(c.ControlFill2),
                    ["ExpanderHeaderBackgroundPressed"] = Brush(c.Card), ["ExpanderHeaderBackgroundDisabled"] = Brush(c.Card),
                    ["ExpanderHeaderBorderBrush"] = Brush(c.Stroke), ["ExpanderHeaderBorderBrushPointerOver"] = Brush(c.Stroke),
                    ["ExpanderHeaderBorderBrushPressed"] = Brush(c.Stroke),
                    ["ExpanderContentBackground"] = Brush(c.Card), ["ExpanderContentBorderBrush"] = Brush(c.Stroke),
                };
                foreach (var (key, value) in set) d[key] = value;
            }

            if (app.Styles.OfType<Avalonia.Themes.Fluent.FluentTheme>().FirstOrDefault() is { } fluent
                && fluent.Palettes.TryGetValue(variant, out var palette))
            {
                palette.Accent = Color.Parse(c.Accent);
                palette.RegionColor = Color.Parse(c.Base);
            }
        }

        app.RequestedThemeVariant = mode switch
        {
            ThemeMode.Light => ThemeVariant.Light,
            ThemeMode.Dark => ThemeVariant.Dark,
            _ => ThemeVariant.Default,
        };
    }

    private static ImmutableSolidColorBrush Brush(string hex) => new(Color.Parse(hex));

    public void OpenTextFile(string path)
    {
        if (OperatingSystem.IsMacOS()) Start("/usr/bin/open", "-t", path);
        else if (OperatingSystem.IsWindows()) Start("notepad.exe", path);
        else Open(path);
    }

    public void Open(string target)
    {
        if (OperatingSystem.IsMacOS()) Start("/usr/bin/open", target);
        else if (OperatingSystem.IsWindows())
        {
            try
            {
                Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or FileNotFoundException)
            {
            }
        }
        else Start("xdg-open", target);
    }

    private static void Start(string program, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(program) { UseShellExecute = false };
            foreach (var arg in args) psi.ArgumentList.Add(arg);
            Process.Start(psi)?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or FileNotFoundException)
        {
            // Nothing useful to do; the path is shown next to the button.
        }
    }

    private sealed class Timer : IUiTimer
    {
        private readonly DispatcherTimer _timer;

        public Timer(TimeSpan interval, Action tick)
        {
            _timer = new DispatcherTimer { Interval = interval };
            _timer.Tick += (_, _) => tick();
        }

        public TimeSpan Interval { get => _timer.Interval; set => _timer.Interval = value; }
        public void Start() => _timer.Start();
        public void Stop() => _timer.Stop();
    }
}
