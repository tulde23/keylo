using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Keylo.App.Services;
using ThemeMode = Keylo.App.Services.ThemeMode;
using Microsoft.Win32;

namespace Keylo.App;

/// <summary>The shared view models' <see cref="IUiHost"/> for WPF: WPF-UI symbols, WPF brushes, Win32 dialogs.</summary>
public sealed class WpfUiHost : IUiHost
{
    public WpfUiHost() => SystemEvents.SessionSwitch += OnSessionSwitch;

    public object? Symbol(string? name, string? fallback)
    {
        var symbol = IconCatalog.ToSymbol(name, IconCatalog.ToSymbol(fallback, Wpf.Ui.Controls.SymbolRegular.Empty));
        return symbol == Wpf.Ui.Controls.SymbolRegular.Empty ? null : symbol;
    }

    public object? Image(string? icon) => IconImages.Load(icon);

    public object Tile(string hex) => IconCatalog.Tile(IconCatalog.ToColor(hex) ?? Colors.SlateGray);

    public object? Solid(string? hex)
    {
        if (IconCatalog.ToColor(hex) is not { } color) return null;
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }

    public object Transparent => Brushes.Transparent;

    public IUiTimer CreateTimer(TimeSpan interval, Action tick) => new Timer(interval, tick);

    public void Post(Action action) => Application.Current?.Dispatcher.BeginInvoke(action);

    public event EventHandler? SessionLocked;

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            SessionLocked?.Invoke(this, EventArgs.Empty);
    }

    public Task<IReadOnlyList<string>> PickFilesAsync(string title, bool multiple, FileFilter? filter = null)
    {
        var dialog = new OpenFileDialog { Title = title, Multiselect = multiple, Filter = Filter(filter, allFiles: true) };
        return Task.FromResult<IReadOnlyList<string>>(dialog.ShowDialog() == true ? dialog.FileNames : []);
    }

    public Task<string?> PickFolderAsync(string title)
    {
        var dialog = new OpenFolderDialog { Title = title };
        return Task.FromResult(dialog.ShowDialog() == true ? dialog.FolderName : null);
    }

    public Task<string?> PickSaveFileAsync(string title, string fileName, FileFilter? filter = null)
    {
        var dialog = new SaveFileDialog { Title = title, FileName = fileName, Filter = Filter(filter, allFiles: false) };
        if (filter is { Extensions: [var ext, ..] }) dialog.DefaultExt = ext;
        return Task.FromResult(dialog.ShowDialog() == true ? dialog.FileName : null);
    }

    public void OpenTextFile(string path) =>
        Process.Start(new ProcessStartInfo("notepad.exe", $"\"{path}\"") { UseShellExecute = false })?.Dispose();

    public void ApplyTheme(ThemeName name, ThemeMode mode) => WpfTheme.Apply(name, mode);

    public void Open(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or System.IO.FileNotFoundException)
        {
            // Nothing useful to do; the path is shown next to the button.
        }
    }

    /// <summary>"Keylo backup|*.keylo-backup" (plus "All files" for opening); null shows everything.</summary>
    private static string? Filter(FileFilter? filter, bool allFiles) =>
        filter is null ? null
        : $"{filter.Name}|{string.Join(";", filter.Extensions.Select(e => "*" + e))}" + (allFiles ? "|All files|*.*" : "");

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
