using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using Keylo.App.Services;

namespace Keylo.App;

public partial class App : Application
{
    private Mutex? _singleInstance;
    private KeyloService? _keylo;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // One window per user and data folder: a second launch (e.g. typing "keylo" again) focuses the
        // first. Keyed by data folder so a copy pointed at a scratch KEYLO_HOME doesn't collide.
        var dataKey = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(Core.KeyloPaths.DefaultDataDirectory.ToLowerInvariant())))[..16];
        _singleInstance = new Mutex(initiallyOwned: true, $"Keylo.App.{Environment.UserName}.{dataKey}", out var isFirst);
        if (!isFirst)
        {
            FocusExistingInstance();
            Shutdown();
            return;
        }

        // "keylow --import PATH..." or paths dropped onto the exe/shortcut open the import dialog after unlocking.
        var importPaths = e.Args.Where(a => !a.Equals("--import", StringComparison.OrdinalIgnoreCase)).ToList();

        _keylo = new KeyloService();
        MainWindow = new MainWindow(_keylo, importPaths);
        MainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _keylo?.Dispose();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }

    private static void FocusExistingInstance()
    {
        var current = Process.GetCurrentProcess();
        var other = Process.GetProcessesByName(current.ProcessName).FirstOrDefault(p => p.Id != current.Id && p.MainWindowHandle != IntPtr.Zero);
        if (other is null) return;

        ShowWindow(other.MainWindowHandle, SW_RESTORE);
        SetForegroundWindow(other.MainWindowHandle);
    }

    private const int SW_RESTORE = 9;

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
