using Avalonia;
using Keylo.App.Services;

namespace Keylo.Desktop;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // Keylo.app/Contents/MacOS/keylo runs "KeyloApp --cli ARGS": the CLI and MCP server share the
        // app's executable, so the keychain trusts one app for both.
        if (args is ["--cli", .. var cli]) return Keylo.Cli.Program.Main(cli).GetAwaiter().GetResult();

#if WINDOWS
        Keylo.Platform.Windows.WindowsPlatform.Install();
#else
        Keylo.Platform.MacOS.MacPlatform.Install();
#endif
        Ui.Install(new AvaloniaUiHost());
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    // Also used by the XAML previewer.
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new MacOSPlatformOptions { ShowInDock = true })
            .LogToTrace();
}
