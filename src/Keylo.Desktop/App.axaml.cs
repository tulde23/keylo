using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Keylo.App.Services;

namespace Keylo.Desktop;

public partial class App : Application
{
    private KeyloService? _keylo;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var state = UiState.Load();
            Ui.Host.ApplyTheme(Themes.ParseName(state.Theme), Themes.ParseMode(state.Mode));
            _keylo = new KeyloService();
            desktop.MainWindow = new MainWindow(_keylo, desktop.Args ?? []);
            desktop.ShutdownRequested += (_, _) => _keylo.Dispose();
        }
        base.OnFrameworkInitializationCompleted();
    }
}
