using Avalonia;
using Avalonia.Controls;
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
#if !WINDOWS
            if (VaultToUnlock() is { } vault)
            {
                // Linux without a keyring: the vault's passphrase first, then the main window.
                desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                AskForPassphrase(desktop, vault, null);
                base.OnFrameworkInitializationCompleted();
                return;
            }
#endif
            Start(desktop);
        }
        base.OnFrameworkInitializationCompleted();
    }

    private void Start(IClassicDesktopStyleApplicationLifetime desktop)
    {
        _keylo = new KeyloService();
        desktop.MainWindow = new MainWindow(_keylo, desktop.Args ?? []);
        desktop.ShutdownRequested += (_, _) => _keylo.Dispose();
    }

#if !WINDOWS
    /// <summary>The Linux vault, when that's the store and it can't be unlocked without asking.</summary>
    private static Keylo.Platform.Linux.FileVault? VaultToUnlock()
    {
        if (!OperatingSystem.IsLinux()) return null;
        try
        {
            return Keylo.Platform.Linux.LinuxPlatform.Current?.Vault is { } vault && !vault.TryUnlockQuietly() ? vault : null;
        }
        catch (Keylo.Core.KeyloException)
        {
            return null; // the main window shows the problem
        }
    }

    private void AskForPassphrase(IClassicDesktopStyleApplicationLifetime desktop, Keylo.Platform.Linux.FileVault vault, string? error)
    {
        var isNew = !vault.Exists;
        var dialog = new Views.PasswordDialog(
            isNew ? "Create Keylo's vault" : "Unlock Keylo",
            isNew
                ? "There's no desktop keyring here, so Keylo keeps your secrets in an encrypted vault. Choose its passphrase: without it the vault can't be opened."
                : "Enter the passphrase of Keylo's vault.",
            isNew ? "Create" : "Unlock", isNew, error)
        {
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ShowInTaskbar = true,
            Title = "Keylo",
        };
        dialog.Closed += (_, _) =>
        {
            if (dialog.Result is not { } passphrase)
            {
                desktop.Shutdown();
                return;
            }
            try
            {
                if (isNew) vault.Create(passphrase);
                else vault.Unlock(passphrase);
            }
            catch (Keylo.Core.KeyloException ex)
            {
                AskForPassphrase(desktop, vault, ex.Message);
                return;
            }
            Start(desktop);
            desktop.MainWindow!.Show();
            desktop.ShutdownMode = ShutdownMode.OnMainWindowClose;
        };
        dialog.Show();
    }
#endif
}
