using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.App.ViewModels;

/// <summary>Settings → About: version, folders, and whether Claude Code is set up to use Keylo.</summary>
public sealed partial class AboutViewModel(KeyloService keylo) : ObservableObject
{
    public const string RepositoryUrl = "https://github.com/tulde23/keylo";

    public string Version { get; } = KeyloVersion.Of(typeof(App).Assembly).ToString();
    public string InstallFolder { get; } = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
    public string DataFolder => KeyloPaths.DefaultDataDirectory;

    [ObservableProperty] private string _claudeStatus = "";
    [ObservableProperty] private string _claudeDetail = "";
    [ObservableProperty] private bool _claudeOk;

    [RelayCommand]
    public void Refresh()
    {
        var keyloExe = Path.Combine(AppContext.BaseDirectory, "keylo.exe");
        var r = ClaudeCode.Inspect(keylo.Config, keyloExe);
        var elsewhere = r.Registered && !r.PointsAt ? $" It runs {r.Command}, not this install." : "";

        (ClaudeOk, ClaudeStatus, ClaudeDetail) = r switch
        {
            { Registered: false } => (false, "Not set up",
                "Claude Code has no Keylo server. Create an access key (New key above) and choose Add to Claude Code."),
            { Key: { } key } => (r.PointsAt, r.PointsAt ? "Connected" : "Registered elsewhere",
                $"Claude Code's Keylo server uses the access key '{key.Name}' ({Describe(key)}).{elsewhere}"),
            { HasToken: true } => (false, "Key not valid",
                $"Claude Code's Keylo server has an access key Keylo doesn't recognise: it was revoked, expired or replaced. Create a new key and choose Add to Claude Code.{elsewhere}"),
            _ => (false, "No access key",
                $"Claude Code's Keylo server has no access key, so every request is refused. Create a key and choose Add to Claude Code.{elsewhere}"),
        };
    }

    private static string Describe(Keylo.Core.Security.AccessKey key) =>
        (key.Scope == Keylo.Core.Security.KeyScope.All ? "everything"
            : key.Categories.Count > 0 ? string.Join(", ", key.Categories)
            : "asks each time") + (key.AllowGet ? ", can read values" : ", run only");

    [RelayCommand] private void OpenInstallFolder() => Open(InstallFolder);
    [RelayCommand] private void OpenDataFolder() => Open(DataFolder);
    [RelayCommand] private void OpenRepository() => Open(RepositoryUrl);
    [RelayCommand] private void OpenReadme() => Open(RepositoryUrl + "#readme");

    private static void Open(string target)
    {
        try
        {
            Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or FileNotFoundException)
        {
            // Nothing useful to do; the path is shown next to the button.
        }
    }
}
