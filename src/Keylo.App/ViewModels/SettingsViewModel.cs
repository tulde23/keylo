using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;
using Keylo.Core.Providers;
using Keylo.Core.Security;

namespace Keylo.App.ViewModels;

public sealed partial class TrustGroupViewModel : ObservableObject
{
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _callers = "";
    [ObservableProperty] private string _categories = "";
    [ObservableProperty] private string _secrets = "";
    [ObservableProperty] private bool _allowGet;

    public static TrustGroupViewModel From(TrustGroup group) => new()
    {
        Name = group.Name,
        Callers = string.Join(", ", group.Callers),
        Categories = string.Join(", ", group.Categories),
        Secrets = string.Join(", ", group.Secrets),
        AllowGet = group.AllowGet,
    };

    public TrustGroup ToModel() => new()
    {
        Name = Name.Trim(),
        Callers = Split(Callers),
        Categories = Split(Categories),
        Secrets = Split(Secrets),
        AllowGet = AllowGet,
    };

    private static List<string> Split(string value) =>
        value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}

public sealed partial class ProviderSettingViewModel(string key, string description, string value) : ObservableObject
{
    public string Key { get; } = key;
    public string Description { get; } = description;
    [ObservableProperty] private string _value = value;
}

public sealed partial class ProviderSettingsViewModel : ObservableObject
{
    private readonly IVaultProvider _provider;

    [ObservableProperty] private string _status = "Not checked";
    [ObservableProperty] private bool _isReady;

    public ProviderSettingsViewModel(IVaultProvider provider, IReadOnlyDictionary<string, string> settings)
    {
        _provider = provider;
        Settings = new ObservableCollection<ProviderSettingViewModel>(provider.SettingDescriptions.Select(d =>
            new ProviderSettingViewModel(d.Key, d.Value, settings.GetValueOrDefault(d.Key) ?? "")));
    }

    public string Id => _provider.Id;
    public string DisplayName => _provider.DisplayName;
    public ObservableCollection<ProviderSettingViewModel> Settings { get; }

    public Dictionary<string, string> ToSettings() =>
        Settings.Where(s => !string.IsNullOrWhiteSpace(s.Value))
            .ToDictionary(s => s.Key, s => s.Value.Trim(), StringComparer.OrdinalIgnoreCase);

    [RelayCommand]
    private async Task Test()
    {
        Status = "Checking…";
        var status = await _provider.GetStatusAsync(ToSettings());
        IsReady = status.Ready;
        Status = status.Message;
    }
}

public sealed record AuditEntry(string Time, string Operation, string Secrets, string Caller, string Group);

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;

    [ObservableProperty] private HelloMode _hello;
    [ObservableProperty] private double _sessionMinutes;
    [ObservableProperty] private double _clipboardSeconds;
    [ObservableProperty] private bool _isBusy;

    private readonly Action _restored;

    public SettingsViewModel(KeyloService keylo, IUserNotifier notify, Action restored)
    {
        _keylo = keylo;
        _notify = notify;
        _restored = restored;
        Revert();
    }

    [ObservableProperty] private string _backupStatus = "";

    [RelayCommand]
    private async Task Backup()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save encrypted backup",
            FileName = $"keylo-backup-{DateTime.Now:yyyy-MM-dd}{KeyloBackup.FileExtension}",
            Filter = $"Keylo backup|*{KeyloBackup.FileExtension}",
            DefaultExt = KeyloBackup.FileExtension,
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            // Exports every value, so it always verifies — no session shortcut.
            await _keylo.ConfirmAsync("back up all secrets");

            var password = _notify.AskPassword("Protect the backup",
                "Choose a password for this backup. Store it somewhere other than Keylo — without it the backup can't be opened, by anyone.",
                "Create backup", isNew: true);
            if (password is null) return;

            IsBusy = true;
            BackupStatus = "Encrypting…";
            var summary = await Task.Run(() => KeyloBackup.Create(_keylo.Store, _keylo.Categories, dialog.FileName, password));
            BackupStatus = $"Last backup: {summary.Secrets} secrets to {summary.Path}";
            _notify.Success($"Backed up {summary.Secrets} secrets, {summary.Categories} categories and {summary.Icons} icons.");
        }
        catch (Exception ex) when (ex is KeyloException or IOException or UnauthorizedAccessException)
        {
            BackupStatus = "";
            _notify.Error(ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task Restore()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Restore from backup",
            Filter = $"Keylo backup|*{KeyloBackup.FileExtension}|All files|*.*",
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            await _keylo.EnsureBrowseAsync();

            // Ask until the password is right or the user gives up.
            BackupContents? contents = null;
            string? error = null;
            while (contents is null)
            {
                var password = _notify.AskPassword("Open backup", $"Enter the password for {Path.GetFileName(dialog.FileName)}.", "Open", isNew: false, error);
                if (password is null) return;

                IsBusy = true;
                BackupStatus = "Decrypting…";
                try
                {
                    contents = await Task.Run(() => KeyloBackup.Read(dialog.FileName, password));
                }
                catch (BackupPasswordException ex)
                {
                    error = ex.Message;
                }
                finally
                {
                    IsBusy = false;
                    BackupStatus = "";
                }
            }

            var existing = contents.Secrets.Count(s => _keylo.Store.Exists(s.Name));
            var summary = $"Backup from {contents.CreatedAt.LocalDateTime:MMM d, yyyy h:mm tt}: {contents.Secrets.Count} secrets, " +
                          $"{contents.Categories.Count} categories, {contents.Icons.Count} icons.";
            bool? choice = existing == 0
                ? await _notify.ChooseAsync("Restore backup", summary, "Restore", null)
                : await _notify.ChooseAsync("Restore backup",
                    $"{summary}\n\n{existing} of these secrets already exist here. Keep the ones here, or replace them with the backup's?",
                    "Keep existing", "Replace existing");
            if (choice is null) return;

            IsBusy = true;
            var result = await Task.Run(() => KeyloBackup.Restore(_keylo.Store, _keylo.Categories, contents, overwrite: choice == false));
            _restored();

            var message = $"Restored {result.Added} new" + (result.Replaced > 0 ? $", replaced {result.Replaced}" : "") +
                          (result.Skipped > 0 ? $", kept {result.Skipped} existing" : "") + ".";
            if (result.Errors.Count > 0) _notify.Info($"{message} {result.Errors.Count} failed: {string.Join("; ", result.Errors.Take(3))}");
            else _notify.Success(message);
        }
        catch (Exception ex) when (ex is KeyloException or IOException or UnauthorizedAccessException)
        {
            _notify.Error(ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public IReadOnlyList<HelloMode> HelloModes { get; } = Enum.GetValues<HelloMode>();
    public ObservableCollection<TrustGroupViewModel> TrustGroups { get; } = [];
    public ObservableCollection<ProviderSettingsViewModel> Providers { get; } = [];
    public ObservableCollection<AuditEntry> Audit { get; } = [];
    public string DataDirectory => KeyloPaths.DefaultDataDirectory;
    public string PluginDirectory => Path.Combine(KeyloPaths.DefaultDataDirectory, "plugins");

    [RelayCommand]
    public void Revert()
    {
        var config = _keylo.Config;
        Hello = config.Hello;
        SessionMinutes = config.SessionMinutes;
        ClipboardSeconds = config.ClipboardSeconds;

        TrustGroups.Clear();
        foreach (var group in config.TrustGroups) TrustGroups.Add(TrustGroupViewModel.From(group));

        Providers.Clear();
        foreach (var provider in _keylo.Providers.All)
            Providers.Add(new ProviderSettingsViewModel(provider, config.Providers.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>()));

        LoadAudit();
    }

    [RelayCommand]
    private void AddTrustGroup() =>
        TrustGroups.Add(new TrustGroupViewModel { Name = $"Group {TrustGroups.Count + 1}", Callers = "claude.exe" });

    [RelayCommand]
    private void RemoveTrustGroup(TrustGroupViewModel? group)
    {
        if (group is not null) TrustGroups.Remove(group);
    }

    [RelayCommand]
    private async Task Save()
    {
        var groups = TrustGroups.Select(g => g.ToModel()).ToList();
        if (groups.FirstOrDefault(g => g.Name.Length == 0 || g.Callers.Count == 0 || g.Categories.Count + g.Secrets.Count == 0) is { } invalid)
        {
            _notify.Error($"Trust group '{(invalid.Name.Length == 0 ? "(unnamed)" : invalid.Name)}' needs a name, at least one caller, and a category or secret.");
            return;
        }

        var updated = new KeyloConfig
        {
            Hello = Hello,
            SessionMinutes = (int)SessionMinutes,
            ClipboardSeconds = (int)ClipboardSeconds,
            TrustGroups = groups,
            Providers = Providers.ToDictionary(p => p.Id, p => p.ToSettings(), StringComparer.OrdinalIgnoreCase),
        };

        IsBusy = true;
        try
        {
            await _keylo.SaveConfigAsync(updated);
            _notify.Success("Settings saved.");
            Revert();
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void LoadAudit()
    {
        Audit.Clear();
        var path = AuditLog.PathIn(KeyloPaths.DefaultDataDirectory);
        if (!File.Exists(path)) return;

        foreach (var line in File.ReadLines(path).Reverse().Take(100))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                Audit.Add(new AuditEntry(
                    root.GetProperty("time").GetDateTimeOffset().LocalDateTime.ToString("MMM d  h:mm:ss tt"),
                    root.GetProperty("operation").GetString() ?? "",
                    string.Join(", ", root.GetProperty("secrets").EnumerateArray().Select(s => s.GetString())),
                    root.GetProperty("caller").GetString() ?? "",
                    root.GetProperty("group").GetString() ?? ""));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                // Skip lines that aren't valid entries rather than hiding the whole log.
            }
        }
    }
}
