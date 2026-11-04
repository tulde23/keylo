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

public sealed partial class AccessKeyViewModel : ObservableObject
{
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _categories = "";
    [ObservableProperty] private string _secrets = "";
    [ObservableProperty] private bool _allowGet;
    [ObservableProperty] private DateTime? _expires;

    /// <summary>The saved key this row edits, or null for a key that is created on Save.</summary>
    public AccessKey? Original { get; private init; }

    public bool IsNew => Original is null;

    public string Details => Original is null
        ? "New — the key is created and shown once when you save"
        : $"id {Original.Id} · created {Original.Created.LocalDateTime:MMM d, yyyy}" +
          (Original.IsExpired(DateTimeOffset.Now) ? " · EXPIRED" : "");

    public static AccessKeyViewModel From(AccessKey key) => new()
    {
        Original = key,
        Name = key.Name,
        Categories = string.Join(", ", key.Categories),
        Secrets = string.Join(", ", key.Secrets),
        AllowGet = key.AllowGet,
        Expires = key.Expires?.LocalDateTime.Date,
    };

    /// <summary>The edited key; new rows get a freshly generated key and its one-time token.</summary>
    public (AccessKey Key, string? Token) ToModel()
    {
        DateTimeOffset? expires = Expires is { } date ? new DateTimeOffset(date.Date.AddDays(1).AddTicks(-1)) : null;
        var (key, token) = Original is null
            ? AccessKeys.Create(Name, expires)
            : (new AccessKey { Id = Original.Id, Hash = Original.Hash, Created = Original.Created }, (string?)null);

        key.Name = Name.Trim();
        key.Categories = Split(Categories);
        key.Secrets = Split(Secrets);
        key.AllowGet = AllowGet;
        key.Expires = expires;
        return (key, token);
    }

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

public sealed record AuditEntry(string Time, string Operation, string Secrets, string Key, string Via);

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
        SecretTypes = new SecretTypesViewModel(keylo, notify);
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
    public ObservableCollection<AccessKeyViewModel> AccessKeys { get; } = [];
    public SecretTypesViewModel SecretTypes { get; }
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

        AccessKeys.Clear();
        foreach (var key in config.AccessKeys) AccessKeys.Add(AccessKeyViewModel.From(key));

        Providers.Clear();
        foreach (var provider in _keylo.Providers.All)
            Providers.Add(new ProviderSettingsViewModel(provider, config.Providers.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>()));

        SecretTypes.Load();
        LoadAudit();
    }

    [RelayCommand]
    private void AddAccessKey() =>
        AccessKeys.Add(new AccessKeyViewModel { Name = AccessKeys.Count == 0 ? "Claude Code" : $"Key {AccessKeys.Count + 1}" });

    /// <summary>Removing a row revokes the key when you save.</summary>
    [RelayCommand]
    private void RemoveAccessKey(AccessKeyViewModel? key)
    {
        if (key is not null) AccessKeys.Remove(key);
    }

    [RelayCommand]
    private async Task Save()
    {
        if (AccessKeys.Any(k => k.Name.Trim().Length == 0))
        {
            _notify.Error("Every access key needs a name.");
            return;
        }
        if (AccessKeys.GroupBy(k => k.Name.Trim(), StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1) is { } duplicate)
        {
            _notify.Error($"Two access keys are called '{duplicate.Key}'. Give each a different name.");
            return;
        }

        var keys = AccessKeys.Select(k => k.ToModel()).ToList();

        var updated = new KeyloConfig
        {
            Hello = Hello,
            SessionMinutes = (int)SessionMinutes,
            ClipboardSeconds = (int)ClipboardSeconds,
            AccessKeys = keys.Select(k => k.Key).ToList(),
            Providers = Providers.ToDictionary(p => p.Id, p => p.ToSettings(), StringComparer.OrdinalIgnoreCase),
        };

        IsBusy = true;
        try
        {
            await _keylo.SaveConfigAsync(updated);
            _notify.Success("Settings saved.");
            Revert();

            // Each new key's token exists only now; show it once.
            foreach (var (key, token) in keys.Where(k => k.Token is not null))
                await _notify.ShowAccessKeyAsync(key.Name, token!);
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
                    Text(root, "key") ?? Text(root, "group") ?? "",
                    Text(root, "via") ?? Text(root, "caller") ?? ""));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                // Skip lines that aren't valid entries rather than hiding the whole log.
            }
        }
    }

    private static string? Text(JsonElement entry, string property) =>
        entry.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
