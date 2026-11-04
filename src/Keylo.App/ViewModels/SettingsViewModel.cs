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

public enum ScopeChoice { Everything, Categories, Nothing }

public sealed record ScopeOption(ScopeChoice Value, string Label, string Description);

public sealed partial class AccessKeyViewModel : ObservableObject
{
    public static IReadOnlyList<ScopeOption> ScopeOptions { get; } =
    [
        new(ScopeChoice.Everything, "Everything", "Every secret, no approval windows."),
        new(ScopeChoice.Categories, "Only these categories", "Secrets in the chosen categories; anything else asks you."),
        new(ScopeChoice.Nothing, "Nothing — ask me each time", "Every use opens an approval window. An approval lasts for your Keylo session."),
    ];

    [ObservableProperty] private string _name = "";

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowCategories))]
    private ScopeOption _scope = ScopeOptions[2];

    public bool ShowCategories => Scope.Value == ScopeChoice.Categories;

    /// <summary>Secrets added by "Always allow" in approval windows (they stay covered whatever the scope).</summary>
    public ObservableCollection<string> ApprovedSecrets { get; } = [];

    public bool HasApproved => ApprovedSecrets.Count > 0;

    public string ApprovedText => $"Also allowed (from approvals): {string.Join(", ", ApprovedSecrets)}";

    [RelayCommand]
    private void ClearApproved()
    {
        ApprovedSecrets.Clear();
        OnPropertyChanged(nameof(HasApproved));
    }
    [ObservableProperty] private bool _allowGet;
    [ObservableProperty] private DateTime? _expires;

    /// <summary>The saved key this row edits, or null for a key that is created on Save.</summary>
    public AccessKey? Original { get; private init; }

    public bool IsNew => Original is null;

    /// <summary>Every category, ticked where the key covers it.</summary>
    public ObservableCollection<PickItem> Categories { get; } = [];


    public string Details => Original is null
        ? "New — the key is created and shown once when you save"
        : $"id {Original.Id} · created {Original.Created.LocalDateTime:MMM d, yyyy}" +
          (Original.IsExpired(DateTimeOffset.Now) ? " · EXPIRED" : "");

    /// <summary>
    /// A row for <paramref name="key"/>, offering every existing category and secret. Names the key
    /// covers that no longer exist (deleted or renamed) stay listed, ticked, so saving doesn't drop them silently.
    /// </summary>
    public static AccessKeyViewModel From(AccessKey key, IEnumerable<string> allCategories)
    {
        var vm = new AccessKeyViewModel { Original = key, Name = key.Name, AllowGet = key.AllowGet, Expires = key.Expires?.LocalDateTime.Date };
        vm.Scope = ScopeOptions.First(o => o.Value == (key.Scope == KeyScope.All ? ScopeChoice.Everything
            : key.Categories.Count > 0 ? ScopeChoice.Categories : ScopeChoice.Nothing));
        Fill(vm.Categories, allCategories, key.Categories);
        foreach (var secret in key.Secrets) vm.ApprovedSecrets.Add(secret);
        return vm;
    }

    private static void Fill(ObservableCollection<PickItem> items, IEnumerable<string> all, IEnumerable<string> selected)
    {
        var chosen = selected.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var name in all.Concat(chosen).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
            items.Add(new PickItem(name) { IsSelected = chosen.Contains(name) });
    }

    /// <summary>The edited key; new rows get a freshly generated key and its one-time token.</summary>
    public (AccessKey Key, string? Token) ToModel()
    {
        DateTimeOffset? expires = Expires is { } date ? new DateTimeOffset(date.Date.AddDays(1).AddTicks(-1)) : null;
        var (key, token) = Original is null
            ? AccessKeys.Create(Name, expires)
            : (new AccessKey { Id = Original.Id, Hash = Original.Hash, Created = Original.Created }, (string?)null);

        key.Name = Name.Trim();
        key.Scope = Scope.Value == ScopeChoice.Everything ? KeyScope.All : KeyScope.Selected;
        key.Categories = Scope.Value == ScopeChoice.Categories ? Categories.Where(c => c.IsSelected).Select(c => c.Name).ToList() : [];
        key.Secrets = [.. ApprovedSecrets];
        key.AllowGet = AllowGet;
        key.Expires = expires;
        return (key, token);
    }
}

/// <summary>One choice in a <see cref="Views.MultiPicker"/>.</summary>
public sealed partial class PickItem(string name) : ObservableObject
{
    public string Name { get; } = name;
    [ObservableProperty] private bool _isSelected;

    /// <summary>Matches the picker's search box.</summary>
    [ObservableProperty] private bool _isMatch = true;

    [RelayCommand]
    private void Remove() => IsSelected = false;
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

public sealed record RetentionOption(int Days, string Label);

public sealed record AuditEntry(string Time, string Operation, string Secrets, string Key, string Via);

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;

    [ObservableProperty] private HelloMode _hello;
    [ObservableProperty] private double _sessionMinutes;
    [ObservableProperty] private double _clipboardSeconds;
    [ObservableProperty] private RetentionOption _auditRetention = RetentionOptions[1];

    public static IReadOnlyList<RetentionOption> RetentionOptions { get; } =
        [new(30, "30 days"), new(90, "90 days"), new(365, "1 year"), new(0, "Forever")];
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(SaveCommand))] private bool _isBusy;

    /// <summary>Whether the page differs from what's saved (drives the Save button's look).</summary>
    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(SaveCommand), nameof(RevertCommand))] private bool _isDirty;

    private string _baseline = "";
    private bool _loading;
    private ChangeWatcher _watcher = null!;

    private readonly Action _restored;

    public SettingsViewModel(KeyloService keylo, IUserNotifier notify, Action restored)
    {
        _keylo = keylo;
        _notify = notify;
        _restored = restored;
        SecretTypes = new SecretTypesViewModel(keylo, notify);
        About = new AboutViewModel(keylo);
        PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(Hello) or nameof(SessionMinutes) or nameof(ClipboardSeconds) or nameof(AuditRetention)) UpdateDirty();
        };
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
    public AboutViewModel About { get; }

    /// <summary>Everything Save would write, as text, to compare with what was loaded.</summary>
    private string Snapshot() => System.Text.Json.JsonSerializer.Serialize(new
    {
        Hello,
        session = (int)SessionMinutes,
        clipboard = (int)ClipboardSeconds,
        audit = AuditRetention.Days,
        keys = AccessKeys.Select(k => new
        {
            id = k.Original?.Id,
            k.Name,
            scope = k.Scope.Value,
            categories = k.Categories.Where(c => c.IsSelected).Select(c => c.Name),
            approved = k.ApprovedSecrets,
            k.AllowGet,
            k.Expires,
        }),
        providers = Providers.Select(p => p.ToSettings()),
    });

    private void UpdateDirty()
    {
        if (!_loading) IsDirty = Snapshot() != _baseline;
    }

    private bool CanSave() => IsDirty && !IsBusy;

    private void WatchForChanges()
    {
        _watcher = new ChangeWatcher(UpdateDirty);
        _watcher.Watch(AccessKeys);
        foreach (var key in AccessKeys) WatchKey(key);
        foreach (var provider in Providers) _watcher.Watch(provider.Settings);
    }

    private void WatchKey(AccessKeyViewModel key)
    {
        _watcher.Watch(key);
        _watcher.Watch(key.Categories);
        _watcher.Watch(key.ApprovedSecrets);
    }
    public ObservableCollection<ProviderSettingsViewModel> Providers { get; } = [];
    public ObservableCollection<AuditEntry> Audit { get; } = [];
    public string DataDirectory => KeyloPaths.DefaultDataDirectory;
    public string PluginDirectory => Path.Combine(KeyloPaths.DefaultDataDirectory, "plugins");

    [RelayCommand(CanExecute = nameof(IsDirty))]
    public void Revert()
    {
        _loading = true;
        var config = _keylo.Config;
        Hello = config.Hello;
        SessionMinutes = config.SessionMinutes;
        ClipboardSeconds = config.ClipboardSeconds;
        AuditRetention = RetentionOptions.FirstOrDefault(o => o.Days == config.AuditRetentionDays)
                         ?? new RetentionOption(config.AuditRetentionDays, $"{config.AuditRetentionDays} days");

        AccessKeys.Clear();
        var categories = CategoryChoices();
        foreach (var key in config.AccessKeys) AccessKeys.Add(AccessKeyViewModel.From(key, categories));

        Providers.Clear();
        foreach (var provider in _keylo.Providers.All)
            Providers.Add(new ProviderSettingsViewModel(provider, config.Providers.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>()));

        SecretTypes.Load();
        About.Refresh();
        LoadAudit();

        _loading = false;
        WatchForChanges();
        _baseline = Snapshot();
        IsDirty = false;
    }

    /// <summary>
    /// Creates and saves a key straight away (after Windows Hello) and shows its token, the only time
    /// it's visible. Its name and scope are then edited in its row and saved with the other settings.
    /// </summary>
    /// <summary>Category names an access key can be scoped to.</summary>
    private List<string> CategoryChoices()
    {
        try
        {
            return _keylo.Categories.All().Select(c => c.Name).ToList();
        }
        catch (KeyloException)
        {
            return [];
        }
    }

    [RelayCommand]
    private async Task AddAccessKey()
    {
        var taken = AccessKeys.Select(k => k.Name.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var name = !taken.Contains("Claude Code") ? "Claude Code"
            : Enumerable.Range(2, 100).Select(i => $"Key {i}").First(n => !taken.Contains(n));

        try
        {
            await _keylo.ConfirmAsync($"create access key '{name}'");

            // Saved on its own (from disk), so unsaved edits elsewhere on this page stay pending.
            _keylo.RefreshConfig();
            var (key, token) = Keylo.Core.Security.AccessKeys.Create(name);
            _keylo.Config.AccessKeys.Add(key);
            _keylo.Config.Save();

            // The new key is saved already: count it as part of the saved state unless other edits are pending.
            var wasDirty = IsDirty;
            var row = AccessKeyViewModel.From(key, CategoryChoices());
            AccessKeys.Add(row);
            WatchKey(row);
            if (!wasDirty)
            {
                _baseline = Snapshot();
                IsDirty = false;
            }
            await _notify.ShowAccessKeyAsync(name, token);
            _notify.Info($"Created '{name}'. Rename it and set its categories or secrets, then Save settings.");
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }

    /// <summary>Removing a row revokes the key when you save.</summary>
    [RelayCommand]
    private void RemoveAccessKey(AccessKeyViewModel? key)
    {
        if (key is not null) AccessKeys.Remove(key);
    }

    [RelayCommand(CanExecute = nameof(CanSave))]
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
            AuditRetentionDays = AuditRetention.Days,
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
    private void OpenAuditLog()
    {
        var path = AuditLog.PathIn(KeyloPaths.DefaultDataDirectory);
        if (!File.Exists(path))
        {
            _notify.Info("The audit log is empty.");
            return;
        }
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("notepad.exe", $"\"{path}\"") { UseShellExecute = false })?.Dispose();
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
