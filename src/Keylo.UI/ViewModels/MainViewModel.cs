using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;
    private readonly IUiTimer _sessionTimer;
    private bool _suppressSelection;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowSettingsDialog))] private bool _isLocked = true;
    [ObservableProperty] private bool _isUnlocking;
    [ObservableProperty] private string _lockMessage = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(ShowSettingsDialog))] private bool _isSettingsOpen;
    [ObservableProperty] private bool _isCategoryManagerOpen;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private CategoryItem? _selectedCategory;
    [ObservableProperty] private SecretItemViewModel? _selectedSecret;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasDetail), nameof(ShowEmptyState))]
    private SecretDetailViewModel? _detail;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsMultiSelect), nameof(ShowEmptyState), nameof(SelectionText))]
    private IReadOnlyList<SecretItemViewModel> _selectedSecrets = [];

    [ObservableProperty] private string _bulkCategory = "";
    [ObservableProperty] private string _sessionText = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(CountText))] private int _visibleCount;

    public string CountText => VisibleCount == 1 ? "1 item" : $"{VisibleCount} items";

    public MainViewModel(KeyloService keylo, IUserNotifier notify)
    {
        _keylo = keylo;
        _notify = notify;
        Settings = new SettingsViewModel(keylo, notify, () => Reload());
        CategoryManager = new CategoryManagerViewModel(keylo, notify, () => Reload(SelectedSecret?.Name));

        _keylo.Locked += (_, _) => ApplyLock("Locked.");
        _sessionTimer = Ui.Host.CreateTimer(TimeSpan.FromSeconds(10), CheckSession);
        _sessionTimer.Start();
    }

    /// <summary>The sidebar's Home entry: pinned and recently used secrets instead of everything.</summary>
    public const string HomeKey = "\u0001home";

    public ObservableCollection<SecretItemViewModel> Secrets { get; } = [];

    /// <summary>
    /// What the list shows: <see cref="Secrets"/> filtered by category and search, A-Z, or on Home
    /// pins then recent uses. Updated in place, so rows that stay keep their selection.
    /// </summary>
    public ObservableCollection<SecretItemViewModel> VisibleSecrets { get; } = [];

    /// <summary>Home without a search: the list is grouped into Pinned and Recently used.</summary>
    [ObservableProperty] private bool _groupByHome;

    public bool IsHome => SelectedCategory?.Key == HomeKey;

    /// <summary>Home without a search shows pins and recent uses; a search covers every secret.</summary>
    private bool ShowingHomeList => IsHome && string.IsNullOrWhiteSpace(SearchText);

    public string ListTitle => IsHome ? (ShowingHomeList ? "Home" : "Search results") : SelectedCategory?.Label ?? "";

    public string EmptyTitle => ShowingHomeList ? "Nothing pinned or used yet" : "Nothing here";

    public string EmptyText => ShowingHomeList
        ? "Pin secrets you use often, and anything you or an agent uses shows up here. Search finds everything."
        : "Add a secret, or drop files on the window to import them.";

    private bool Shows(SecretItemViewModel s)
    {
        if (ShowingHomeList) return s.HomeGroup is not null;
        if (!SecretSearch.Matches(s.Info, SearchText)) return false;
        return SelectedCategory?.Key switch
        {
            null or HomeKey => true,
            "" => s.Category is null,
            var key => string.Equals(s.Category, key, StringComparison.OrdinalIgnoreCase),
        };
    }
    public ObservableCollection<CategoryItem> Categories { get; } = [];
    public ObservableCollection<string> CategoryNames { get; } = [];
    public SettingsViewModel Settings { get; }
    public CategoryManagerViewModel CategoryManager { get; }
    public bool HasDetail => Detail is not null;
    public bool IsMultiSelect => SelectedSecrets.Count > 1;
    public bool ShowEmptyState => !HasDetail && !IsMultiSelect;
    /// <summary>Settings shows as a dialog over the window, never over the lock screen.</summary>
    public bool ShowSettingsDialog => IsSettingsOpen && !IsLocked;
    public string SelectionText => $"{SelectedSecrets.Count} secrets selected";

    /// <summary>Called once the window exists (Windows Hello needs its handle).</summary>
    public async Task StartAsync()
    {
        if (_keylo.IsUnlocked)
        {
            OnUnlocked();
            return;
        }

        await Unlock();
    }

    [RelayCommand]
    private async Task Unlock()
    {
        IsUnlocking = true;
        LockMessage = _keylo.Gate.Mode == HelloMode.Never
            ? ""
            : OperatingSystem.IsWindows()
                ? "Waiting for Windows Hello… If you don't see it, press Alt+Tab and choose Windows Security."
                : $"Waiting for {Ui.Verifier}…";
        try
        {
            await _keylo.UnlockAsync();
            LockMessage = "";
            OnUnlocked();
        }
        catch (KeyloException ex)
        {
            LockMessage = ex.Message;
        }
        finally
        {
            IsUnlocking = false;
        }
    }

    [RelayCommand]
    private void Lock() => _keylo.Lock();

    private void OnUnlocked()
    {
        IsLocked = false;
        Reload();
        CheckSession();
    }

    private void ApplyLock(string message)
    {
        Detail?.Clear();
        Detail = null;
        SelectedSecrets = [];
        Secrets.Clear();
        Categories.Clear();
        _keylo.ClearClipboard();
        IsSettingsOpen = false;
        IsCategoryManagerOpen = false;
        IsLocked = true;
        LockMessage = message;
    }

    private void CheckSession()
    {
        if (IsLocked) return;
        if (!_keylo.IsUnlocked)
        {
            ApplyLock("Your session expired.");
            return;
        }

        SessionText = _keylo.Gate.SessionExpiresAt is { } until
            ? $"Unlocked until {until.LocalDateTime:h:mm tt}"
            : _keylo.Gate.Mode == HelloMode.Always ? $"{Ui.Verifier} on every reveal" : $"{Ui.Verifier} off";
    }

    /// <summary>Re-reads the store, keeping the category filter and selecting <paramref name="select"/>.</summary>
    public void Reload(string? select = null)
    {
        var all = _keylo.Store.List();
        var categories = _keylo.Categories.All(all);
        var categoryKey = SelectedCategory is null ? HomeKey : SelectedCategory.Key;

        _suppressSelection = true;
        Secrets.Clear();
        foreach (var info in all) Secrets.Add(new SecretItemViewModel(info, _keylo.Categories.StyleOf(info.Category), _keylo.TypeOf(info.Type)));
        var homeCount = MarkHomeItems();

        Categories.Clear();
        var host = Ui.Host;
        Categories.Add(new CategoryItem(HomeKey, "Home", homeCount, host.Symbol("Home24", null)));
        Categories.Add(new CategoryItem(null, "All secrets", all.Count, host.Symbol("Key24", null)));
        foreach (var category in categories)
            Categories.Add(new CategoryItem(category.Name, category.Name, category.Count,
                host.Symbol(category.Icon, "Folder24"), host.Solid(category.Color), host.Image(category.Icon)));
        if (all.Any(s => s.Category is null))
            Categories.Add(new CategoryItem("", "Uncategorized", all.Count(s => s.Category is null), host.Symbol("Tag24", null)));

        CategoryNames.Clear();
        foreach (var category in categories) CategoryNames.Add(category.Name);

        SelectedCategory = Categories.FirstOrDefault(c => c.Key == categoryKey) ?? Categories[0];
        SelectedSecrets = [];
        _suppressSelection = false;

        RefreshView();

        var target = select is null ? null : Secrets.FirstOrDefault(s => s.Name.Equals(select, StringComparison.OrdinalIgnoreCase));
        if (target is not null && !VisibleSecrets.Contains(target))
        {
            // Saved into a category that's filtered out: switch to All so the result is visible.
            SearchText = "";
            SelectedCategory = Categories.First(c => c.Key is null);
        }
        SelectedSecret = target;
        if (target is null) ShowDetail(null, creating: false);
        CategoryManager.Refresh();
    }

    /// <summary>Flags pinned and recently used secrets for Home. Returns how many Home shows.</summary>
    private int MarkHomeItems()
    {
        var byName = Secrets.ToDictionary(s => s.Name, StringComparer.OrdinalIgnoreCase);
        var pins = _keylo.Activity.Pins().Where(byName.ContainsKey).ToList();
        foreach (var (name, i) in pins.Select((n, i) => (n, i)))
        {
            var item = byName[name];
            (item.IsPinned, item.HomeGroup, item.HomeRank) = (true, SecretItemViewModel.PinnedGroup, i);
        }

        var recent = _keylo.Activity.Recent(12).Where(r => byName.TryGetValue(r.Name, out var s) && !s.IsPinned).Take(8).ToList();
        foreach (var (use, i) in recent.Select((u, i) => (u, i)))
        {
            var item = byName[use.Name];
            (item.HomeGroup, item.HomeRank, item.RecentText) = (SecretItemViewModel.RecentGroup, 1000 + i, Describe(use));
        }
        return pins.Count + recent.Count;
    }

    private static string Describe(RecentUse use)
    {
        var verb = use.Action switch { "run" => "ran it", "get" => "read it", var a => a };
        var age = DateTimeOffset.Now - use.Time;
        var when = age.TotalMinutes < 1 ? "just now"
            : age.TotalHours < 1 ? $"{(int)age.TotalMinutes} min ago"
            : age.TotalDays < 1 ? $"{(int)age.TotalHours} h ago"
            : age.TotalDays < 7 ? use.Time.LocalDateTime.ToString("ddd")
            : use.Time.LocalDateTime.ToString("MMM d");
        return $"{use.Who} {verb} · {when}";
    }

    private Task ReloadAsync(string? select)
    {
        Reload(select);
        return Task.CompletedTask;
    }

    partial void OnSearchTextChanged(string value) => RefreshView();

    partial void OnSelectedCategoryChanged(CategoryItem? value)
    {
        if (_suppressSelection) return;
        CloseOverlays();
        RefreshView();
    }

    partial void OnSelectedSecretChanged(SecretItemViewModel? value)
    {
        if (_suppressSelection) return;
        if (value is not null) CloseOverlays();
        ShowDetail(IsMultiSelect ? null : value?.Info, creating: false);
    }

    /// <summary>From the list's SelectionChanged (SelectedItems isn't bindable).</summary>
    public void UpdateSelection(IEnumerable<SecretItemViewModel> selected)
    {
        if (_suppressSelection) return;
        SelectedSecrets = selected.ToList();
        if (IsMultiSelect)
        {
            CloseOverlays();
            ShowDetail(null, creating: false);
        }
        else if (SelectedSecrets.Count == 1 && Detail?.Name != SelectedSecrets[0].Name)
        {
            ShowDetail(SelectedSecrets[0].Info, creating: false);
        }
    }

    private void RefreshView()
    {
        // Home groups pins and recent uses (in that order); everywhere else is a plain A-Z list.
        var home = ShowingHomeList;
        var visible = Secrets.Where(Shows);
        var wanted = (home ? visible.OrderBy(s => s.HomeRank) : visible.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)).ToList();

        foreach (var item in Secrets)
        {
            item.DisplaySubtitle = home && item.RecentText is not null ? item.RecentText : item.Subtitle;
            item.GroupHeader = null;
        }
        if (home)
        {
            string? group = null;
            foreach (var item in wanted.Where(i => i.HomeGroup != group))
                item.GroupHeader = group = item.HomeGroup;
        }

        GroupByHome = home;
        SyncVisible(wanted);
        VisibleCount = wanted.Count;
        OnPropertyChanged(nameof(IsHome));
        OnPropertyChanged(nameof(ListTitle));
        OnPropertyChanged(nameof(EmptyTitle));
        OnPropertyChanged(nameof(EmptyText));
    }

    /// <summary>Makes <see cref="VisibleSecrets"/> equal <paramref name="wanted"/> with removes and moves, not a reset.</summary>
    private void SyncVisible(List<SecretItemViewModel> wanted)
    {
        var keep = wanted.ToHashSet();
        for (var i = VisibleSecrets.Count - 1; i >= 0; i--)
            if (!keep.Contains(VisibleSecrets[i])) VisibleSecrets.RemoveAt(i);

        for (var i = 0; i < wanted.Count; i++)
        {
            if (i < VisibleSecrets.Count && VisibleSecrets[i] == wanted[i]) continue;
            var at = VisibleSecrets.IndexOf(wanted[i]);
            if (at >= 0) VisibleSecrets.Move(at, i);
            else VisibleSecrets.Insert(i, wanted[i]);
        }
    }

    private void ShowDetail(SecretInfo? info, bool creating)
    {
        Detail?.Clear();
        Detail = info is null && !creating ? null : new SecretDetailViewModel(_keylo, _notify, ReloadAsync, info);
        if (creating && SelectedCategory?.Key is { Length: > 0 } category && category != HomeKey) Detail!.Category = category;
    }

    private void CloseOverlays()
    {
        IsSettingsOpen = false;
        IsCategoryManagerOpen = false;
    }

    [RelayCommand]
    private void NewSecret()
    {
        CloseOverlays();
        _suppressSelection = true;
        SelectedSecret = null;
        SelectedSecrets = [];
        _suppressSelection = false;
        ShowDetail(null, creating: true);
    }

    [RelayCommand]
    private void OpenSettings()
    {
        _keylo.RefreshConfig();
        Settings.Revert();
        IsCategoryManagerOpen = false;
        IsSettingsOpen = true;
    }

    [RelayCommand]
    private void OpenCategoryManager()
    {
        CategoryManager.Refresh();
        IsSettingsOpen = false;
        IsCategoryManagerOpen = true;
    }

    [RelayCommand]
    private void CloseSettings() => CloseOverlays();

    // ---------------------------------------------------------------- bulk actions

    [RelayCommand]
    private async Task DeleteSelected()
    {
        var names = SelectedSecrets.Select(s => s.Name).ToList();
        if (names.Count == 0) return;

        var preview = string.Join(", ", names.Take(5)) + (names.Count > 5 ? $" and {names.Count - 5} more" : "");
        if (!await _notify.ConfirmAsync($"Delete {names.Count} secrets", $"Delete {preview}? This can't be undone.", $"Delete {names.Count}"))
            return;

        try
        {
            await _keylo.EnsureBrowseAsync();
            var deleted = names.Count(_keylo.Store.Delete);
            _keylo.Activity.Removed(names);
            _notify.Success($"Deleted {deleted} secret{(deleted == 1 ? "" : "s")}.");
            Reload();
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private async Task MoveSelected()
    {
        var names = SelectedSecrets.Select(s => s.Name).ToList();
        if (names.Count == 0) return;

        try
        {
            await _keylo.EnsureBrowseAsync();
            var target = BulkCategory.Trim();
            foreach (var name in names) _keylo.Store.UpdateDetails(name, category: target);
            _notify.Success(target.Length == 0
                ? $"Removed the category from {names.Count} secrets."
                : $"Moved {names.Count} secrets to '{target}'.");
            BulkCategory = "";
            Reload();
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private void ClearSelection()
    {
        SelectedSecret = null;
        SelectedSecrets = [];
    }

    // ---------------------------------------------------------------- pins

    /// <summary>From a row's pin button or right-click menu.</summary>
    [RelayCommand]
    private void TogglePin(SecretItemViewModel? item)
    {
        if (item is null) return;
        _keylo.Activity.SetPinned(item.Name, !item.IsPinned);
        _notify.Success(item.IsPinned ? $"Unpinned '{item.Name}'." : $"Pinned '{item.Name}' to Home.");
        Reload(SelectedSecret?.Name);
    }

    // ---------------------------------------------------------------- link

    [RelayCommand]
    private async Task LinkFromVault()
    {
        if (_keylo.Providers.Linked.Count == 0)
        {
            _notify.Error("No vault to link to. 1Password is built in; others come as plugins.");
            return;
        }
        if (await _notify.LinkSecretAsync() is { } result)
        {
            // "name" for one link, "first|count" for several.
            var parts = result.Split('|');
            _notify.Success(parts.Length == 2 ? $"Linked {parts[1]} secrets." : $"Linked '{parts[0]}'.");
            Reload(parts[0]);
        }
    }

    // ---------------------------------------------------------------- import

    [RelayCommand]
    private async Task ImportFiles()
    {
        var files = await Ui.Host.PickFilesAsync("Import files as secrets", multiple: true);
        if (files.Count > 0) await ImportAsync(files);
    }

    [RelayCommand]
    private async Task ImportFolder()
    {
        if (await Ui.Host.PickFolderAsync("Import a folder") is { } folder) await ImportAsync([folder]);
    }

    /// <summary>Also used for files dropped on the window or passed on the command line.</summary>
    public async Task ImportAsync(IReadOnlyList<string> paths)
    {
        if (IsLocked || paths.Count == 0) return;
        try
        {
            await _keylo.EnsureBrowseAsync();

            var options = new ImportOptionsViewModel(
                paths,
                _keylo.Categories.All().Select(c => c.Name),
                Secrets.Select(s => s.Name),
                preferredCategory: SelectedCategory?.Key is { Length: > 0 } key && key != HomeKey ? key : null);
            if (options.FileCount == 0)
            {
                _notify.Error("No files to import there.");
                return;
            }

            if (await _notify.AskImportOptionsAsync(options) is not { } chosen) return;

            var result = SecretImporter.Import(_keylo.Store, paths, chosen.Category, chosen.Overwrite, chosen.SubfolderCategories, chosen.Names, chosen.Types);
            Reload(result.Imported.Count == 1 ? result.Imported[0].Name : null);

            var message = $"Imported {result.Imported.Count} secret{(result.Imported.Count == 1 ? "" : "s")}";
            if (result.Skipped.Count > 0)
            {
                message += $", skipped {result.Skipped.Count}: " +
                           string.Join("; ", result.Skipped.Take(3).Select(s => $"{System.IO.Path.GetFileName(s.SourcePath)} ({s.Reason})"));
                _notify.Info(message);
            }
            else
            {
                _notify.Success(message + ". The original files are untouched.");
            }
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }
}
