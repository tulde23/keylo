using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace Keylo.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;
    private readonly DispatcherTimer _sessionTimer = new() { Interval = TimeSpan.FromSeconds(10) };
    private bool _suppressSelection;

    [ObservableProperty] private bool _isLocked = true;
    [ObservableProperty] private bool _isUnlocking;
    [ObservableProperty] private string _lockMessage = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsOverlayOpen))] private bool _isSettingsOpen;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsOverlayOpen))] private bool _isCategoryManagerOpen;
    [ObservableProperty] private string _searchText = "";
    [ObservableProperty] private CategoryItem? _selectedCategory;
    [ObservableProperty] private SecretItemViewModel? _selectedSecret;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasDetail), nameof(ShowEmptyState))]
    private SecretDetailViewModel? _detail;

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsMultiSelect), nameof(ShowEmptyState), nameof(SelectionText))]
    private IReadOnlyList<SecretItemViewModel> _selectedSecrets = [];

    [ObservableProperty] private string _bulkCategory = "";
    [ObservableProperty] private string _sessionText = "";
    [ObservableProperty] private int _visibleCount;

    public MainViewModel(KeyloService keylo, IUserNotifier notify)
    {
        _keylo = keylo;
        _notify = notify;
        Settings = new SettingsViewModel(keylo, notify, () => Reload());
        CategoryManager = new CategoryManagerViewModel(keylo, notify, () => Reload(SelectedSecret?.Name));
        SecretsView = CollectionViewSource.GetDefaultView(Secrets);
        SecretsView.Filter = o => o is SecretItemViewModel s &&
                                  (SelectedCategory?.Key is not { } key ||
                                   (key.Length == 0 ? s.Category is null : string.Equals(s.Category, key, StringComparison.OrdinalIgnoreCase))) &&
                                  SecretSearch.Matches(s.Info, SearchText);

        _keylo.Locked += (_, _) => ApplyLock("Locked.");
        _sessionTimer.Tick += (_, _) => CheckSession();
        _sessionTimer.Start();
    }

    public ObservableCollection<SecretItemViewModel> Secrets { get; } = [];
    public ICollectionView SecretsView { get; }
    public ObservableCollection<CategoryItem> Categories { get; } = [];
    public ObservableCollection<string> CategoryNames { get; } = [];
    public SettingsViewModel Settings { get; }
    public CategoryManagerViewModel CategoryManager { get; }
    public bool HasDetail => Detail is not null;
    public bool IsMultiSelect => SelectedSecrets.Count > 1;
    public bool ShowEmptyState => !HasDetail && !IsMultiSelect;
    public bool IsOverlayOpen => IsSettingsOpen || IsCategoryManagerOpen;
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
            : "Waiting for Windows Hello… If you don't see it, press Alt+Tab and choose Windows Security.";
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
            : _keylo.Gate.Mode == HelloMode.Always ? "Windows Hello on every reveal" : "Windows Hello off";
    }

    /// <summary>Re-reads the store, keeping the category filter and selecting <paramref name="select"/>.</summary>
    public void Reload(string? select = null)
    {
        var all = _keylo.Store.List();
        var categories = _keylo.Categories.All(all);
        var categoryKey = SelectedCategory?.Key;

        _suppressSelection = true;
        Secrets.Clear();
        foreach (var info in all) Secrets.Add(new SecretItemViewModel(info, _keylo.Categories.StyleOf(info.Category)));

        Categories.Clear();
        Categories.Add(new CategoryItem(null, "All secrets", all.Count, SymbolRegular.Key24));
        foreach (var category in categories)
        {
            var color = IconCatalog.ToColor(category.Color);
            Categories.Add(new CategoryItem(category.Name, category.Name, category.Count,
                IconCatalog.ToSymbol(category.Icon, SymbolRegular.Folder24),
                color is { } c ? new System.Windows.Media.SolidColorBrush(c) : null,
                IconImages.Load(category.Icon)));
        }
        if (all.Any(s => s.Category is null))
            Categories.Add(new CategoryItem("", "Uncategorized", all.Count(s => s.Category is null), SymbolRegular.Tag24));

        CategoryNames.Clear();
        foreach (var category in categories) CategoryNames.Add(category.Name);

        SelectedCategory = Categories.FirstOrDefault(c => c.Key == categoryKey) ?? Categories[0];
        SelectedSecrets = [];
        _suppressSelection = false;

        RefreshView();

        var target = select is null ? null : Secrets.FirstOrDefault(s => s.Name.Equals(select, StringComparison.OrdinalIgnoreCase));
        if (target is not null && !SecretsView.Cast<SecretItemViewModel>().Contains(target))
        {
            // Saved into a category that's filtered out: switch to All so the result is visible.
            SearchText = "";
            SelectedCategory = Categories[0];
        }
        SelectedSecret = target;
        if (target is null) ShowDetail(null, creating: false);
        CategoryManager.Refresh();
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
        SecretsView.Refresh();
        VisibleCount = SecretsView.Cast<object>().Count();
    }

    private void ShowDetail(SecretInfo? info, bool creating)
    {
        Detail?.Clear();
        Detail = info is null && !creating ? null : new SecretDetailViewModel(_keylo, _notify, ReloadAsync, info);
        if (creating && SelectedCategory?.Key is { Length: > 0 } category) Detail!.Category = category;
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

    // ---------------------------------------------------------------- import

    [RelayCommand]
    private async Task ImportFiles()
    {
        var dialog = new OpenFileDialog { Title = "Import files as secrets", Multiselect = true };
        if (dialog.ShowDialog() == true) await ImportAsync(dialog.FileNames);
    }

    [RelayCommand]
    private async Task ImportFolder()
    {
        var dialog = new OpenFolderDialog { Title = "Import a folder" };
        if (dialog.ShowDialog() == true) await ImportAsync([dialog.FolderName]);
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
                preferredCategory: SelectedCategory?.Key is { Length: > 0 } key ? key : null);
            if (options.FileCount == 0)
            {
                _notify.Error("No files to import there.");
                return;
            }

            if (_notify.AskImportOptions(options) is not { } chosen) return;

            var result = SecretImporter.Import(_keylo.Store, paths, chosen.Category, chosen.Overwrite, chosen.SubfolderCategories);
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
