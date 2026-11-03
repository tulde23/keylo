using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Keylo.Core;

namespace Keylo.App.ViewModels;

public enum ImportCategoryMode { Subfolders, Single, None }

/// <summary>What the user chose in the import dialog.</summary>
public sealed record ImportOptions(string? Category, bool SubfolderCategories, bool Overwrite);

public sealed record ImportPreviewRow(string Name, string Category, bool Exists);

/// <summary>Backs the import dialog: category choice, overwrite, and a live preview of the result.</summary>
public sealed partial class ImportOptionsViewModel : ObservableObject
{
    private const int PreviewRows = 8;

    private readonly IReadOnlyList<string> _paths;
    private readonly HashSet<string> _existingNames;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSubfolders), nameof(IsSingle), nameof(IsNone))]
    private ImportCategoryMode _mode;

    [ObservableProperty] private string _category = "";
    [ObservableProperty] private bool _overwrite;
    [ObservableProperty] private int _fileCount;
    [ObservableProperty] private int _conflictCount;
    [ObservableProperty] private string _moreText = "";

    public ImportOptionsViewModel(IReadOnlyList<string> paths, IEnumerable<string> categories, IEnumerable<string> existingNames, string? preferredCategory)
    {
        _paths = paths;
        _existingNames = new HashSet<string>(existingNames, StringComparer.OrdinalIgnoreCase);
        Categories = new ObservableCollection<string>(categories);

        var plan = SecretImporter.Plan(paths);
        HasSubfolders = plan.Items.Any(i => i.Category is not null);
        Source = paths.Count == 1 ? paths[0] : $"{paths.Count} items";

        if (preferredCategory is { Length: > 0 })
        {
            Category = preferredCategory;
            Mode = ImportCategoryMode.Single;
        }
        else
        {
            Mode = HasSubfolders ? ImportCategoryMode.Subfolders : ImportCategoryMode.None;
        }

        Refresh();
    }

    public ObservableCollection<string> Categories { get; }
    public ObservableCollection<ImportPreviewRow> Preview { get; } = [];
    public bool HasSubfolders { get; }
    public string Source { get; }

    // Radio buttons bind to these; setting one true selects that mode.
    public bool IsSubfolders { get => Mode == ImportCategoryMode.Subfolders; set { if (value) Mode = ImportCategoryMode.Subfolders; } }
    public bool IsSingle { get => Mode == ImportCategoryMode.Single; set { if (value) Mode = ImportCategoryMode.Single; } }
    public bool IsNone { get => Mode == ImportCategoryMode.None; set { if (value) Mode = ImportCategoryMode.None; } }

    public bool CanImport => FileCount > 0 && (Mode != ImportCategoryMode.Single || Category.Trim().Length > 0);

    public ImportOptions ToOptions() => new(
        Mode == ImportCategoryMode.Single ? Category.Trim() : null,
        SubfolderCategories: Mode == ImportCategoryMode.Subfolders,
        Overwrite);

    partial void OnModeChanged(ImportCategoryMode value) => Refresh();
    partial void OnCategoryChanged(string value) => Refresh();
    partial void OnOverwriteChanged(bool value) => OnPropertyChanged(nameof(CanImport));

    private void Refresh()
    {
        var options = ToOptions();
        var items = SecretImporter.Plan(_paths, options.Category is { Length: > 0 } c ? c : null, options.SubfolderCategories).Items;

        FileCount = items.Count;
        ConflictCount = items.Count(i => _existingNames.Contains(i.Name));

        Preview.Clear();
        foreach (var item in items.Take(PreviewRows))
            Preview.Add(new ImportPreviewRow(item.Name, item.Category ?? "No category", _existingNames.Contains(item.Name)));
        MoreText = items.Count > PreviewRows ? $"…and {items.Count - PreviewRows} more" : "";

        OnPropertyChanged(nameof(CanImport));
    }
}
