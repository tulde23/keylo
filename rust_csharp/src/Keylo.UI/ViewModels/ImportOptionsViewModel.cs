using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using Keylo.Core;

namespace Keylo.App.ViewModels;

public enum ImportCategoryMode { Subfolders, Single, None }

/// <summary>What the user chose in the import dialog. <see cref="Names"/>: names they typed, by source path.</summary>
public sealed record ImportOptions(string? Category, bool SubfolderCategories, bool Overwrite,
    IReadOnlyDictionary<string, string>? Names = null, IReadOnlyDictionary<string, string>? Types = null);

/// <summary>One file in the import preview; its name and type can be changed.</summary>
public sealed partial class ImportRowViewModel(string sourcePath, string defaultName, string category, IReadOnlyList<TypeChoice> types, Action changed) : ObservableObject
{
    public IReadOnlyList<TypeChoice> TypeChoices { get; } = types;

    /// <summary>Guessed from the file; "Plain secret" keeps the value as it is.</summary>
    [ObservableProperty] private TypeChoice? _type;

    public string SourcePath { get; } = sourcePath;
    public string DefaultName { get; } = defaultName;
    public string Category { get; } = category;
    public string FileName => Path.GetFileName(SourcePath);

    [ObservableProperty] private string _name = defaultName;

    /// <summary>"exists", "duplicate", "invalid", or empty.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasProblem))] private string _problem = "";

    public bool HasProblem => Problem.Length > 0;

    partial void OnNameChanged(string value) => changed();
}

/// <summary>Backs the import dialog: category choice, overwrite, and a live preview of the result.</summary>
public sealed partial class ImportOptionsViewModel : ObservableObject
{
    private readonly IReadOnlyList<string> _paths;
    private readonly HashSet<string> _existingNames;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSubfolders), nameof(IsSingle), nameof(IsNone))]
    private ImportCategoryMode _mode;

    [ObservableProperty] private string _category = "";
    [ObservableProperty] private bool _overwrite;
    [ObservableProperty] private int _fileCount;
    [ObservableProperty] private int _conflictCount;
    [ObservableProperty] private int _problemCount;

    // Names typed and types chosen by the user survive changes to the category options.
    private readonly Dictionary<string, string> _typedNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, TypeChoice> _chosenTypes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string?> _guesses = new(StringComparer.OrdinalIgnoreCase);
    private readonly IReadOnlyList<TypeChoice> _typeChoices =
        [new TypeChoice(null), .. SecretTypeCatalog.BuiltIn.Select(t => new TypeChoice(t))];

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
    public ObservableCollection<ImportRowViewModel> Preview { get; } = [];
    public bool HasSubfolders { get; }
    public string Source { get; }

    // Radio buttons bind to these; setting one true selects that mode.
    public bool IsSubfolders { get => Mode == ImportCategoryMode.Subfolders; set { if (value) Mode = ImportCategoryMode.Subfolders; } }
    public bool IsSingle { get => Mode == ImportCategoryMode.Single; set { if (value) Mode = ImportCategoryMode.Single; } }
    public bool IsNone { get => Mode == ImportCategoryMode.None; set { if (value) Mode = ImportCategoryMode.None; } }

    /// <summary>Names must be valid and unique; an existing name is fine only when replacing.</summary>
    public bool CanImport => FileCount > 0 && (Mode != ImportCategoryMode.Single || Category.Trim().Length > 0) &&
                             Preview.All(r => r.Problem is "" or "exists");

    public ImportOptions ToOptions() => new(
        Mode == ImportCategoryMode.Single ? Category.Trim() : null,
        SubfolderCategories: Mode == ImportCategoryMode.Subfolders,
        Overwrite,
        Preview.Where(r => r.Name.Trim() != r.DefaultName).ToDictionary(r => r.SourcePath, r => r.Name.Trim(), StringComparer.OrdinalIgnoreCase),
        Preview.ToDictionary(r => r.SourcePath, r => r.Type?.Id ?? "", StringComparer.OrdinalIgnoreCase));

    partial void OnModeChanged(ImportCategoryMode value) => Refresh();
    partial void OnCategoryChanged(string value) => Refresh();
    partial void OnOverwriteChanged(bool value) => OnPropertyChanged(nameof(CanImport));

    private void Refresh()
    {
        foreach (var row in Preview.Where(r => r.Name.Trim() != r.DefaultName)) _typedNames[row.SourcePath] = row.Name;
        foreach (var row in Preview.Where(r => r.Type is not null)) _chosenTypes[row.SourcePath] = row.Type!;

        var options = ToOptions();
        var items = SecretImporter.Plan(_paths, options.Category is { Length: > 0 } c ? c : null, options.SubfolderCategories).Items;
        FileCount = items.Count;

        Preview.Clear();
        foreach (var item in items)
        {
            var row = new ImportRowViewModel(item.SourcePath, item.Name, item.Category ?? "No category", _typeChoices, Validate);
            if (_typedNames.TryGetValue(item.SourcePath, out var typed)) row.Name = typed;
            row.Type = _chosenTypes.GetValueOrDefault(item.SourcePath) ?? _typeChoices.FirstOrDefault(t => t.Id == Guess(item.SourcePath)) ?? _typeChoices[0];
            Preview.Add(row);
        }
        Validate();
    }

    /// <summary>The guessed type of a file (read once; large or unreadable files stay plain).</summary>
    private string? Guess(string path)
    {
        if (_guesses.TryGetValue(path, out var guess)) return guess;
        try
        {
            guess = new FileInfo(path).Length <= 64 * 1024 ? SecretTypeInference.Infer(path, File.ReadAllBytes(path))?.TypeId : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            guess = null;
        }
        return _guesses[path] = guess;
    }

    /// <summary>Flags each row's name: invalid, a duplicate within this import, or already in Keylo.</summary>
    private void Validate()
    {
        var counts = Preview.GroupBy(r => r.Name.Trim(), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        foreach (var row in Preview)
        {
            var name = row.Name.Trim();
            row.Problem = !SecretStore.IsValidName(name) ? "invalid"
                : counts[name] > 1 ? "duplicate"
                : _existingNames.Contains(name) ? "exists"
                : "";
        }
        ConflictCount = Preview.Count(r => r.Problem == "exists");
        ProblemCount = Preview.Count(r => r.Problem is "invalid" or "duplicate");
        OnPropertyChanged(nameof(CanImport));
    }
}
