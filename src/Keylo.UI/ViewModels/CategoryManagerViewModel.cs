using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.App.ViewModels;

/// <summary>One category in the manager: editable name, icon and colour, plus what to do with its secrets on delete.</summary>
public sealed partial class CategoryRowViewModel : ObservableObject
{
    public const string Uncategorized = "Uncategorized";
    public const string DeleteSecrets = "Delete its secrets too";

    [ObservableProperty] private string _name;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Symbol), nameof(Image), nameof(HasImage), nameof(TileBrush))] private string? _icon;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(TileBrush))] private string? _color;
    [ObservableProperty] private bool _isEditingStyle;
    [ObservableProperty] private bool _isConfirmingDelete;
    [ObservableProperty] private string _deleteTarget = Uncategorized;

    public CategoryRowViewModel(CategorySummary summary, IEnumerable<string> otherCategories)
    {
        OriginalName = summary.Name;
        _name = summary.Name;
        _icon = summary.Icon;
        _color = summary.Color;
        Count = summary.Count;
        DeleteTargets = [Uncategorized, .. otherCategories, .. summary.Count > 0 ? new[] { DeleteSecrets } : []];
    }

    public string OriginalName { get; }
    public int Count { get; }
    public string CountText => Count == 1 ? "1 secret" : $"{Count} secrets";
    public IReadOnlyList<string> DeleteTargets { get; }
    public object? Symbol => Ui.Host.Symbol(Icon, "Folder24");
    public object? Image => Ui.Host.Image(Icon);
    public bool HasImage => Image is not null;
    public object TileBrush => HasImage ? Ui.Host.Transparent : Ui.Host.Tile(IconPalette.FirstColor(Color) ?? "#64748B");
}

public sealed partial class CategoryManagerViewModel : ObservableObject
{
    private readonly KeyloService _keylo;
    private readonly IUserNotifier _notify;
    private readonly Action _changed;

    [ObservableProperty] private string _newName = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(NewSymbol), nameof(NewImage), nameof(NewHasImage), nameof(NewTileBrush))] private string? _newIcon;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(NewTileBrush))] private string? _newColor;

    public CategoryManagerViewModel(KeyloService keylo, IUserNotifier notify, Action changed)
    {
        _keylo = keylo;
        _notify = notify;
        _changed = changed;
    }

    public ObservableCollection<CategoryRowViewModel> Rows { get; } = [];
    public object? NewSymbol => Ui.Host.Symbol(NewIcon, "Folder24");
    public object? NewImage => Ui.Host.Image(NewIcon);
    public bool NewHasImage => NewImage is not null;
    public object NewTileBrush => NewHasImage ? Ui.Host.Transparent : Ui.Host.Tile(IconPalette.FirstColor(NewColor) ?? "#64748B");

    public void Refresh()
    {
        var all = _keylo.Categories.All();
        Rows.Clear();
        foreach (var category in all)
            Rows.Add(new CategoryRowViewModel(category, all.Select(c => c.Name).Where(n => n != category.Name)));
    }

    [RelayCommand]
    private void Create()
    {
        try
        {
            if (Rows.Any(r => string.Equals(r.OriginalName, NewName.Trim(), StringComparison.OrdinalIgnoreCase)))
            {
                _notify.Error($"'{NewName.Trim()}' already exists.");
                return;
            }

            _keylo.Categories.Create(NewName, NewIcon, NewColor);
            _notify.Success($"Created '{NewName.Trim()}'.");
            NewName = "";
            NewIcon = null;
            NewColor = null;
            _changed();
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private async Task Save(CategoryRowViewModel? row)
    {
        if (row is null) return;
        try
        {
            var renamed = !string.Equals(row.OriginalName, row.Name.Trim(), StringComparison.Ordinal);
            if (renamed)
            {
                // Renaming touches every secret in the category.
                await _keylo.EnsureBrowseAsync();
                var merging = Rows.Any(r => r != row && string.Equals(r.OriginalName, row.Name.Trim(), StringComparison.OrdinalIgnoreCase));
                if (merging && !await _notify.ConfirmAsync("Merge categories",
                        $"'{row.Name.Trim()}' already exists. Move the {row.CountText} from '{row.OriginalName}' into it?", "Merge"))
                    return;

                var moved = _keylo.Categories.Rename(row.OriginalName, row.Name);
                _keylo.UpdateKeysForCategory(row.OriginalName, row.Name, merged: merging);
                _keylo.Categories.SetStyle(row.Name, row.Icon, row.Color);
                _notify.Success(merging ? $"Merged into '{row.Name.Trim()}' ({moved} moved)." : $"Renamed to '{row.Name.Trim()}'.");
            }
            else
            {
                _keylo.Categories.SetStyle(row.OriginalName, row.Icon, row.Color);
                _notify.Success($"Saved '{row.OriginalName}'.");
            }

            _changed();
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }

    [RelayCommand]
    private void AskDelete(CategoryRowViewModel? row)
    {
        if (row is null) return;
        if (row.Count == 0)
        {
            _ = Delete(row);
            return;
        }
        row.IsConfirmingDelete = true;
    }

    [RelayCommand]
    private static void CancelDelete(CategoryRowViewModel? row)
    {
        if (row is not null) row.IsConfirmingDelete = false;
    }

    [RelayCommand]
    private async Task Delete(CategoryRowViewModel? row)
    {
        if (row is null) return;
        var deleteSecrets = row.DeleteTarget == CategoryRowViewModel.DeleteSecrets;
        if (deleteSecrets && !await _notify.ConfirmAsync("Delete category and secrets",
                $"Delete '{row.OriginalName}' and its {row.CountText}? This can't be undone.", $"Delete {row.Count}"))
            return;

        try
        {
            await _keylo.EnsureBrowseAsync();
            var moveTo = row.DeleteTarget is CategoryRowViewModel.Uncategorized or CategoryRowViewModel.DeleteSecrets ? null : row.DeleteTarget;
            var affected = _keylo.Categories.Delete(row.OriginalName, moveTo, deleteSecrets);
            _keylo.UpdateKeysForCategory(row.OriginalName, null);

            _notify.Success(row.Count == 0 ? $"Deleted '{row.OriginalName}'."
                : deleteSecrets ? $"Deleted '{row.OriginalName}' and {affected} secrets."
                : $"Deleted '{row.OriginalName}'; {affected} secrets moved to {moveTo ?? "Uncategorized"}.");
            _changed();
        }
        catch (KeyloException ex)
        {
            _notify.Error(ex.Message);
        }
    }
}
