using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.App.ViewModels;

public sealed partial class FieldDefinitionViewModel : ObservableObject
{
    /// <summary>Fixed once saved: secrets store their data under it, so relabeling keeps it.</summary>
    public string Id { get; init; } = "";

    [ObservableProperty] private string _label = "";
    [ObservableProperty] private FieldKind _kind = FieldKind.Text;
    [ObservableProperty] private string _options = "";

    public static IReadOnlyList<FieldKind> Kinds { get; } = Enum.GetValues<FieldKind>();

    public FieldDefinition ToModel() => new()
    {
        Id = Id,
        Label = Label.Trim(),
        Kind = Kind,
        Options = Options.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) is { Length: > 0 } o ? [.. o] : null,
    };
}

public sealed partial class SecretTypeViewModel : ObservableObject
{
    public string Id { get; init; } = "";
    public bool IsBuiltIn { get; init; }
    public bool IsCustom => !IsBuiltIn;

    [ObservableProperty] private string _name = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Symbol))] private string? _icon;
    [ObservableProperty] private string? _color;

    public ObservableCollection<FieldDefinitionViewModel> Fields { get; } = [];

    public Wpf.Ui.Controls.SymbolRegular Symbol => IconCatalog.ToSymbol(Icon, Wpf.Ui.Controls.SymbolRegular.Key24);

    public string Summary => string.Join(" · ", Fields.Select(f => f.Label));

    public static SecretTypeViewModel From(SecretTypeDefinition type)
    {
        var vm = new SecretTypeViewModel { Id = type.Id, IsBuiltIn = type.IsBuiltIn, Name = type.Name, Icon = type.Icon, Color = type.Color };
        foreach (var field in type.Fields)
            vm.Fields.Add(new FieldDefinitionViewModel { Id = field.Id, Label = field.Label, Kind = field.Kind, Options = string.Join(", ", field.Options ?? []) });
        return vm;
    }

    public SecretTypeDefinition ToModel() => new()
    {
        Id = Id,
        Name = Name.Trim(),
        Icon = Icon,
        Color = Color,
        Fields = Fields.Select(f => f.ToModel()).ToList(),
    };

    [RelayCommand]
    private void AddField() => Fields.Add(new FieldDefinitionViewModel { Label = $"Field {Fields.Count + 1}" });

    [RelayCommand]
    private void RemoveField(FieldDefinitionViewModel? field)
    {
        if (field is not null) Fields.Remove(field);
    }
}

/// <summary>Settings → Secret types: built-ins (icon and colour only) and the user's own types.</summary>
public sealed partial class SecretTypesViewModel(KeyloService keylo, IUserNotifier notify) : ObservableObject
{
    public ObservableCollection<SecretTypeViewModel> Types { get; } = [];

    [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(SaveCommand))] private bool _isDirty;

    private string _baseline = "";
    private bool _loading;

    private string Snapshot() => System.Text.Json.JsonSerializer.Serialize(Types.Select(t => t.ToModel()));

    private void UpdateDirty()
    {
        if (!_loading) IsDirty = Snapshot() != _baseline;
    }

    public void Load()
    {
        _loading = true;
        Types.Clear();
        foreach (var type in keylo.Types) Types.Add(SecretTypeViewModel.From(type));
        _loading = false;

        var watcher = new ChangeWatcher(UpdateDirty);
        watcher.Watch(Types);
        foreach (var type in Types) watcher.Watch(type.Fields);
        Types.CollectionChanged += (_, e) =>
        {
            foreach (var added in e.NewItems?.OfType<SecretTypeViewModel>() ?? []) watcher.Watch(added.Fields);
        };
        _baseline = Snapshot();
        IsDirty = false;
    }

    [RelayCommand]
    private void AddType()
    {
        var type = new SecretTypeViewModel { Name = "New type", Icon = "Apps24" };
        type.Fields.Add(new FieldDefinitionViewModel { Label = "Username", Kind = FieldKind.Username });
        type.Fields.Add(new FieldDefinitionViewModel { Label = "Secret", Kind = FieldKind.Password });
        Types.Add(type);
    }

    [RelayCommand]
    private void RemoveType(SecretTypeViewModel? type)
    {
        if (type is null || type.IsBuiltIn) return;
        if (type.Id.Length > 0 && keylo.Store.List().Count(s => string.Equals(s.Type, type.Id, StringComparison.OrdinalIgnoreCase)) is > 0 and var used)
        {
            notify.Error($"{used} secret(s) use '{type.Name}'. Change their type first.");
            return;
        }
        Types.Remove(type);
    }

    [RelayCommand(CanExecute = nameof(IsDirty))]
    private void Save()
    {
        try
        {
            keylo.TypeCatalog.SaveCustom(Types.Where(t => t.IsCustom).Select(t => t.ToModel()).ToList());
            keylo.TypeCatalog.SaveBuiltInStyles(Types.Where(t => t.IsBuiltIn).ToDictionary(t => t.Id, t => (t.Icon, t.Color)));
            keylo.RefreshTypes();
            Load();
            notify.Success("Secret types saved.");
        }
        catch (KeyloException ex)
        {
            notify.Error(ex.Message);
        }
    }
}
