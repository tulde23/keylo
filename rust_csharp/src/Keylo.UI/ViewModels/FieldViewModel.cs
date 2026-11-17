using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Keylo.Core;

namespace Keylo.App.ViewModels;

/// <summary>One field of a typed secret, in the detail panel (view and edit).</summary>
public sealed partial class FieldViewModel(FieldDefinition definition, Func<FieldViewModel, Task> copy) : ObservableObject
{
    public FieldDefinition Definition { get; } = definition;
    public string Id => Definition.Id;
    public string Label => Definition.Label;
    public string SectionLabel => Definition.Label.ToUpperInvariant();
    public bool IsSecret => Definition.IsSecret;
    public bool IsMultiline => Definition.Kind == FieldKind.SecretText;
    public bool HasOptions => Definition.Options is { Count: > 0 };
    public IReadOnlyList<string> Options => Definition.Options ?? [];

    public string Placeholder => Definition.Kind switch
    {
        FieldKind.Url => "https://…",
        FieldKind.Number => "e.g. 5432",
        FieldKind.Username => "Account, email or key id",
        _ => "",
    };

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(DisplayValue), nameof(HasValue), nameof(ShowInView))]
    private string _value = "";

    /// <summary>Secret fields stay masked until the user reveals them (the value isn't even loaded before).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(DisplayValue), nameof(ShowInView))]
    private bool _revealed;

    /// <summary>A database connection string built from the other fields rather than stored.</summary>
    [ObservableProperty] private bool _isDerived;

    public bool HasValue => Value.Length > 0;

    /// <summary>In view mode, empty fields are hidden; secret ones show (masked) until revealed, as they aren't loaded before.</summary>
    public bool ShowInView => HasValue || (IsSecret && !Revealed);

    public string DisplayValue => IsSecret && !Revealed ? "••••••••••••••••" : Value;

    [RelayCommand]
    private Task Copy() => copy(this);
}

/// <summary>An entry in the type picker; <see cref="Definition"/> is null for a plain secret.</summary>
public sealed record TypeChoice(SecretTypeDefinition? Definition)
{
    public string Name => Definition?.Name ?? "Plain secret";
    public string? Id => Definition?.Id;
    public object? Symbol => Services.Ui.Host.Symbol(Definition?.Icon, "Key24");
}
