using System.Collections;
using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Keylo.App.ViewModels;

namespace Keylo.Desktop.Views;

/// <summary>
/// Picks any number of <see cref="PickItem"/>s: the chosen ones show as removable chips, and Add
/// opens a searchable checklist of all of them.
/// </summary>
public partial class MultiPicker : UserControl
{
    public static readonly StyledProperty<IEnumerable?> ItemsSourceProperty = AvaloniaProperty.Register<MultiPicker, IEnumerable?>(nameof(ItemsSource));
    public static readonly StyledProperty<string> PlaceholderProperty = AvaloniaProperty.Register<MultiPicker, string>(nameof(Placeholder), "");

    static MultiPicker()
    {
        ItemsSourceProperty.Changed.AddClassHandler<MultiPicker>((p, e) => p.Attach(e.OldValue as IEnumerable, e.NewValue as IEnumerable));
        PlaceholderProperty.Changed.AddClassHandler<MultiPicker>((p, _) => p.PlaceholderText.Text = p.Placeholder);
    }

    public MultiPicker()
    {
        InitializeComponent();
        Dropdown.Opened += (_, _) =>
        {
            Search.Text = "";
            Search.Focus();
        };
        Search.TextChanged += (_, _) => Filter();
    }

    public IEnumerable? ItemsSource { get => GetValue(ItemsSourceProperty); set => SetValue(ItemsSourceProperty, value); }
    public string Placeholder { get => GetValue(PlaceholderProperty); set => SetValue(PlaceholderProperty, value); }

    private IEnumerable<PickItem> Items => ItemsSource?.OfType<PickItem>() ?? [];

    private void Attach(IEnumerable? oldItems, IEnumerable? newItems)
    {
        foreach (var item in oldItems?.OfType<PickItem>() ?? []) item.PropertyChanged -= OnItemChanged;
        foreach (var item in newItems?.OfType<PickItem>() ?? []) item.PropertyChanged += OnItemChanged;
        Chips.ItemsSource = newItems;
        Checklist.ItemsSource = newItems;
        UpdatePlaceholder();
    }

    private void OnItemChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PickItem.IsSelected)) UpdatePlaceholder();
    }

    private void UpdatePlaceholder() => PlaceholderText.IsVisible = !Items.Any(i => i.IsSelected);

    private void Filter()
    {
        var term = (Search.Text ?? "").Trim();
        var any = false;
        foreach (var item in Items)
        {
            item.IsMatch = term.Length == 0 || item.Name.Contains(term, StringComparison.OrdinalIgnoreCase);
            any |= item.IsMatch;
        }
        NoMatches.IsVisible = !any;
    }
}
