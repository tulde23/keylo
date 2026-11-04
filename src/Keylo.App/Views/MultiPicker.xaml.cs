using System.Collections;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Keylo.App.ViewModels;

namespace Keylo.App.Views;

/// <summary>
/// Picks any number of <see cref="PickItem"/>s: the chosen ones show as removable chips, and Add
/// opens a searchable checklist of all of them.
/// </summary>
public partial class MultiPicker : UserControl
{
    public static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register(
        nameof(ItemsSource), typeof(IEnumerable), typeof(MultiPicker), new PropertyMetadata(null, (d, e) => ((MultiPicker)d).Attach(e.OldValue, e.NewValue)));

    public static readonly DependencyProperty PlaceholderProperty = DependencyProperty.Register(
        nameof(Placeholder), typeof(string), typeof(MultiPicker), new PropertyMetadata(""));

    public MultiPicker()
    {
        InitializeComponent();
        Dropdown.Opened += (_, _) =>
        {
            // Clicking the button while open would close and immediately reopen it.
            AddButton.IsHitTestVisible = false;
            Search.Text = "";
            Search.Focus();
            Keyboard.Focus(Search);
        };
        Dropdown.Closed += (_, _) => AddButton.IsHitTestVisible = true;
    }

    public IEnumerable? ItemsSource
    {
        get => (IEnumerable?)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    public string Placeholder
    {
        get => (string)GetValue(PlaceholderProperty);
        set => SetValue(PlaceholderProperty, value);
    }

    private IEnumerable<PickItem> Items => ItemsSource?.OfType<PickItem>() ?? [];

    private void Attach(object? oldItems, object? newItems)
    {
        if (oldItems is IEnumerable old)
            foreach (var item in old.OfType<PickItem>()) item.PropertyChanged -= OnItemChanged;
        if (newItems is IEnumerable items)
            foreach (var item in items.OfType<PickItem>()) item.PropertyChanged += OnItemChanged;
        UpdatePlaceholder();
    }

    private void OnItemChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PickItem.IsSelected)) UpdatePlaceholder();
    }

    private void UpdatePlaceholder() =>
        PlaceholderText.Visibility = Items.Any(i => i.IsSelected) ? Visibility.Collapsed : Visibility.Visible;

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        var term = Search.Text.Trim();
        var any = false;
        foreach (var item in Items)
        {
            item.IsMatch = term.Length == 0 || item.Name.Contains(term, StringComparison.OrdinalIgnoreCase);
            any |= item.IsMatch;
        }
        NoMatches.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
    }
}
