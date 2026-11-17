using Avalonia.Controls;
using Avalonia.Interactivity;
using Keylo.App.ViewModels;

namespace Keylo.Desktop.Views;

public partial class CategoryManagerView : UserControl
{
    public CategoryManagerView() => InitializeComponent();

    /// <summary>The row's tile opens and closes its icon picker.</summary>
    private void OnToggleStyle(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is CategoryRowViewModel row) row.IsEditingStyle = !row.IsEditingStyle;
    }
}
