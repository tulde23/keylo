using System.Windows;
using System.Windows.Controls;
using Keylo.App.ViewModels;

namespace Keylo.App.Views;

public partial class CategoryManagerView : UserControl
{
    public CategoryManagerView() => InitializeComponent();

    private void OnToggleStyle(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CategoryRowViewModel row }) row.IsEditingStyle = !row.IsEditingStyle;
    }
}
