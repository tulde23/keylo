using System.Windows;
using Keylo.App.ViewModels;
using Wpf.Ui.Controls;

namespace Keylo.App.Views;

public partial class ImportDialog : FluentWindow
{
    private readonly ImportOptionsViewModel _viewModel;

    public ImportDialog(ImportOptionsViewModel viewModel)
    {
        _viewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();
    }

    public ImportOptions? Result { get; private set; }

    private void OnImport(object sender, RoutedEventArgs e)
    {
        if (!_viewModel.CanImport) return;
        Result = _viewModel.ToOptions();
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
