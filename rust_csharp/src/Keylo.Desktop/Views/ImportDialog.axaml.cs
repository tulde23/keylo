using Avalonia.Interactivity;
using Keylo.App.ViewModels;

namespace Keylo.Desktop.Views;

/// <summary>Import options: category, overwrite, and each file's name and type. Closes with the options, or null.</summary>
public partial class ImportDialog : DialogWindow
{
    private readonly ImportOptionsViewModel? _viewModel;

    public ImportDialog() => InitializeComponent();

    public ImportDialog(ImportOptionsViewModel viewModel)
    {
        _viewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();
    }

    private void OnImport(object? sender, RoutedEventArgs e)
    {
        if (_viewModel is { CanImport: true }) Close(_viewModel.ToOptions());
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(null);
}
