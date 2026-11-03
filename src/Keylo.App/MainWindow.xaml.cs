using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using Keylo.App.Services;
using Keylo.App.ViewModels;
using Wpf.Ui;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Keylo.App;

public partial class MainWindow : FluentWindow, IUserNotifier
{
    private readonly KeyloService _keylo;
    private readonly SnackbarService _snackbar = new();
    private readonly MainViewModel _viewModel;
    private readonly UiState _uiState;

    public MainWindow(KeyloService keylo, IReadOnlyList<string> importPaths)
    {
        _keylo = keylo;
        InitializeComponent();

        // Follow Windows light/dark, but keep Keylo's own accent rather than the system one.
        ApplicationThemeManager.ApplySystemTheme(updateAccent: false);
        ApplyBrandAccent(ApplicationThemeManager.GetAppTheme());
        ApplicationThemeManager.Changed += (theme, _) => ApplyBrandAccent(theme);
        SystemThemeWatcher.Watch(this, WindowBackdropType.Mica, updateAccents: false);

        _snackbar.SetSnackbarPresenter(Snackbar);
        _viewModel = new MainViewModel(keylo, this);
        DataContext = _viewModel;

        _uiState = UiState.Load();
        SidebarColumn.Width = new GridLength(Math.Clamp(_uiState.SidebarWidth, SidebarColumn.MinWidth, SidebarColumn.MaxWidth));
        ListColumn.Width = new GridLength(Math.Clamp(_uiState.ListWidth, ListColumn.MinWidth, ListColumn.MaxWidth));

        SourceInitialized += (_, _) => _keylo.WindowHandle = new WindowInteropHelper(this).Handle;
        // Ask for Windows Hello only once this window is drawn and in front. Prompting from Loaded
        // let the window appear on top of the Hello dialog, leaving the lock screen spinning.
        ContentRendered += async (_, _) =>
        {
            Activate();
            await System.Windows.Threading.Dispatcher.Yield(System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            await _viewModel.StartAsync();
            if (importPaths.Count > 0) await _viewModel.ImportAsync(importPaths);
        };
        PreviewKeyDown += OnPreviewKeyDown;
        DragOver += OnDragOver;
        Drop += OnDrop;
    }

    private static void ApplyBrandAccent(ApplicationTheme theme) =>
        ApplicationAccentColorManager.Apply(System.Windows.Media.Color.FromRgb(0x6D, 0x6A, 0xF6), theme);

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control && !_viewModel.IsLocked)
        {
            _viewModel.IsSettingsOpen = false;
            SearchBox.Focus();
            SearchBox.SelectAll();
            e.Handled = true;
        }
        else if (e.Key == Key.Escape && _viewModel.Detail is { IsEditing: true } detail)
        {
            detail.CancelCommand.Execute(null);
            e.Handled = true;
        }
        else if (e.Key == Key.Delete && SecretList.IsKeyboardFocusWithin)
        {
            // Delete from the list: the selection (one or many), always after a confirmation.
            if (_viewModel.IsMultiSelect) _viewModel.DeleteSelectedCommand.Execute(null);
            else _viewModel.Detail?.DeleteCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void OnSecretSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) =>
        _viewModel.UpdateSelection(SecretList.SelectedItems.OfType<SecretItemViewModel>());

    private void OnSplitterDragged(object sender, System.Windows.Controls.Primitives.DragCompletedEventArgs e)
    {
        _uiState.SidebarWidth = SidebarColumn.ActualWidth;
        _uiState.ListWidth = ListColumn.ActualWidth;
        _uiState.Save();
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = !_viewModel.IsLocked && e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths)
            await _viewModel.ImportAsync(paths);
    }

    public void Success(string message) =>
        _snackbar.Show("Done", message, ControlAppearance.Success, new SymbolIcon(SymbolRegular.CheckmarkCircle24), TimeSpan.FromSeconds(4));

    public void Info(string message) =>
        _snackbar.Show("Heads up", message, ControlAppearance.Info, new SymbolIcon(SymbolRegular.Info24), TimeSpan.FromSeconds(7));

    public void Error(string message) =>
        _snackbar.Show("Something went wrong", message, ControlAppearance.Danger, new SymbolIcon(SymbolRegular.ErrorCircle24), TimeSpan.FromSeconds(7));

    public ImportOptions? AskImportOptions(ImportOptionsViewModel options)
    {
        var dialog = new Views.ImportDialog(options) { Owner = this };
        return dialog.ShowDialog() == true ? dialog.Result : null;
    }

    public string? AskPassword(string heading, string message, string okText, bool isNew, string? error = null)
    {
        var dialog = new Views.PasswordDialog(heading, message, okText, isNew, error) { Owner = this };
        return dialog.ShowDialog() == true ? dialog.Password : null;
    }

    public async Task<bool?> ChooseAsync(string title, string message, string primaryText, string? secondaryText)
    {
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = title,
            Content = message,
            PrimaryButtonText = primaryText,
            PrimaryButtonAppearance = ControlAppearance.Primary,
            CloseButtonText = "Cancel",
            Owner = this,
        };
        if (secondaryText is not null)
        {
            box.SecondaryButtonText = secondaryText;
            box.IsSecondaryButtonEnabled = true;
        }

        return await box.ShowDialogAsync() switch
        {
            Wpf.Ui.Controls.MessageBoxResult.Primary => true,
            Wpf.Ui.Controls.MessageBoxResult.Secondary => false,
            _ => null,
        };
    }

    public async Task<bool> ConfirmAsync(string title, string message, string confirmText)
    {
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = title,
            Content = message,
            PrimaryButtonText = confirmText,
            PrimaryButtonAppearance = ControlAppearance.Danger,
            CloseButtonText = "Cancel",
            Owner = this,
        };
        return await box.ShowDialogAsync() == Wpf.Ui.Controls.MessageBoxResult.Primary;
    }
}
