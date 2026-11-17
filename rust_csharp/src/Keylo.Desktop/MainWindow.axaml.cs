using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using FluentIcons.Common;
using Keylo.App.Services;
using Keylo.App.ViewModels;
using Keylo.Desktop.Views;
using SymbolIcon = FluentIcons.Avalonia.SymbolIcon;

namespace Keylo.Desktop;

public partial class MainWindow : Window, IUserNotifier
{
    private readonly KeyloService _keylo;
    private readonly MainViewModel _viewModel;
    private readonly UiState _uiState;
    private readonly IReadOnlyList<string> _importPaths;

    /// <summary>"⌘" on macOS, "Ctrl+" elsewhere, for shortcut hints.</summary>
    private static readonly string Mod = OperatingSystem.IsMacOS() ? "⌘" : "Ctrl+";

    public MainWindow(KeyloService keylo, IReadOnlyList<string> importPaths)
    {
        _keylo = keylo;
        _importPaths = importPaths;
        InitializeComponent();

        _viewModel = new MainViewModel(keylo, this);
        DataContext = _viewModel;

        // The window's own buttons live in the top bar: traffic lights top-left on macOS, caption buttons top-right elsewhere.
        if (OperatingSystem.IsMacOS()) Brand.Margin = new Thickness(84, 0, 0, 0);
        else ActionTiles.Margin = new Thickness(14, 0, 148, 0);

        SearchBox.Watermark = $"Search all secrets…   {Mod}K";
        NewTile.SetValue(ToolTip.TipProperty, $"New secret ({Mod}N)");
        LockTile.SetValue(ToolTip.TipProperty, $"Lock ({Mod}L)");
        EmptyHints.Text = $"Values stay encrypted until you reveal or copy them.\n" +
                          $"{(OperatingSystem.IsMacOS() ? "⌘/Shift" : "Ctrl/Shift")} + click selects several · {Mod}A all\n" +
                          $"{Mod}N new · {Mod}F search · {Mod}L lock";
        LockHint.Text = $"Verify with {Ui.Verifier} to see your secrets.";
        UnlockText.Text = $"Unlock with {Ui.Verifier}";

        _uiState = UiState.Load();
        var columns = Body.ColumnDefinitions;
        columns[0].Width = new GridLength(Math.Clamp(_uiState.SidebarWidth, columns[0].MinWidth, columns[0].MaxWidth));
        columns[2].Width = new GridLength(Math.Clamp(_uiState.ListWidth, columns[2].MinWidth, columns[2].MaxWidth));
        SyncTopBar();
        foreach (var column in columns)
            column.PropertyChanged += (_, e) => { if (e.Property == ColumnDefinition.WidthProperty) SyncTopBar(); };

        // Using the app keeps it unlocked: the session slides with keyboard and pointer activity.
        AddHandler(KeyDownEvent, (_, _) => _keylo.NoteActivity(), RoutingStrategies.Tunnel);
        AddHandler(PointerPressedEvent, (_, _) => _keylo.NoteActivity(), RoutingStrategies.Tunnel);
        AddHandler(PointerWheelChangedEvent, (_, _) => _keylo.NoteActivity(), RoutingStrategies.Tunnel);
        AddHandler(PointerMovedEvent, (_, _) => { if (IsActive) _keylo.NoteActivity(); }, RoutingStrategies.Tunnel);
        AddHandler(KeyDownEvent, OnKeyDown, RoutingStrategies.Tunnel);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DropEvent, OnDrop);

        Opened += async (_, _) =>
        {
            Activate();
            await Task.Delay(150); // let the window draw before Touch ID / Windows Hello asks
            await _viewModel.StartAsync();
            if (_importPaths.Count > 0) await _viewModel.ImportAsync(_importPaths);
#if DEBUG
            if (Environment.GetEnvironmentVariable("KEYLO_SNAPSHOTS") is { Length: > 0 } snapshots) await Snapshots.RunAsync(this, _viewModel, snapshots);
#endif
        };
    }

    // ---------------------------------------------------------------- layout

    /// <summary>The top bar's columns follow the sidebar and list widths, so search stays above the list.</summary>
    private void SyncTopBar()
    {
        TopGrid.ColumnDefinitions[0].Width = new GridLength(Body.ColumnDefinitions[0].Width.Value);
        TopGrid.ColumnDefinitions[2].Width = new GridLength(Body.ColumnDefinitions[2].Width.Value);
    }

    private void OnSplitterDragged(object? sender, VectorEventArgs e)
    {
        _uiState.SidebarWidth = Body.ColumnDefinitions[0].ActualWidth;
        _uiState.ListWidth = Body.ColumnDefinitions[2].ActualWidth;
        _uiState.Save();
    }

    /// <summary>Empty parts of the top bar and the lock screen move the window; a double-click zooms it.</summary>
    private void OnDragArea(object? sender, PointerPressedEventArgs e)
    {
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) return;
        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            return;
        }
        BeginMoveDrag(e);
    }

    // ---------------------------------------------------------------- keyboard, list, drop

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        var command = OperatingSystem.IsMacOS() ? KeyModifiers.Meta : KeyModifiers.Control;
        if (e.KeyModifiers == command && !_viewModel.IsLocked)
        {
            switch (e.Key)
            {
                case Key.F or Key.K:
                    _viewModel.IsSettingsOpen = false;
                    SearchBox.Focus();
                    SearchBox.SelectAll();
                    e.Handled = true;
                    return;
                case Key.N:
                    _viewModel.NewSecretCommand.Execute(null);
                    e.Handled = true;
                    return;
                case Key.L:
                    _viewModel.LockCommand.Execute(null);
                    e.Handled = true;
                    return;
            }
        }

        if (e.Key == Key.Escape && _viewModel.Detail is { IsEditing: true } detail)
        {
            detail.CancelCommand.Execute(null);
            e.Handled = true;
        }
        else if (e.Key is Key.Delete or Key.Back && SecretList.IsKeyboardFocusWithin && (e.Key == Key.Delete || e.KeyModifiers == command))
        {
            // Delete from the list (⌘⌫ on a Mac): the selection, always after a confirmation.
            if (_viewModel.IsMultiSelect) _viewModel.DeleteSelectedCommand.Execute(null);
            else _viewModel.Detail?.DeleteCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void OnSecretSelectionChanged(object? sender, SelectionChangedEventArgs e) =>
        _viewModel.UpdateSelection(SecretList.SelectedItems?.OfType<SecretItemViewModel>() ?? []);

    private void OnTogglePin(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is SecretItemViewModel item) _viewModel.TogglePinCommand.Execute(item);
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = !_viewModel.IsLocked && e.DataTransfer.Contains(DataFormat.File) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private async void OnDrop(object? sender, DragEventArgs e)
    {
        var paths = e.DataTransfer.TryGetFiles()?.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
        if (paths is { Count: > 0 }) await _viewModel.ImportAsync(paths);
    }

    // ---------------------------------------------------------------- IUserNotifier

    public void Success(string message) => Toast("Done", message, Symbol.CheckmarkCircle, "Success", 4);

    public void Info(string message) => Toast("Heads up", message, Symbol.Info, "AccentText", 7);

    public void Error(string message) => Toast("Something went wrong", message, Symbol.ErrorCircle, "Critical", 7);

    private void Toast(string title, string message, Symbol symbol, string colorKey, int seconds)
    {
        var toast = new Border
        {
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14, 10),
            MaxWidth = 560,
            BorderThickness = new Thickness(1),
            Child = new DockPanel
            {
                Children =
                {
                    new SymbolIcon { Symbol = symbol, FontSize = 20, Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = Avalonia.Layout.VerticalAlignment.Top },
                    new StackPanel
                    {
                        Children =
                        {
                            new TextBlock { Text = title, FontWeight = FontWeight.SemiBold },
                            new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, FontSize = 12, Margin = new Thickness(0, 2, 0, 0) },
                        },
                    },
                },
            },
        };
        toast.Bind(Border.BackgroundProperty, this.GetResourceObservable("PopupFill"));
        toast.Bind(Border.BorderBrushProperty, this.GetResourceObservable("ControlStroke"));
        ((SymbolIcon)((DockPanel)toast.Child).Children[0]).Bind(ForegroundProperty, this.GetResourceObservable(colorKey));
        toast.Effect = new DropShadowEffect { BlurRadius = 24, OffsetY = 6, Opacity = 0.35, Color = Colors.Black };
        toast.PointerPressed += (_, _) => Toasts.Children.Remove(toast);

        Toasts.Children.Add(toast);
        while (Toasts.Children.Count > 3) Toasts.Children.RemoveAt(0);
        DispatcherTimer.RunOnce(() => Toasts.Children.Remove(toast), TimeSpan.FromSeconds(seconds));
    }

    public Task<bool> ConfirmAsync(string title, string message, string confirmText) =>
        Dialogs.ConfirmAsync(this, title, message, confirmText, danger: true);

    public Task<bool?> ChooseAsync(string title, string message, string primaryText, string? secondaryText) =>
        Dialogs.ChooseAsync(this, title, message, primaryText, secondaryText);

    public async Task<ImportOptions?> AskImportOptionsAsync(ImportOptionsViewModel options) =>
        await new ImportDialog(options).ShowDialog<ImportOptions?>(this);

    public async Task<string?> AskPasswordAsync(string heading, string message, string okText, bool isNew, string? error = null) =>
        await new PasswordDialog(heading, message, okText, isNew, error).ShowDialog<string?>(this);

    public async Task<bool> ConfirmPushAsync(PushConfirmation push) => await new PushDialog(push).ShowDialog<bool>(this);

    public async Task<string?> LinkSecretAsync()
    {
        var dialog = new LinkDialog(_keylo);
        await dialog.ShowDialog(this);
        return dialog.CreatedName is null ? null : dialog.LinkedCount > 1 ? $"{dialog.CreatedName}|{dialog.LinkedCount}" : dialog.CreatedName;
    }

    public Task ShowAccessKeyAsync(string name, string token) => new AccessKeyDialog(name, token, _keylo.CopyToClipboard).ShowDialog(this);
}
