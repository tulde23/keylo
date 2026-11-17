using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Interactivity;
using Avalonia.Media;
using FluentIcons.Common;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.Desktop.Views;

/// <summary>Colour swatches and an icon grid. <see cref="Icon"/> and <see cref="Color"/> bind two-way; null means default.</summary>
public partial class IconPicker : UserControl
{
    public static readonly StyledProperty<string?> IconProperty =
        AvaloniaProperty.Register<IconPicker, string?>(nameof(Icon), defaultBindingMode: BindingMode.TwoWay);

    public static readonly StyledProperty<string?> ColorProperty =
        AvaloniaProperty.Register<IconPicker, string?>(nameof(Color), defaultBindingMode: BindingMode.TwoWay);

    /// <summary>The palette's icons as FluentIcons symbols, keyed back to the stored (WPF-UI) names.</summary>
    private static readonly IReadOnlyList<(string Name, Symbol Symbol)> Choices =
        IconPalette.Icons.Select(n => (n, Icons.Find(n))).Where(c => c.Item2 is not null).Select(c => (c.n, c.Item2!.Value)).ToList();

    private bool _syncing;

    static IconPicker()
    {
        IconProperty.Changed.AddClassHandler<IconPicker>((p, _) => p.SyncSelection());
        ColorProperty.Changed.AddClassHandler<IconPicker>((p, _) => p.SyncSelection());
    }

    public IconPicker()
    {
        InitializeComponent();
        IconList.ItemsSource = Choices.Select(c => c.Symbol).ToList();
        ColorList.ItemsSource = IconPalette.Colors;
    }

    public string? Icon { get => GetValue(IconProperty); set => SetValue(IconProperty, value); }
    public string? Color { get => GetValue(ColorProperty); set => SetValue(ColorProperty, value); }

    private void SyncSelection()
    {
        _syncing = true;
        var chosen = Choices.FirstOrDefault(c => string.Equals(c.Name, Icon, StringComparison.OrdinalIgnoreCase));
        IconList.SelectedItem = chosen.Name is null ? null : chosen.Symbol;
        ColorList.SelectedItem = IconPalette.Colors.FirstOrDefault(c => string.Equals(c, Color, StringComparison.OrdinalIgnoreCase));

        var image = Ui.Host.Image(Icon) as IImageBrushSource;
        UploadedPreview.Background = image is null ? null : new ImageBrush(image) { Stretch = Stretch.Uniform };
        UploadedPreview.IsVisible = image is not null;
        _syncing = false;
    }

    private async void OnUpload(object? sender, RoutedEventArgs e)
    {
        var files = await Ui.Host.PickFilesAsync("Choose an icon image", multiple: false,
            new FileFilter("Images", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp"));
        if (files.Count == 0) return;

        UploadError.IsVisible = false;
        try
        {
            Icon = IconImages.Import(files[0]);
        }
        catch (KeyloException ex)
        {
            UploadError.Text = ex.Message;
            UploadError.IsVisible = true;
        }
    }

    private void OnIconChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && IconList.SelectedItem is Symbol symbol)
            Icon = Choices.First(c => c.Symbol == symbol).Name;
    }

    private void OnColorChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && ColorList.SelectedItem is string color) Color = color;
    }

    private void OnReset(object? sender, RoutedEventArgs e)
    {
        Icon = null;
        Color = null;
    }
}
