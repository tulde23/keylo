using System.Windows;
using System.Windows.Controls;
using Wpf.Ui.Controls;

namespace Keylo.App.Views;

/// <summary>Colour swatches and an icon grid. <see cref="Icon"/> and <see cref="Color"/> bind two-way; null means default.</summary>
public partial class IconPicker : UserControl
{
    public static readonly DependencyProperty IconProperty = DependencyProperty.Register(
        nameof(Icon), typeof(string), typeof(IconPicker),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, (d, _) => ((IconPicker)d).SyncSelection()));

    public static readonly DependencyProperty ColorProperty = DependencyProperty.Register(
        nameof(Color), typeof(string), typeof(IconPicker),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, (d, _) => ((IconPicker)d).SyncSelection()));

    private bool _syncing;

    public IconPicker()
    {
        InitializeComponent();
        IconList.ItemsSource = IconCatalog.Icons;
        ColorList.ItemsSource = IconCatalog.Colors;
    }

    public string? Icon
    {
        get => (string?)GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }

    public string? Color
    {
        get => (string?)GetValue(ColorProperty);
        set => SetValue(ColorProperty, value);
    }

    private void SyncSelection()
    {
        _syncing = true;
        IconList.SelectedItem = Enum.TryParse<SymbolRegular>(Icon, out var symbol) && IconCatalog.Icons.Contains(symbol) ? symbol : null;
        ColorList.SelectedItem = IconCatalog.Colors.FirstOrDefault(c => string.Equals(c, Color, StringComparison.OrdinalIgnoreCase));

        var image = IconImages.Load(Icon);
        UploadedPreview.Background = image is null ? null : new System.Windows.Media.ImageBrush(image) { Stretch = System.Windows.Media.Stretch.Uniform };
        UploadedPreview.Visibility = image is null ? Visibility.Collapsed : Visibility.Visible;
        _syncing = false;
    }

    private void OnUpload(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose an icon image",
            Filter = "Images|*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.ico;*.tif;*.tiff|All files|*.*",
        };
        if (dialog.ShowDialog(Window.GetWindow(this)) != true) return;

        try
        {
            Icon = IconImages.Import(dialog.FileName);
        }
        catch (Core.KeyloException ex)
        {
            System.Windows.MessageBox.Show(Window.GetWindow(this), ex.Message, "Keylo", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnIconChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && IconList.SelectedItem is SymbolRegular symbol) Icon = symbol.ToString();
    }

    private void OnColorChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_syncing && ColorList.SelectedItem is string color) Color = color;
    }

    private void OnReset(object sender, RoutedEventArgs e)
    {
        Icon = null;
        Color = null;
    }
}
