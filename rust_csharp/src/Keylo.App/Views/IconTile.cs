using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Wpf.Ui.Controls;
using TextBlock = System.Windows.Controls.TextBlock;

namespace Keylo.App.Views;

/// <summary>
/// A rounded tile showing, in order of preference: an uploaded image (scaled to fit the tile,
/// high-quality resampling, clipped to the corners), a symbol, or a letter.
/// </summary>
public sealed class IconTile : Border
{
    public static readonly DependencyProperty ImageProperty = Register<ImageSource?>(nameof(Image));
    public static readonly DependencyProperty SymbolProperty = Register<SymbolRegular?>(nameof(Symbol));
    public static readonly DependencyProperty TextProperty = Register<string?>(nameof(Text));
    public static readonly DependencyProperty FillProperty = Register<Brush?>(nameof(Fill));
    public static readonly DependencyProperty GlyphSizeProperty = Register<double>(nameof(GlyphSize), 18.0);

    private readonly SymbolIcon _symbol = new() { Foreground = Brushes.White, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _text = new() { Foreground = Brushes.White, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };

    public IconTile()
    {
        RenderOptions.SetBitmapScalingMode(this, BitmapScalingMode.HighQuality);
        Child = new Grid { Children = { _symbol, _text } };
        Update();
    }

    public ImageSource? Image { get => (ImageSource?)GetValue(ImageProperty); set => SetValue(ImageProperty, value); }
    public SymbolRegular? Symbol { get => (SymbolRegular?)GetValue(SymbolProperty); set => SetValue(SymbolProperty, value); }
    public string? Text { get => (string?)GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public Brush? Fill { get => (Brush?)GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public double GlyphSize { get => (double)GetValue(GlyphSizeProperty); set => SetValue(GlyphSizeProperty, value); }

    private void Update()
    {
        if (Image is { } image)
        {
            // An ImageBrush on the border is clipped to its rounded corners, unlike a child Image.
            var brush = new ImageBrush(image) { Stretch = Stretch.Uniform };
            brush.Freeze();
            Background = brush;
            _symbol.Visibility = _text.Visibility = Visibility.Collapsed;
            return;
        }

        Background = Fill;
        var showSymbol = Symbol is { } s && s != SymbolRegular.Empty;
        _symbol.Visibility = showSymbol ? Visibility.Visible : Visibility.Collapsed;
        _text.Visibility = showSymbol ? Visibility.Collapsed : Visibility.Visible;
        if (showSymbol) _symbol.Symbol = Symbol!.Value;
        _symbol.FontSize = GlyphSize;
        _text.FontSize = GlyphSize * 0.85;
        _text.Text = Text;
    }

    private static DependencyProperty Register<T>(string name, object? defaultValue = null) =>
        DependencyProperty.Register(name, typeof(T), typeof(IconTile),
            new FrameworkPropertyMetadata(defaultValue, (d, _) => ((IconTile)d).Update()));
}
