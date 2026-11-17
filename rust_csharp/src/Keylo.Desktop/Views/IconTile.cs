using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using FluentIcons.Common;
using SymbolIcon = FluentIcons.Avalonia.SymbolIcon;

namespace Keylo.Desktop.Views;

/// <summary>
/// A rounded tile showing, in order of preference: an uploaded image (scaled to fit, clipped to the
/// corners), a symbol, or a letter. Image, Symbol and Fill take the view models' toolkit objects.
/// </summary>
public sealed class IconTile : Border
{
    public static readonly StyledProperty<object?> ImageProperty = AvaloniaProperty.Register<IconTile, object?>(nameof(Image));
    public static readonly StyledProperty<object?> SymbolProperty = AvaloniaProperty.Register<IconTile, object?>(nameof(Symbol));
    public static readonly StyledProperty<string?> TextProperty = AvaloniaProperty.Register<IconTile, string?>(nameof(Text));
    public static readonly StyledProperty<object?> FillProperty = AvaloniaProperty.Register<IconTile, object?>(nameof(Fill));
    public static readonly StyledProperty<double> GlyphSizeProperty = AvaloniaProperty.Register<IconTile, double>(nameof(GlyphSize), 18);

    private readonly SymbolIcon _symbol = new() { Foreground = Brushes.White, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _text = new() { Foreground = Brushes.White, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };

    static IconTile()
    {
        foreach (var property in new AvaloniaProperty[] { ImageProperty, SymbolProperty, TextProperty, FillProperty, GlyphSizeProperty })
            property.Changed.AddClassHandler<IconTile>((tile, _) => tile.Update());
    }

    public IconTile()
    {
        ClipToBounds = true;
        Child = new Panel { Children = { _symbol, _text } };
        Update();
    }

    public object? Image { get => GetValue(ImageProperty); set => SetValue(ImageProperty, value); }
    public object? Symbol { get => GetValue(SymbolProperty); set => SetValue(SymbolProperty, value); }
    public string? Text { get => GetValue(TextProperty); set => SetValue(TextProperty, value); }
    public object? Fill { get => GetValue(FillProperty); set => SetValue(FillProperty, value); }
    public double GlyphSize { get => GetValue(GlyphSizeProperty); set => SetValue(GlyphSizeProperty, value); }

    private void Update()
    {
        if (Image is IImageBrushSource or Bitmap)
        {
            // An ImageBrush on the border is clipped to its rounded corners.
            Background = new ImageBrush((IImageBrushSource)Image) { Stretch = Stretch.Uniform };
            _symbol.IsVisible = _text.IsVisible = false;
            return;
        }

        Background = Fill as IBrush ?? (IBrush?)Application.Current?.FindResource("BrandBrush");
        var symbol = Symbol as Symbol?;
        _symbol.IsVisible = symbol is not null;
        _text.IsVisible = symbol is null && !string.IsNullOrEmpty(Text);
        if (symbol is { } s) _symbol.Symbol = s;
        _symbol.FontSize = GlyphSize;
        _text.FontSize = GlyphSize * 0.85;
        _text.Text = Text;
    }
}
