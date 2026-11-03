using System.Windows.Media;
using Keylo.Core;
using Wpf.Ui.Controls;

namespace Keylo.App.ViewModels;

/// <summary>A row in the secret list.</summary>
public sealed class SecretItemViewModel(SecretInfo info, CategoryStyle? categoryStyle = null)
{
    private static readonly Color[] Palette = IconCatalog.Colors.Select(c => IconCatalog.ToColor(c)!.Value).ToArray();

    public SecretInfo Info { get; } = info;
    public string Name => Info.Name;
    public string? Category => Info.Category;

    public string Subtitle => string.Join("  ·  ", new[] { Info.Category, Info.Username }.Where(s => !string.IsNullOrEmpty(s)))
        is { Length: > 0 } s ? s : "No category";

    public string Initial => Info.Name[..1].ToUpperInvariant();

    private string? EffectiveIcon => Info.Icon ?? categoryStyle?.Icon;

    /// <summary>An uploaded image icon (own or the category's), shown instead of a symbol.</summary>
    public ImageSource? Image => IconImages.Load(EffectiveIcon);

    public bool HasImage => Image is not null;

    /// <summary>The secret's own icon, else its category's, else none (the initial is shown).</summary>
    public SymbolRegular? Icon =>
        !HasImage && IconCatalog.ToSymbol(EffectiveIcon, SymbolRegular.Empty) is var s && s != SymbolRegular.Empty ? s : null;

    public bool HasIcon => Icon is not null;
    public bool ShowInitial => !HasIcon && !HasImage;

    /// <summary>Own colour, else the category's, else a stable colour per name so the list is scannable.</summary>
    public Brush AvatarBrush
    {
        get
        {
            if (HasImage) return Brushes.Transparent;
            var color = IconCatalog.ToColor(Info.Color) ?? IconCatalog.ToColor(categoryStyle?.Color);
            if (color is null)
            {
                var hash = Info.Name.ToLowerInvariant().Aggregate(17, (h, c) => unchecked(h * 31 + c));
                color = Palette[(hash & 0x7fffffff) % Palette.Length];
            }
            return IconCatalog.Tile(color.Value);
        }
    }
}

/// <summary>An entry in the category sidebar. <see cref="Key"/> is null for "All" and "" for uncategorized.</summary>
public sealed record CategoryItem(string? Key, string Label, int Count, SymbolRegular Icon, Brush? IconBrush = null, ImageSource? Image = null)
{
    public bool HasImage => Image is not null;
}
