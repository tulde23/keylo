using CommunityToolkit.Mvvm.ComponentModel;
using Keylo.App.Services;
using Keylo.Core;

namespace Keylo.App.ViewModels;

/// <summary>A row in the secret list.</summary>
public sealed partial class SecretItemViewModel(SecretInfo info, CategoryStyle? categoryStyle = null, SecretTypeDefinition? type = null) : ObservableObject
{
    public const string PinnedGroup = "PINNED";
    public const string RecentGroup = "RECENTLY USED";

    public bool IsPinned { get; set; }

    /// <summary>Pinned or Recently used on Home; null when it's neither.</summary>
    public string? HomeGroup { get; set; }

    /// <summary>Order on Home: pins in pin order, then recent uses newest first.</summary>
    public int HomeRank { get; set; }

    /// <summary>"Claude Code ran it · 2 min ago", for the Home list.</summary>
    public string? RecentText { get; set; }

    /// <summary>What the second line shows: the recent use on Home, the usual details elsewhere.</summary>
    [ObservableProperty] private string? _displaySubtitle;

    /// <summary>"PINNED" or "RECENTLY USED" above the first row of each Home group; null elsewhere.</summary>
    [ObservableProperty] private string? _groupHeader;

    public SecretInfo Info { get; } = info;
    public string Name => Info.Name;
    public string? Category => Info.Category;

    public string Subtitle => string.Join("  ·  ", new[] { type?.Name, Info.Category, Info.Username }.Where(s => !string.IsNullOrEmpty(s)))
        is { Length: > 0 } s ? s : "No category";

    public string Initial => Info.Name[..1].ToUpperInvariant();

    private string? EffectiveIcon => Info.Icon ?? categoryStyle?.Icon ?? type?.Icon;

    /// <summary>An uploaded image icon (own or the category's), shown instead of a symbol.</summary>
    public object? Image => Ui.Host.Image(EffectiveIcon);

    public bool HasImage => Image is not null;

    /// <summary>The secret's own icon, else its category's, else its type's, else none (the initial is shown).</summary>
    public object? Icon => HasImage ? null : Ui.Host.Symbol(EffectiveIcon, null);

    public bool HasIcon => Icon is not null;
    public bool ShowInitial => !HasIcon && !HasImage;

    /// <summary>Own colour, else the category's, else the type's, else a stable colour per name so the list is scannable.</summary>
    public object AvatarBrush => HasImage ? Ui.Host.Transparent
        : Ui.Host.Tile(IconPalette.FirstColor(Info.Color, categoryStyle?.Color, type?.Color) ?? IconPalette.ColorFor(Info.Name));
}

/// <summary>An entry in the category sidebar. <see cref="Key"/> is null for "All" and "" for uncategorized.</summary>
public sealed record CategoryItem(string? Key, string Label, int Count, object? Icon, object? IconBrush = null, object? Image = null)
{
    public bool HasImage => Image is not null;
}
