using System.Windows;
using System.Windows.Media;
using Wpf.Ui.Controls;

namespace Keylo.App.Views;

/// <summary>What a push will do, for <see cref="PushDialog"/>.</summary>
public sealed record PushConfirmation(
    string ProviderName,
    string SecretName,
    string SecretDetail,
    SymbolRegular SecretSymbol,
    ImageSource? SecretImage,
    Brush SecretTileBrush,
    string Destination,
    string DestinationDetail,
    bool? Exists);

/// <summary>Confirms a push to another vault: from which secret, to which vault and account, new or update.</summary>
public partial class PushDialog : FluentWindow
{
    public PushDialog(PushConfirmation push)
    {
        InitializeComponent();

        Heading.Text = $"Push to {push.ProviderName}";
        ToLabel.Text = $"TO {push.ProviderName.ToUpperInvariant()}";

        SecretName.Text = push.SecretName;
        SecretDetail.Text = push.SecretDetail;
        SecretTile.Symbol = push.SecretSymbol;
        SecretTile.Image = push.SecretImage;
        SecretTile.Fill = push.SecretTileBrush;

        VaultName.Text = push.Destination;
        VaultDetail.Text = push.DestinationDetail;

        // Updating an earlier copy deserves a caution; a new item is routine.
        (StatusIcon.Symbol, StatusText.Text, PushButton.Content) = push.Exists switch
        {
            true => (SymbolRegular.ArrowSync24, $"Updates the “{push.SecretName}” item Keylo pushed there before.", "Update"),
            false => (SymbolRegular.AddCircle24, $"Creates a new item “{push.SecretName}”, tagged keylo.", "Push"),
            null => (SymbolRegular.Info24, $"Creates the item, or updates the one Keylo pushed before.", "Push"),
        };
        var caution = push.Exists == true;
        StatusChip.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, caution ? "SystemFillColorCautionBackgroundBrush" : "SystemFillColorSuccessBackgroundBrush");
        StatusIcon.SetResourceReference(ForegroundProperty, caution ? "SystemFillColorCautionBrush" : "SystemFillColorSuccessBrush");
    }

    private void OnPush(object sender, RoutedEventArgs e) => DialogResult = true;

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
