using Avalonia.Controls;
using Avalonia.Interactivity;
using FluentIcons.Common;
using Keylo.App.ViewModels;

namespace Keylo.Desktop.Views;

/// <summary>Confirms a push to another vault: from which secret, to which vault and account, new or update. Closes with true to push.</summary>
public partial class PushDialog : DialogWindow
{
    public PushDialog() => InitializeComponent();

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
        (StatusIcon.Symbol, StatusText.Text, PushText.Text) = push.Exists switch
        {
            true => (Symbol.ArrowSync, $"Updates the “{push.SecretName}” item Keylo pushed there before.", "Update"),
            false => (Symbol.AddCircle, $"Creates a new item “{push.SecretName}”, tagged keylo.", "Push"),
            null => (Symbol.Info, "Creates the item, or updates the one Keylo pushed before.", "Push"),
        };
        var caution = push.Exists == true;
        StatusChip.Bind(Border.BackgroundProperty, this.GetResourceObservable(caution ? "CautionBg" : "SuccessBg"));
        StatusIcon.Bind(ForegroundProperty, this.GetResourceObservable(caution ? "Caution" : "Success"));
    }

    private void OnPush(object? sender, RoutedEventArgs e) => Close(true);

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);
}
