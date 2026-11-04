using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace Keylo.Desktop.Views;

/// <summary>Keylo's dialog windows: fixed width, sized to content, centred on the main window.</summary>
public class DialogWindow : Window
{
    public DialogWindow()
    {
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Bind(BackgroundProperty, this.GetResourceObservable("BaseFill"));
    }
}

/// <summary>Confirmations and choices: a message and up to three buttons.</summary>
public static class Dialogs
{
    public static async Task<bool> ConfirmAsync(Window owner, string title, string message, string confirmText, bool danger) =>
        await ShowAsync(owner, title, message, confirmText, null, danger) == true;

    /// <summary>true = primary, false = secondary, null = canceled.</summary>
    public static Task<bool?> ChooseAsync(Window owner, string title, string message, string primaryText, string? secondaryText) =>
        ShowAsync(owner, title, message, primaryText, secondaryText, danger: false);

    private static async Task<bool?> ShowAsync(Window owner, string title, string message, string primaryText, string? secondaryText, bool danger)
    {
        var dialog = new DialogWindow { Title = title, Width = 460 };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Spacing = 8, Margin = new Thickness(0, 22, 0, 0) };

        var cancel = new Button { Content = "Cancel", IsCancel = true, Classes = { "big" } };
        cancel.Click += (_, _) => dialog.Close(null);
        buttons.Children.Add(cancel);

        if (secondaryText is not null)
        {
            var secondary = new Button { Content = secondaryText, Classes = { "big" } };
            secondary.Click += (_, _) => dialog.Close(false);
            buttons.Children.Add(secondary);
        }

        var primary = new Button { Content = primaryText, IsDefault = true, Classes = { "big", danger ? "danger" : "accent" } };
        primary.Click += (_, _) => dialog.Close(true);
        buttons.Children.Add(primary);

        var text = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap };
        text.Bind(TextBlock.ForegroundProperty, dialog.GetResourceObservable("TextSecondary"));

        dialog.Content = new StackPanel
        {
            Margin = new Thickness(28, 24),
            Children =
            {
                new TextBlock { Text = title, FontSize = 20, FontWeight = FontWeight.SemiBold, Margin = new Thickness(0, 0, 0, 12) },
                text,
                buttons,
            },
        };
        return await dialog.ShowDialog<bool?>(owner);
    }
}
