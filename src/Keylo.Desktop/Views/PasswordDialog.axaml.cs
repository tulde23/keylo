using Avalonia.Interactivity;
using Keylo.Core;

namespace Keylo.Desktop.Views;

/// <summary>Asks for a backup password: a new one (entered twice, length-checked) or an existing one. Closes with it, or null.</summary>
public partial class PasswordDialog : DialogWindow
{
    private readonly bool _isNew;

    public PasswordDialog() : this("", "", "OK", false) { }

    public PasswordDialog(string heading, string message, string okText, bool isNew, string? error = null)
    {
        InitializeComponent();
        _isNew = isNew;
        Heading.Text = heading;
        Message.Text = message;
        OkButton.Content = okText;
        ConfirmPanel.IsVisible = isNew;
        Problem.Text = error ?? "";
        First.TextChanged += (_, _) => Problem.Text = "";
        Second.TextChanged += (_, _) => Problem.Text = "";
        Opened += (_, _) => First.Focus();
    }

    private string? Validate()
    {
        var password = First.Text ?? "";
        if (!_isNew) return password.Length == 0 ? "Enter the backup's password." : null;
        return KeyloBackup.CheckPassword(password) ?? (password != (Second.Text ?? "") ? "The passwords don't match." : null);
    }

    private void OnOk(object? sender, RoutedEventArgs e)
    {
        if (Validate() is { } problem)
        {
            Problem.Text = problem;
            return;
        }
        Close(First.Text);
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(null);
}
