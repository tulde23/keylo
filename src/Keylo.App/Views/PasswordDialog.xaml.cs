using System.Windows;
using Keylo.Core;
using Wpf.Ui.Controls;

namespace Keylo.App.Views;

/// <summary>Asks for a backup password: a new one (entered twice, length-checked) or an existing one.</summary>
public partial class PasswordDialog : FluentWindow
{
    private readonly bool _isNew;

    public PasswordDialog(string heading, string message, string okText, bool isNew, string? error = null)
    {
        InitializeComponent();
        _isNew = isNew;
        Heading.Text = heading;
        Message.Text = message;
        OkButton.Content = okText;
        ConfirmPanel.Visibility = isNew ? Visibility.Visible : Visibility.Collapsed;
        Problem.Text = error ?? "";
        Loaded += (_, _) => First.Focus();
    }

    public string? Password { get; private set; }

    private string? Validate()
    {
        var password = First.Password ?? "";
        if (!_isNew) return password.Length == 0 ? "Enter the backup's password." : null;
        return KeyloBackup.CheckPassword(password) ?? (password != (Second.Password ?? "") ? "The passwords don't match." : null);
    }

    private void OnPasswordChanged(object sender, RoutedEventArgs e) => Problem.Text = "";

    private void OnOk(object sender, RoutedEventArgs e)
    {
        if (Validate() is { } problem)
        {
            Problem.Text = problem;
            return;
        }

        Password = First.Password;
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
