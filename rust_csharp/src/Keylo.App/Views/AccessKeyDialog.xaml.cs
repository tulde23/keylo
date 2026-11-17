using System.IO;
using System.Windows;
using Keylo.Core;
using Keylo.Core.Security;
using Wpf.Ui.Controls;

namespace Keylo.App.Views;

/// <summary>The one-time display of a new access key, with the command that registers it with Claude Code.</summary>
public partial class AccessKeyDialog : FluentWindow
{
    private readonly string _token;
    private readonly Action<string> _copy;
    private readonly string _keyloExe = Path.Combine(AppContext.BaseDirectory, "keylo.exe");

    public AccessKeyDialog(string name, string token, Action<string> copy)
    {
        InitializeComponent();
        _token = token;
        _copy = copy;

        Heading.Text = $"“{name}” created";
        TokenText.Text = token;
        CommandText.Text = $"claude mcp add {ClaudeCode.ServerName} --scope user --env {AccessKeys.EnvironmentVariable}={token} -- \"{_keyloExe}\" mcp";

        if (ClaudeCode.FindCli() is null)
        {
            RegisterButton.IsEnabled = false;
            RegisterButton.ToolTip = "Claude Code ('claude') wasn't found on PATH.";
        }
    }

    private void OnCopyKey(object sender, RoutedEventArgs e)
    {
        _copy(_token);
        Status.Text = "Key copied.";
    }

    private void OnCopyCommand(object sender, RoutedEventArgs e)
    {
        _copy(CommandText.Text);
        Status.Text = "Command copied.";
    }

    private async void OnRegister(object sender, RoutedEventArgs e)
    {
        RegisterButton.IsEnabled = false;
        Status.Text = "Adding Keylo to Claude Code…";
        try
        {
            await ClaudeCode.RegisterAsync(_keyloExe, _token);
            Status.Text = "Added. Restart Claude Code (or run /mcp) to load the Keylo tools.";
        }
        catch (KeyloException ex)
        {
            Status.Text = ex.Message;
            RegisterButton.IsEnabled = true;
        }
    }

    private void OnDone(object sender, RoutedEventArgs e) => Close();
}
