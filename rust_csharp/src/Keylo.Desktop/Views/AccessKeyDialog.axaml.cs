using Avalonia.Controls;
using Avalonia.Interactivity;
using Keylo.Core;
using Keylo.Core.Security;

namespace Keylo.Desktop.Views;

/// <summary>The one-time display of a new access key, with the command that registers it with Claude Code.</summary>
public partial class AccessKeyDialog : DialogWindow
{
    private readonly string _token = "";
    private readonly Action<string> _copy = _ => { };

    /// <summary>The keylo CLI next to this app (inside Keylo.app on macOS).</summary>
    private static readonly string KeyloExe = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "keylo.exe" : "keylo");

    public AccessKeyDialog() => InitializeComponent();

    public AccessKeyDialog(string name, string token, Action<string> copy)
    {
        InitializeComponent();
        _token = token;
        _copy = copy;

        Heading.Text = $"“{name}” created";
        TokenText.Text = token;
        CommandText.Text = $"claude mcp add {ClaudeCode.ServerName} --scope user --env {AccessKeys.EnvironmentVariable}={token} -- \"{KeyloExe}\" mcp";

        if (ClaudeCode.FindCli() is null)
        {
            RegisterButton.IsEnabled = false;
            ToolTip.SetTip(RegisterButton, "Claude Code ('claude') wasn't found on PATH.");
            ToolTip.SetShowOnDisabled(RegisterButton, true);
        }
    }

    private void OnCopyKey(object? sender, RoutedEventArgs e)
    {
        _copy(_token);
        Status.Text = "Key copied.";
    }

    private void OnCopyCommand(object? sender, RoutedEventArgs e)
    {
        _copy(CommandText.Text ?? "");
        Status.Text = "Command copied.";
    }

    private async void OnRegister(object? sender, RoutedEventArgs e)
    {
        RegisterButton.IsEnabled = false;
        Status.Text = "Adding Keylo to Claude Code…";
        try
        {
            await ClaudeCode.RegisterAsync(KeyloExe, _token);
            Status.Text = "Added. Restart Claude Code (or run /mcp) to load the Keylo tools.";
        }
        catch (KeyloException ex)
        {
            Status.Text = ex.Message;
            RegisterButton.IsEnabled = true;
        }
    }

    private void OnDone(object? sender, RoutedEventArgs e) => Close();
}
