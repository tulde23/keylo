using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using Keylo.Core;
using Keylo.Core.Security;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace Keylo.App.Views;

/// <summary>
/// Shown by <c>keylow --approve</c> when an agent (via keylo mcp) wants secrets its access key
/// doesn't cover. Allowing needs Windows Hello; the answer is the process exit code.
/// </summary>
public partial class ApprovalWindow : FluentWindow
{
    private static readonly TimeSpan AutoDeny = TimeSpan.FromMinutes(5);

    private readonly ApprovalRequest _request;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DateTime _deadline = DateTime.Now + AutoDeny;
    private bool _busy;

    public ApprovalWindow(ApprovalRequest request)
    {
        InitializeComponent();
        _request = request;

        ApplicationThemeManager.ApplySystemTheme(updateAccent: false);
        ApplicationAccentColorManager.Apply(System.Windows.Media.Color.FromRgb(0x6D, 0x6A, 0xF6), ApplicationThemeManager.GetAppTheme());

        var agent = string.IsNullOrWhiteSpace(request.KeyName) ? "An agent" : request.KeyName;
        var many = request.Secrets.Count > 1;
        Heading.Text = request.GrantOnly
            ? $"{agent} asks for permanent access"
            : $"{agent} wants to {(request.Operation == SecretOperation.Get ? "read" : "use")} {(many ? $"{request.Secrets.Count} secrets" : "a secret")}";
        Subheading.Text = "Via Keylo's MCP server, using its access key";
        ActionLabel.Text = request.GrantOnly ? "ADD TO ITS ACCESS KEY"
            : request.Operation == SecretOperation.Get ? "SHOW THE VALUE OF" : "PASS TO A COMMAND AS ENVIRONMENT VARIABLES";
        SecretList.ItemsSource = request.Secrets;

        CommandText.Text = request.Command ?? "";
        CommandPanel.Visibility = string.IsNullOrWhiteSpace(request.Command) ? Visibility.Collapsed : Visibility.Visible;
        ReasonText.Text = string.IsNullOrWhiteSpace(request.Reason) ? "" : $"“{request.Reason.Trim()}”";
        ReasonPanel.Visibility = string.IsNullOrWhiteSpace(request.Reason) ? Visibility.Collapsed : Visibility.Visible;
        GetWarning.Visibility = request.Operation == SecretOperation.Get ? Visibility.Visible : Visibility.Collapsed;

        if (request.GrantOnly)
        {
            OnceButton.Content = "Add to key";
            AlwaysButton.Visibility = Visibility.Collapsed;
        }
        else
        {
            // keylo mcp remembers an approval for the Hello session length.
            var minutes = KeyloConfig.Load().SessionMinutes;
            OnceButton.Content = $"Allow for {minutes} min";
            OnceButton.ToolTip = $"The agent can use {(many ? "these secrets" : "this secret")} again for {minutes} minutes without asking.";
            AlwaysButton.Content = "Always allow";
            AlwaysButton.ToolTip = $"Allow now and add {(many ? "these secrets" : "this secret")} to the access key '{request.KeyName}', so it won't ask again.";
            AlwaysButton.Visibility = request.CanAlwaysAllow && request.KeyId is not null ? Visibility.Visible : Visibility.Collapsed;
        }

        _timer.Tick += (_, _) => Tick();
        Loaded += (_, _) =>
        {
            Tick();
            _timer.Start();
            Activate();
            DenyButton.Focus();
        };
        Closing += (_, _) => Result ??= ApprovalResult.Denied;
    }

    public ApprovalResult? Result { get; private set; }

    private void Tick()
    {
        var left = _deadline - DateTime.Now;
        if (left <= TimeSpan.Zero && !_busy) Finish(ApprovalResult.Denied);
        Countdown.Text = $"Denies automatically in {Math.Max(0, (int)left.TotalMinutes)}:{Math.Max(0, left.Seconds):00}";
    }

    private void OnDeny(object sender, RoutedEventArgs e) => Finish(ApprovalResult.Denied);

    private async void OnOnce(object sender, RoutedEventArgs e) =>
        await AllowAsync(_request.GrantOnly ? ApprovalResult.AllowedAlways : ApprovalResult.AllowedOnce);

    private async void OnAlways(object sender, RoutedEventArgs e) => await AllowAsync(ApprovalResult.AllowedAlways);

    private async Task AllowAsync(ApprovalResult result)
    {
        if (_busy) return;
        _busy = true;
        SetButtonsEnabled(false);
        Problem.Text = "Confirm with Windows Hello…";

        try
        {
            var config = KeyloConfig.Load();
            var gate = new AccessGate(config, new WindowsHelloVerifier());
            var what = result == ApprovalResult.AllowedAlways
                ? $"Keylo: give '{_request.KeyName}' lasting access to {string.Join(", ", _request.Secrets)}"
                : $"Keylo: allow '{_request.KeyName}' to {(_request.Operation == SecretOperation.Get ? "read" : "use")} {string.Join(", ", _request.Secrets)}";
            await gate.ConfirmAsync(new WindowInteropHelper(this).Handle, what);

            if (result == ApprovalResult.AllowedAlways)
            {
                // Reload right before writing, so changes made meanwhile (e.g. in Settings) aren't lost.
                var fresh = KeyloConfig.Load();
                if (!AccessKeys.Grant(fresh, _request.KeyId ?? "", _request.Secrets))
                    throw new KeyloException("That access key no longer exists (it was revoked).");
                fresh.Save();
            }

            Finish(result);
        }
        catch (KeyloException ex)
        {
            Problem.Text = ex.Message;
            SetButtonsEnabled(true);
            _busy = false;
        }
    }

    private void SetButtonsEnabled(bool enabled) => DenyButton.IsEnabled = OnceButton.IsEnabled = AlwaysButton.IsEnabled = enabled;

    private void Finish(ApprovalResult result)
    {
        Result = result;
        _timer.Stop();
        Close();
    }
}
