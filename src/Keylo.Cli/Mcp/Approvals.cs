using System.Text;
using System.Diagnostics;
using Keylo.Core;
using Keylo.Core.Security;

namespace Keylo.Cli.Mcp;

/// <summary>Asks the user whether an agent may use secrets: the Keylo app's approval window on Windows, an alert on macOS.</summary>
internal static class Approvals
{
    // One window at a time: parallel tool calls queue rather than stacking prompts.
    private static readonly SemaphoreSlim OneAtATime = new(1, 1);

    // The window denies by itself after 5 minutes; this is a backstop if it never answers.
    private static readonly TimeSpan Backstop = TimeSpan.FromMinutes(6);

    public static async Task<ApprovalResult> RequestAsync(ApprovalRequest request)
    {
#if !WINDOWS
        await OneAtATime.WaitAsync();
        try
        {
            return await RequestOnMacAsync(request);
        }
        finally
        {
            OneAtATime.Release();
        }
#else

        var app = Path.Combine(AppContext.BaseDirectory, "keylow.exe");
        if (!File.Exists(app)) throw new KeyloException("The Keylo app (keylow.exe) isn't installed next to keylo.exe, so access can't be approved.");

        await OneAtATime.WaitAsync();
        try
        {
            var psi = new ProcessStartInfo(app) { UseShellExecute = false };
            psi.ArgumentList.Add(ApprovalRequest.Argument);
            psi.ArgumentList.Add(request.Encode());
            psi.Environment.Remove(AccessKeys.EnvironmentVariable);

            using var process = Process.Start(psi) ?? throw new KeyloException("Couldn't open the Keylo approval window.");
            using var cts = new CancellationTokenSource(Backstop);
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(); } catch (InvalidOperationException) { }
                return ApprovalResult.Denied;
            }

            return Enum.IsDefined((ApprovalResult)process.ExitCode) ? (ApprovalResult)process.ExitCode : ApprovalResult.Denied;
        }
        finally
        {
            OneAtATime.Release();
        }
#endif
    }

#if !WINDOWS
    /// <summary>
    /// macOS (no Keylo app yet): a native alert from keylo-mac — Deny / Allow once / Always allow —
    /// then Touch ID, as the Windows approval window does with Windows Hello.
    /// </summary>
    private static async Task<ApprovalResult> RequestOnMacAsync(ApprovalRequest request)
    {
        var agent = string.IsNullOrWhiteSpace(request.KeyName) ? "An agent" : request.KeyName;
        var verb = request.GrantOnly ? "permanent access to" : request.Operation == SecretOperation.Get ? "read" : "use";
        var message = new StringBuilder();
        message.AppendLine(string.Join(", ", request.Secrets));
        if (request.Command is { Length: > 0 } command) message.AppendLine().AppendLine($"Command: {command}");
        if (request.Reason is { Length: > 0 } reason) message.AppendLine().AppendLine($"Reason given by the agent: “{reason.Trim()}”");
        if (request.Operation == SecretOperation.Get) message.AppendLine().AppendLine("The value will be shown to the agent.");

        var canAlways = !request.GrantOnly && request.CanAlwaysAllow && request.KeyId is not null;
        var (code, _) = await Keylo.Platform.MacOS.MacHelper.RunAsync(
            ["approve", $"{agent} wants {verb} {(request.Secrets.Count == 1 ? "a secret" : $"{request.Secrets.Count} secrets")}", message.ToString().Trim(), canAlways ? "1" : "0"]);
        var choice = request.GrantOnly && code == (int)ApprovalResult.AllowedOnce ? ApprovalResult.AllowedAlways : (ApprovalResult)code;
        if (choice is not (ApprovalResult.AllowedOnce or ApprovalResult.AllowedAlways)) return ApprovalResult.Denied;

        var config = KeyloConfig.Load();
        try
        {
            await new AccessGate(config, Keylo.Core.Platform.KeyloPlatform.Current.Verifier)
                .ConfirmAsync(IntPtr.Zero, $"Keylo: allow '{request.KeyName}' to {verb} {string.Join(", ", request.Secrets)}");
        }
        catch (KeyloException)
        {
            return ApprovalResult.Denied;
        }

        if (choice == ApprovalResult.AllowedAlways)
        {
            var fresh = KeyloConfig.Load();
            if (!AccessKeys.Grant(fresh, request.KeyId ?? "", request.Secrets)) return ApprovalResult.AllowedOnce;
            fresh.Save();
        }
        return choice;
    }
#endif
}
