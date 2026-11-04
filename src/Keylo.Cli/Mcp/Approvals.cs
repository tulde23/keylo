using System.Diagnostics;
using Keylo.Core;
using Keylo.Core.Security;

namespace Keylo.Cli.Mcp;

/// <summary>Asks the user, in a Keylo app window (keylow --approve), whether an agent may use secrets.</summary>
internal static class Approvals
{
    // One window at a time: parallel tool calls queue rather than stacking prompts.
    private static readonly SemaphoreSlim OneAtATime = new(1, 1);

    // The window denies by itself after 5 minutes; this is a backstop if it never answers.
    private static readonly TimeSpan Backstop = TimeSpan.FromMinutes(6);

    public static async Task<ApprovalResult> RequestAsync(ApprovalRequest request)
    {
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
    }
}
