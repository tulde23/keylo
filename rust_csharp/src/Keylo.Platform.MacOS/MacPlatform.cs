using System.Diagnostics;
using Keylo.Core.Platform;
using Keylo.Core.Security;

namespace Keylo.Platform.MacOS;

/// <summary>Touch ID (or Apple Watch / password) through LocalAuthentication, via keylo-mac.</summary>
public sealed class TouchIdVerifier : IUserVerifier
{
    public async Task<(VerificationResult Result, string? Detail)> VerifyAsync(IntPtr ownerWindow, string message)
    {
        // The system prompt reads "<app> is trying to <reason>", so drop Keylo's "Keylo: " prefix.
        var reason = message.StartsWith("Keylo: ", StringComparison.Ordinal) ? message[7..] : message;
        var (code, output) = await MacHelper.RunAsync(["auth", reason]);
        return code switch
        {
            0 => (VerificationResult.Verified, null),
            1 => (VerificationResult.Canceled, null),
            2 => (VerificationResult.Unavailable, output.Length > 0 ? output : "no Touch ID, Apple Watch or password available"),
            _ => (VerificationResult.Failed, output.Length > 0 ? output : null),
        };
    }
}

/// <summary>
/// The general pasteboard, marked org.nspasteboard.ConcealedType and TransientType so clipboard
/// managers and Universal Clipboard history skip it. The token is the pasteboard's change count.
/// </summary>
public sealed class MacClipboard : ISecureClipboard
{
    public uint SetText(string text)
    {
        var (code, output) = MacHelper.Run(["copy"], text);
        if (code != 0 || !uint.TryParse(output, out var changeCount))
            throw new Keylo.Core.KeyloException("Couldn't copy to the clipboard.");
        return changeCount;
    }

    public bool ClearIfUnchanged(uint token) => MacHelper.Run(["clear", token.ToString()]).Code == 0;
}

/// <summary>The parent chain from <c>ps</c>: one call per ancestor for its parent pid and command name.</summary>
public sealed class MacProcessAncestry : IProcessAncestry
{
    public IReadOnlyList<AncestorProcess> Current(int maxDepth = 12)
    {
        var chain = new List<AncestorProcess>();
        var next = Row(Environment.ProcessId)?.ParentPid;
        while (next is > 1 && chain.Count < maxDepth && Row(next.Value) is { } row)
        {
            chain.Add(new AncestorProcess(next.Value, row.Name));
            next = row.ParentPid;
        }
        return chain;
    }

    /// <summary><c>ps -o ppid=,ucomm= -p PID</c> → (parent pid, command name).</summary>
    private static (int ParentPid, string Name)? Row(int pid)
    {
        try
        {
            var psi = new ProcessStartInfo("/bin/ps") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in (string[])["-o", "ppid=,ucomm=", "-p", pid.ToString()]) psi.ArgumentList.Add(arg);
            using var ps = Process.Start(psi)!;
            var line = ps.StandardOutput.ReadToEnd().Trim();
            ps.WaitForExit();

            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return parts.Length == 2 && int.TryParse(parts[0], out var ppid) ? (ppid, parts[1]) : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }
}

/// <summary>Keylo on macOS: the login keychain, Touch ID, a concealed pasteboard, and ps for process info.</summary>
public sealed class MacPlatform : IKeyloPlatform
{
    public MacPlatform()
    {
        // KEYLO_KEYCHAIN: a specific keychain file instead of the login keychain (tests, SSH sessions).
        var keychain = Environment.GetEnvironmentVariable("KEYLO_KEYCHAIN");
        Credentials = new KeychainCredentialStore(keychainPath: keychain);
        // The master key sits under its own service so it never shows up among secrets.
        DataProtector = new KeychainDataProtector(new KeychainCredentialStore(KeychainCredentialStore.DefaultService + ".Internal", keychain));
    }

    public string Name => "macOS";
    public string VerifierName => "Touch ID";
    public string StoreName => "macOS Keychain";
    public string FileProtectionName => "Keychain key";
    public ICredentialStore Credentials { get; }
    public IDataProtector DataProtector { get; }
    public IUserVerifier Verifier { get; } = new TouchIdVerifier();
    public ISecureClipboard Clipboard { get; } = new MacClipboard();
    public IProcessAncestry Processes { get; } = new MacProcessAncestry();

    /// <summary>Makes macOS the platform for this process. Call once at startup.</summary>
    public static void Install() => KeyloPlatform.Install(new MacPlatform());
}
