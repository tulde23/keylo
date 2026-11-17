using Keylo.Core.Platform;

namespace Keylo.Core.Security;

public sealed record AncestorProcess(int ProcessId, string ExecutableName);

/// <summary>
/// The chain of processes that started this one (parent first), recorded in the audit log. It is
/// informational only: any process running as this user can arrange to be started by a program of a
/// given name, which is why access is granted by access keys rather than by caller name.
/// </summary>
public static class ProcessAncestry
{
    public static IReadOnlyList<AncestorProcess> Current(int maxDepth = 12) => KeyloPlatform.Current.Processes.Current(maxDepth);
}

/// <summary>
/// Puts text on the clipboard kept out of clipboard history and sync, and clears it later only if
/// nothing else has been copied since. See <see cref="ISecureClipboard"/>.
/// </summary>
public static class SecureClipboard
{
    /// <summary>Copies <paramref name="text"/>; returns the token to pass to <see cref="ClearIfUnchanged"/>.</summary>
    public static uint SetText(string text) => KeyloPlatform.Current.Clipboard.SetText(text);

    public static bool ClearIfUnchanged(uint token) => KeyloPlatform.Current.Clipboard.ClearIfUnchanged(token);
}
