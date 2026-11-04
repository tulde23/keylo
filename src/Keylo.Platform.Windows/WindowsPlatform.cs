using Keylo.Core.Platform;
using Keylo.Core.Security;

namespace Keylo.Platform.Windows;

/// <summary>
/// Keylo on Windows: Credential Manager, DPAPI, Windows Hello, a clipboard kept out of history and
/// cloud sync, and Toolhelp32 process ancestry.
/// </summary>
public sealed class WindowsPlatform : IKeyloPlatform
{
    public string Name => "Windows";
    public string VerifierName => "Windows Hello";
    public string StoreName => "Windows Credential Manager";
    public string FileProtectionName => "DPAPI";
    public ICredentialStore Credentials { get; } = new WindowsCredentialStore();
    public IDataProtector DataProtector { get; } = new DpapiProtector();
    public IUserVerifier Verifier { get; } = new WindowsHelloVerifier();
    public ISecureClipboard Clipboard { get; } = new WindowsClipboard();
    public IProcessAncestry Processes { get; } = new WindowsProcessAncestry();

    /// <summary>Makes Windows the platform for this process. Call once at startup.</summary>
    public static void Install() => KeyloPlatform.Install(new WindowsPlatform());
}
