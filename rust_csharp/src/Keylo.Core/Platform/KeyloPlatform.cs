using Keylo.Core.Security;

namespace Keylo.Core.Platform;

/// <summary>A secure item in the OS store, the unit <see cref="SecretStore"/> builds secrets from.</summary>
/// <param name="Blob">The stored bytes (Keylo's value or a reference to an encrypted file).</param>
/// <param name="Attributes">Small named strings stored with the item (category, type, fields…).</param>
public sealed record RawCredential(
    string Target,
    string? UserName,
    string? Comment,
    DateTimeOffset LastWritten,
    byte[] Blob,
    IReadOnlyDictionary<string, string> Attributes);

/// <summary>
/// The OS's secure item store: Windows Credential Manager, the macOS Keychain… Items are private to
/// the signed-in user and encrypted by the OS.
/// </summary>
public interface ICredentialStore
{
    /// <summary>Largest <see cref="RawCredential.Blob"/> the store accepts; larger values go to protected files.</summary>
    int MaxBlobBytes { get; }

    /// <summary>Largest UTF-8 size of one attribute value.</summary>
    int MaxAttributeBytes { get; }

    /// <summary>Most attributes per item.</summary>
    int MaxAttributes { get; }

    RawCredential? Read(string target);

    /// <summary>Items whose target starts with <paramref name="prefix"/>.</summary>
    IReadOnlyList<RawCredential> Enumerate(string prefix);

    /// <summary>Creates or replaces an item.</summary>
    void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null);

    bool Delete(string target);
}

/// <summary>Encrypts local files so only this user (on this machine) can read them: DPAPI, the Keychain…</summary>
public interface IDataProtector
{
    byte[] Protect(byte[] data, byte[] entropy);

    /// <summary>Throws <see cref="System.Security.Cryptography.CryptographicException"/> when the data can't be decrypted.</summary>
    byte[] Unprotect(byte[] data, byte[] entropy);
}

/// <summary>A clipboard that keeps copied secrets out of history and sync, and can clear them later.</summary>
public interface ISecureClipboard
{
    /// <summary>Copies <paramref name="text"/>; returns a token for <see cref="ClearIfUnchanged"/>.</summary>
    uint SetText(string text);

    /// <summary>Empties the clipboard if it still holds what <see cref="SetText"/> put there.</summary>
    bool ClearIfUnchanged(uint token);
}

/// <summary>The chain of processes that started this one, for the audit log.</summary>
public interface IProcessAncestry
{
    IReadOnlyList<AncestorProcess> Current(int maxDepth = 12);
}

/// <summary>Everything Keylo needs from the operating system.</summary>
public interface IKeyloPlatform
{
    /// <summary>"Windows", "macOS"…</summary>
    string Name { get; }

    ICredentialStore Credentials { get; }
    IDataProtector DataProtector { get; }

    /// <summary>Windows Hello, Touch ID…</summary>
    IUserVerifier Verifier { get; }

    /// <summary>The verifier as people know it, for UI text: "Windows Hello", "Touch ID".</summary>
    string VerifierName => "device sign-in";

    /// <summary>Where secrets live, for UI text: "Windows Credential Manager", "the macOS Keychain".</summary>
    string StoreName => "the system credential store";

    /// <summary>What protects large values kept as files, for UI text: "DPAPI".</summary>
    string FileProtectionName => "encrypted";

    ISecureClipboard Clipboard { get; }
    IProcessAncestry Processes { get; }
}

/// <summary>
/// The platform in use, installed once at startup by each host (CLI, app, tests), e.g.
/// <c>WindowsPlatform.Install()</c>. Core itself is OS-neutral.
/// </summary>
public static class KeyloPlatform
{
    private static IKeyloPlatform? _current;

    public static IKeyloPlatform Current =>
        _current ?? throw new InvalidOperationException("No Keylo platform is installed. Call e.g. WindowsPlatform.Install() at startup.");

    public static bool IsInstalled => _current is not null;

    public static void Install(IKeyloPlatform platform) => _current = platform;
}
