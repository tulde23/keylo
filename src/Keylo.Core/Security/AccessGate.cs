using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Keylo.Core.Security;

public enum VerificationResult { Verified, Canceled, Unavailable, Failed }

public interface IUserVerifier
{
    Task<(VerificationResult Result, string? Detail)> VerifyAsync(IntPtr ownerWindow, string message);
}

public sealed class AccessDeniedException(string message) : KeyloException(message);

/// <summary>
/// Decides when Windows Hello must be shown before a secret is used.
///
/// This is a presence check (someone at the keyboard approved it), not encryption: the values are
/// protected by DPAPI and readable by any process running as this user, with or without Keylo.
/// </summary>
public sealed class AccessGate(KeyloConfig config, IUserVerifier verifier, string? dataDirectory = null)
{
    private static readonly byte[] SessionEntropy = Encoding.UTF8.GetBytes("keylo:session:v1");

    private readonly string _sessionPath = Path.Combine(dataDirectory ?? KeyloPaths.DefaultDataDirectory, "session.bin");

    // In Always mode, browsing (list/search) is allowed after one verification in this process;
    // each value access still asks again.
    private bool _browseUnlocked;

    public HelloMode Mode => config.Hello;

    public DateTimeOffset? SessionExpiresAt => config.Hello == HelloMode.Session ? ReadSession() : null;

    /// <summary>Whether the secret list can be shown without prompting.</summary>
    public bool IsUnlocked => config.Hello switch
    {
        HelloMode.Never => true,
        HelloMode.Session => ReadSession() is not null,
        _ => _browseUnlocked,
    };

    /// <summary>Unlocks browsing (and, in Session mode, values) — prompting if needed.</summary>
    public Task UnlockAsync(IntPtr owner, string message = "Unlock Keylo") =>
        EnsureAsync(owner, message, valueAccess: false);

    /// <summary>Throws <see cref="AccessDeniedException"/> unless access is (or just became) allowed.</summary>
    public async Task EnsureAsync(IntPtr owner, string message, bool valueAccess)
    {
        switch (config.Hello)
        {
            case HelloMode.Never:
                return;
            case HelloMode.Session when ReadSession() is not null:
                return;
            case HelloMode.Always when !valueAccess && _browseUnlocked:
                return;
        }

        var (result, detail) = await verifier.VerifyAsync(owner, message);
        switch (result)
        {
            case VerificationResult.Verified:
                _browseUnlocked = true;
                if (config.Hello == HelloMode.Session) WriteSession(DateTimeOffset.UtcNow.AddMinutes(config.SessionMinutes));
                return;
            case VerificationResult.Unavailable:
                throw new AccessDeniedException(
                    $"Windows Hello isn't available ({detail}). Set it up in Settings → Accounts → Sign-in options, " +
                    "or run 'keylo config hello never'.");
            case VerificationResult.Canceled:
                throw new AccessDeniedException("Windows Hello was canceled.");
            default:
                throw new AccessDeniedException($"Windows Hello verification failed{(detail is null ? "" : $" ({detail})")}.");
        }
    }

    /// <summary>
    /// Always verifies (ignoring any session) unless Hello is off. For changes to the settings that
    /// decide what skips verification: Hello mode, session length, trust groups.
    /// </summary>
    public async Task ConfirmAsync(IntPtr owner, string message)
    {
        if (config.Hello == HelloMode.Never) return;

        var (result, detail) = await verifier.VerifyAsync(owner, message);
        if (result != VerificationResult.Verified)
            throw new AccessDeniedException(result == VerificationResult.Canceled
                ? "Windows Hello was canceled."
                : $"Windows Hello verification failed{(detail is null ? "" : $" ({detail})")}.");
    }

    /// <summary>
    /// Slides an active session's expiry to a full session length from now (Session mode only).
    /// Called on user activity in the app, so the session lasts while someone is at the keyboard;
    /// agents and the CLI never call it. Writes at most every 30 seconds.
    /// </summary>
    public void ExtendSession()
    {
        if (config.Hello != HelloMode.Session || ReadSession() is not { } expires) return;
        var extended = DateTimeOffset.UtcNow.AddMinutes(config.SessionMinutes);
        if (extended - expires > TimeSpan.FromSeconds(30)) WriteSession(extended);
    }

    public void Lock()
    {
        _browseUnlocked = false;
        try { File.Delete(_sessionPath); } catch (IOException) { }
    }

    private DateTimeOffset? ReadSession()
    {
        try
        {
            if (!File.Exists(_sessionPath)) return null;
            var raw = Platform.KeyloPlatform.Current.DataProtector.Unprotect(File.ReadAllBytes(_sessionPath), SessionEntropy);
            if (raw.Length != 8) return null;

            var expires = new DateTimeOffset(BinaryPrimitives.ReadInt64LittleEndian(raw), TimeSpan.Zero);
            var now = DateTimeOffset.UtcNow;
            // Reject a session that outlives the configured length (e.g. after the setting was shortened).
            return expires > now && expires <= now.AddMinutes(config.SessionMinutes) ? expires : null;
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void WriteSession(DateTimeOffset expires)
    {
        var raw = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(raw, expires.UtcTicks);
        Directory.CreateDirectory(Path.GetDirectoryName(_sessionPath)!);
        File.WriteAllBytes(_sessionPath, Platform.KeyloPlatform.Current.DataProtector.Protect(raw, SessionEntropy));
    }
}
