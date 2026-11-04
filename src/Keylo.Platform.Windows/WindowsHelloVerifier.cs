using System.Runtime.InteropServices;
using Windows.Security.Credentials.UI;

using Keylo.Core.Security;

namespace Keylo.Platform.Windows;

/// <summary>Windows Hello (PIN, fingerprint or face) via UserConsentVerifier.</summary>
public sealed class WindowsHelloVerifier : IUserVerifier
{
    public async Task<(VerificationResult Result, string? Detail)> VerifyAsync(IntPtr ownerWindow, string message)
    {
        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        if (availability != UserConsentVerifierAvailability.Available)
            return (VerificationResult.Unavailable, availability.ToString());

        // Desktop apps must parent the prompt to a window. A console's window works; under
        // Windows Terminal it is a hidden pseudo-window, so fall back to the foreground window.
        var owner = ownerWindow != IntPtr.Zero ? ownerWindow : GetConsoleWindow();
        if (owner == IntPtr.Zero || !IsWindowVisible(owner)) owner = GetForegroundWindow();

        var result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(owner, message);
        return result switch
        {
            UserConsentVerificationResult.Verified => (VerificationResult.Verified, null),
            UserConsentVerificationResult.Canceled => (VerificationResult.Canceled, null),
            UserConsentVerificationResult.DeviceNotPresent or
            UserConsentVerificationResult.NotConfiguredForUser or
            UserConsentVerificationResult.DisabledByPolicy => (VerificationResult.Unavailable, result.ToString()),
            _ => (VerificationResult.Failed, result.ToString()),
        };
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);
}
