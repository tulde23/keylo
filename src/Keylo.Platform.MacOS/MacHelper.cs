using System.Diagnostics;
using Keylo.Core;

namespace Keylo.Platform.MacOS;

/// <summary>
/// Runs <c>keylo-mac</c>, the small Swift helper built alongside keylo (helper/keylo-mac.swift), for
/// the bits that need Apple frameworks: Touch ID (LocalAuthentication), the pasteboard (AppKit) and
/// approval alerts. It sits next to the keylo binary.
/// </summary>
public static class MacHelper
{
    public static string Path => System.IO.Path.Combine(AppContext.BaseDirectory, "keylo-mac");

    /// <summary>Runs the helper; returns its exit code and stdout. Throws when it isn't installed.</summary>
    public static async Task<(int Code, string Output)> RunAsync(IReadOnlyList<string> args, string? stdin = null)
    {
        if (!File.Exists(Path)) throw new KeyloException($"keylo-mac (Keylo's macOS helper) isn't installed next to keylo ({Path}). Re-run build.sh.");

        var psi = new ProcessStartInfo(Path)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new KeyloException("Couldn't start keylo-mac.");
        if (stdin is not null) await process.StandardInput.WriteAsync(stdin);
        process.StandardInput.Close();
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, output.Trim());
    }

    public static (int Code, string Output) Run(IReadOnlyList<string> args, string? stdin = null) =>
        RunAsync(args, stdin).GetAwaiter().GetResult();
}
