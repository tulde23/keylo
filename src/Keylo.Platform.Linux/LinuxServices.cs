using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Keylo.Core;
using Keylo.Core.Platform;
using Keylo.Core.Security;

namespace Keylo.Platform.Linux;

/// <summary>Runs small helper programs (pkcheck, wl-copy, zenity…).</summary>
internal static class Tool
{
    public static string? Find(string name) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "/usr/bin:/bin")
        .Split(':', StringSplitOptions.RemoveEmptyEntries)
        .Append("/usr/bin").Append("/bin")
        .Select(dir => System.IO.Path.Combine(dir, name))
        .FirstOrDefault(File.Exists);

    /// <summary>Runs <paramref name="program"/>; returns its exit code, stdout and stderr.</summary>
    public static async Task<(int Code, string Output, string Error)> RunAsync(string program, IEnumerable<string> args, string? stdin = null, bool captureOutput = true)
    {
        var psi = new ProcessStartInfo(program)
        {
            UseShellExecute = false,
            RedirectStandardInput = stdin is not null,
            // Programs that fork a server (wl-copy, xclip) keep inherited pipes open; don't capture theirs.
            RedirectStandardOutput = captureOutput,
            RedirectStandardError = captureOutput,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new KeyloException($"Couldn't start {program}.");
        if (stdin is not null)
        {
            await process.StandardInput.WriteAsync(stdin);
            process.StandardInput.Close();
        }
        var output = captureOutput ? process.StandardOutput.ReadToEndAsync() : Task.FromResult("");
        var error = captureOutput ? process.StandardError.ReadToEndAsync() : Task.FromResult("");
        await process.WaitForExitAsync();
        return (process.ExitCode, await output, (await error).Trim());
    }

    public static (int Code, string Output, string Error) Run(string program, IEnumerable<string> args, string? stdin = null, bool captureOutput = true) =>
        RunAsync(program, args, stdin, captureOutput).GetAwaiter().GetResult();

    public static bool HasDisplay =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY")) ||
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY"));
}

/// <summary>
/// The presence check through polkit: the user authenticates as themselves (password, or fingerprint
/// with fprintd) in the desktop's polkit prompt, or on the terminal over SSH (pkttyagent).
/// </summary>
public sealed class PolkitVerifier : IUserVerifier
{
    public const string ActionId = "io.github.tulde23.keylo.verify";
    public const string PolicyFile = "/usr/share/polkit-1/actions/io.github.tulde23.keylo.policy";

    public async Task<(VerificationResult Result, string? Detail)> VerifyAsync(IntPtr ownerWindow, string message)
    {
        if (Tool.Find("pkcheck") is not { } pkcheck)
            return (VerificationResult.Unavailable, "polkit isn't installed");
        if (!File.Exists(PolicyFile))
            return (VerificationResult.Unavailable, $"Keylo's polkit policy isn't installed ({PolicyFile}); run Keylo's install.sh");

        var subject = $"{Environment.ProcessId},{StartTime(Environment.ProcessId)}";

        // No desktop (SSH, a plain terminal): register a text agent so polkit can ask here.
        Process? textAgent = null;
        if (!Tool.HasDisplay && FileVault.CanPromptOnTerminal && Tool.Find("pkttyagent") is { } pkttyagent)
        {
            textAgent = Process.Start(new ProcessStartInfo(pkttyagent, ["--process", subject, "--fallback"]) { UseShellExecute = false });
            await Task.Delay(300); // let it register
        }

        try
        {
            if (FileVault.CanPromptOnTerminal && textAgent is not null) await Console.Error.WriteLineAsync(message);
            var (code, _, error) = await Tool.RunAsync(pkcheck, ["--action-id", ActionId, "--process", subject, "--allow-user-interaction"]);
            return code switch
            {
                0 => (VerificationResult.Verified, null),
                3 => (VerificationResult.Canceled, null),
                2 => (VerificationResult.Unavailable, "there's no polkit agent to ask for your password (no desktop session)"),
                1 when error.Contains("No authentication agent", StringComparison.OrdinalIgnoreCase) =>
                    (VerificationResult.Unavailable, "there's no polkit agent to ask for your password (no desktop session)"),
                _ => (VerificationResult.Failed, error.Length > 0 ? error : null),
            };
        }
        finally
        {
            if (textAgent is not null)
            {
                try { textAgent.Kill(); } catch (InvalidOperationException) { }
                textAgent.Dispose();
            }
        }
    }

    /// <summary>The process's start time in clock ticks (field 22 of /proc/PID/stat), which polkit pairs with the pid.</summary>
    private static string StartTime(int pid)
    {
        var stat = File.ReadAllText($"/proc/{pid}/stat");
        var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
        return fields[19]; // fields after "pid (comm) " start at field 3
    }
}

/// <summary>
/// The clipboard through wl-clipboard (Wayland) or xclip / xsel (X11). Linux has no change counter,
/// so the token is a hash of what was copied: clearing checks the clipboard still holds it.
/// </summary>
public sealed class LinuxClipboard : ISecureClipboard
{
    public uint SetText(string text)
    {
        var (program, args) = Backend("set");
        var (code, _, _) = Tool.Run(program, args, text, captureOutput: false);
        if (code != 0) throw new KeyloException($"Couldn't copy to the clipboard ({System.IO.Path.GetFileName(program)} failed).");
        return Token(text);
    }

    public bool ClearIfUnchanged(uint token)
    {
        try
        {
            var (getProgram, getArgs) = Backend("get");
            var (code, current, _) = Tool.Run(getProgram, getArgs);
            if (code != 0 || Token(current) != token) return false;
            var (clearProgram, clearArgs) = Backend("clear");
            return Tool.Run(clearProgram, clearArgs, clearProgram.EndsWith("xclip") ? "" : null, captureOutput: false).Code == 0;
        }
        catch (KeyloException)
        {
            return false;
        }
    }

    private static uint Token(string text) => BitConverter.ToUInt32(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static (string Program, string[] Args) Backend(string operation)
    {
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY")))
        {
            if (operation == "get" && Tool.Find("wl-paste") is { } paste) return (paste, ["--no-newline"]);
            if (operation != "get" && Tool.Find("wl-copy") is { } copy) return (copy, operation == "clear" ? ["--clear"] : []);
        }
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")))
        {
            if (Tool.Find("xclip") is { } xclip)
                return (xclip, operation == "get" ? ["-selection", "clipboard", "-out"] : ["-selection", "clipboard", "-in"]);
            if (Tool.Find("xsel") is { } xsel)
                return (xsel, operation switch { "get" => ["--clipboard", "--output"], "clear" => ["--clipboard", "--clear"], _ => ["--clipboard", "--input"] });
        }
        throw new KeyloException(Tool.HasDisplay
            ? "Copying needs wl-clipboard (Wayland) or xclip (X11). Install one, e.g. 'sudo apt install wl-clipboard xclip'."
            : "There's no desktop session here, so there's no clipboard. Use 'keylo get NAME' instead.");
    }
}

/// <summary>The parent chain from /proc: each process's parent pid and command name.</summary>
public sealed class LinuxProcessAncestry : IProcessAncestry
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

    private static (int ParentPid, string Name)? Row(int pid)
    {
        try
        {
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            var open = stat.IndexOf('(');
            var close = stat.LastIndexOf(')');
            var name = stat[(open + 1)..close];
            var fields = stat[(close + 2)..].Split(' ');
            return int.TryParse(fields[1], out var ppid) ? (ppid, name) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}

/// <summary>The login session's state, for locking Keylo along with the screen.</summary>
public static class LinuxSession
{
    /// <summary>True while the screen is locked (logind's LockedHint, set by GNOME, KDE and others); false when it can't tell.</summary>
    public static bool IsScreenLocked()
    {
        if (Tool.Find("loginctl") is not { } loginctl) return false;
        var session = Environment.GetEnvironmentVariable("XDG_SESSION_ID") is { Length: > 0 } id ? id : "self";
        try
        {
            var (code, output, _) = Tool.Run(loginctl, ["show-session", session, "-p", "LockedHint", "--value"]);
            return code == 0 && output.Trim() == "yes";
        }
        catch (Exception ex) when (ex is KeyloException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}

/// <summary>Native dialogs for the MCP server's approvals: zenity (GNOME and most desktops) or kdialog (KDE).</summary>
public static class LinuxDialogs
{
    public const int Deny = 10, AllowOnce = 11, AllowAlways = 12;

    public static async Task<int> ApproveAsync(string title, string message, bool allowAlways)
    {
        if (!Tool.HasDisplay)
            throw new KeyloException("There's no desktop session to ask for approval in. Add the secrets to the access key instead ('keylo keys').");

        if (Tool.Find("zenity") is { } zenity)
        {
            List<string> args = ["--question", "--no-markup", "--width=460", "--icon-name=dialog-warning", "--title=Keylo",
                $"--text={title}\n\n{message}", "--ok-label=Allow once", "--cancel-label=Deny"];
            if (allowAlways) args.Add("--extra-button=Always allow");
            var (code, output, _) = await Tool.RunAsync(zenity, args);
            if (code == 0) return AllowOnce;
            return output.Trim() == "Always allow" ? AllowAlways : Deny;
        }

        if (Tool.Find("kdialog") is { } kdialog)
        {
            var text = $"{title}\n\n{message}";
            var (code, _, _) = allowAlways
                ? await Tool.RunAsync(kdialog, ["--title", "Keylo", "--warningyesnocancel", text, "--yes-label", "Allow once", "--no-label", "Always allow", "--cancel-label", "Deny"])
                : await Tool.RunAsync(kdialog, ["--title", "Keylo", "--warningyesno", text, "--yes-label", "Allow once", "--no-label", "Deny"]);
            return code switch
            {
                0 => AllowOnce,
                1 when allowAlways => AllowAlways,
                _ => Deny,
            };
        }

        throw new KeyloException("Approving access needs zenity or kdialog. Install one, e.g. 'sudo apt install zenity'.");
    }
}
