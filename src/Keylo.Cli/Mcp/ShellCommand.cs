using System.Diagnostics;
using System.Text;
using Keylo.Core;

namespace Keylo.Cli.Mcp;

/// <summary>Runs an agent's command line through a shell and captures its output (no console, no stdin).</summary>
internal static class ShellCommand
{
    private const int MaxCapture = 1_000_000;

    public sealed record Result(int? ExitCode, string Stdout, bool StdoutTruncated, string Stderr, bool StderrTruncated, bool TimedOut);

    public static async Task<Result> RunAsync(string shell, string command, string? workingDirectory, IReadOnlyDictionary<string, string> environment, TimeSpan timeout)
    {
        var psi = shell switch
        {
            "powershell" or "pwsh" => PowerShell(command),
            "cmd" when OperatingSystem.IsWindows() => Cmd(command),
            "bash" when OperatingSystem.IsWindows() => Bash(command),
            "bash" or "zsh" or "sh" => Unix("/bin/" + shell, command),
            _ => throw new ArgumentException(OperatingSystem.IsWindows()
                ? "shell must be powershell, cmd or bash."
                : "shell must be zsh, bash, sh or powershell (if installed)."),
        };

        if (workingDirectory is not null)
        {
            if (!Directory.Exists(workingDirectory)) throw new ArgumentException($"working_directory '{workingDirectory}' doesn't exist.");
            psi.WorkingDirectory = workingDirectory;
        }

        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardInput = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.StandardOutputEncoding = Encoding.UTF8;
        psi.StandardErrorEncoding = Encoding.UTF8;
        // The key that let us run this stays with Keylo; the command doesn't need it.
        psi.Environment.Remove(Core.Security.AccessKeys.EnvironmentVariable);
        foreach (var (key, value) in environment) psi.Environment[key] = value;

        using var process = Process.Start(psi) ?? throw new KeyloException($"Couldn't start {psi.FileName}.");
        process.StandardInput.Close();

        var stdout = CaptureAsync(process.StandardOutput);
        var stderr = CaptureAsync(process.StandardError);

        var timedOut = false;
        using (var cts = new CancellationTokenSource(timeout))
        {
            try
            {
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                timedOut = true;
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            }
        }

        // Children that inherited the pipes can keep them open after the shell exits; don't wait forever.
        var (outText, outCut) = await WithinAsync(stdout, TimeSpan.FromSeconds(5));
        var (errText, errCut) = await WithinAsync(stderr, TimeSpan.FromSeconds(5));
        return new Result(timedOut ? null : process.ExitCode, outText, outCut, errText, errCut, timedOut);
    }

    private static ProcessStartInfo PowerShell(string command)
    {
        var exe = CommandRunner.Resolve("pwsh") ?? CommandRunner.Resolve("powershell")
                  ?? (OperatingSystem.IsWindows() ? "powershell.exe" : throw new KeyloException("PowerShell (pwsh) isn't installed. Use shell \"zsh\" instead."));
        var psi = new ProcessStartInfo(exe);
        foreach (var arg in (string[])["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                     "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $OutputEncoding = [Text.Encoding]::UTF8; " + command])
            psi.ArgumentList.Add(arg);
        return psi;
    }

    /// <summary>The shell agents get when they don't name one.</summary>
    public static string DefaultShell => OperatingSystem.IsWindows() ? "powershell" : "zsh";

    private static ProcessStartInfo Unix(string shell, string command)
    {
        var psi = new ProcessStartInfo(shell);
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(command);
        return psi;
    }

    private static ProcessStartInfo Cmd(string command) =>
        // /s /c "..." passes the command line through untouched.
        new(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe", $"/d /s /c \"{command}\"");

    private static ProcessStartInfo Bash(string command)
    {
        var bash = FindGitBash() ?? throw new KeyloException("Git Bash wasn't found. Use shell \"powershell\" or \"cmd\", or install Git for Windows.");
        var psi = new ProcessStartInfo(bash);
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(command);
        return psi;
    }

    /// <summary>Git for Windows' bash; not System32\bash.exe, which is WSL and doesn't see Windows env vars the same way.</summary>
    private static string? FindGitBash()
    {
        if (CommandRunner.Resolve("git") is { } git && Path.GetDirectoryName(Path.GetDirectoryName(git)) is { } root
            && Path.Combine(root, "bin", "bash.exe") is var candidate && File.Exists(candidate))
            return candidate;

        var programFiles = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "bash.exe");
        return File.Exists(programFiles) ? programFiles : null;
    }

    private static async Task<(string Text, bool Truncated)> CaptureAsync(StreamReader reader)
    {
        var text = new StringBuilder();
        var truncated = false;
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer)) > 0)
        {
            var room = MaxCapture - text.Length;
            if (room <= 0)
            {
                truncated = true; // Keep draining so the process doesn't block on a full pipe.
                continue;
            }

            text.Append(buffer, 0, Math.Min(read, room));
            if (read > room) truncated = true;
        }
        return (text.ToString(), truncated);
    }

    private static async Task<(string, bool)> WithinAsync(Task<(string Text, bool Truncated)> capture, TimeSpan wait) =>
        await Task.WhenAny(capture, Task.Delay(wait)) == capture ? await capture : ("", true);
}
