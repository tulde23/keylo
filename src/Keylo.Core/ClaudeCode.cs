using System.Diagnostics;

namespace Keylo.Core;

/// <summary>Registers Keylo's MCP server with Claude Code (user scope, so it's in every project but never in a repo).</summary>
public static class ClaudeCode
{
    public const string ServerName = "keylo";

    public static string? FindCli()
    {
        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD").Split(';', StringSplitOptions.RemoveEmptyEntries);
        var directories = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Append(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "bin"));

        return directories
            .SelectMany(dir => extensions.Select(ext => Path.Combine(dir.Trim('"'), "claude" + ext)))
            .FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Replaces any existing "keylo" server with one that runs <paramref name="keyloExe"/> mcp and
    /// receives <paramref name="token"/> as its access key. The key goes into Claude Code's user
    /// config (~/.claude.json), which only this Windows account can read.
    /// </summary>
    public static async Task RegisterAsync(string keyloExe, string token)
    {
        var cli = FindCli() ?? throw new KeyloException("Claude Code ('claude') wasn't found on PATH.");

        await RunAsync(cli, ["mcp", "remove", ServerName, "--scope", "user"], allowFailure: true);
        await RunAsync(cli, ["mcp", "add", ServerName, "--scope", "user", "--env", $"{Security.AccessKeys.EnvironmentVariable}={token}", "--", keyloExe, "mcp"]);
    }

    private static async Task RunAsync(string cli, IReadOnlyList<string> args, bool allowFailure = false)
    {
        ProcessStartInfo psi;
        if (Path.GetExtension(cli).Equals(".cmd", StringComparison.OrdinalIgnoreCase))
        {
            psi = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe");
            foreach (var arg in (string[])["/d", "/c", cli, .. args]) psi.ArgumentList.Add(arg);
        }
        else
        {
            psi = new ProcessStartInfo(cli);
            foreach (var arg in args) psi.ArgumentList.Add(arg);
        }

        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;

        using var process = Process.Start(psi) ?? throw new KeyloException("Couldn't start Claude Code.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (process.ExitCode != 0 && !allowFailure)
        {
            // Never echo the arguments: they contain the key.
            var detail = (await stderr).Trim() is { Length: > 0 } err ? err : (await stdout).Trim();
            throw new KeyloException($"Claude Code couldn't add the server: {detail}");
        }
    }
}
