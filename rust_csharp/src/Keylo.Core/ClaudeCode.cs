using System.Diagnostics;

namespace Keylo.Core;

/// <summary>Registers Keylo's MCP server with Claude Code (user scope, so it's in every project but never in a repo).</summary>
public static class ClaudeCode
{
    public const string ServerName = "keylo";

    public static string? FindCli()
    {
        var extensions = OperatingSystem.IsWindows()
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD").Split(';', StringSplitOptions.RemoveEmptyEntries)
            : [""];
        var directories = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
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

    public sealed record Registration(bool Registered, string? Command, Security.AccessKey? Key, bool HasToken, bool PointsAt);

    /// <summary>
    /// Whether Claude Code has Keylo's server registered at user scope (~/.claude.json), which
    /// access key it was given (matched by hash; the token is never returned), and whether it runs
    /// <paramref name="keyloExe"/>.
    /// </summary>
    public static Registration Inspect(KeyloConfig config, string keyloExe)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude.json");
        try
        {
            if (!File.Exists(path)) return new Registration(false, null, null, false, false);

            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path),
                new System.Text.Json.JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = System.Text.Json.JsonCommentHandling.Skip });
            if (!doc.RootElement.TryGetProperty("mcpServers", out var servers) || !servers.TryGetProperty(ServerName, out var server))
                return new Registration(false, null, null, false, false);

            var command = server.TryGetProperty("command", out var c) ? c.GetString() : null;
            var token = server.TryGetProperty("env", out var env) && env.TryGetProperty(Security.AccessKeys.EnvironmentVariable, out var t) ? t.GetString() : null;
            var pointsAt = command is not null && string.Equals(Path.GetFullPath(command), Path.GetFullPath(keyloExe), StringComparison.OrdinalIgnoreCase);
            return new Registration(true, command, Security.AccessKeys.Find(config, token), !string.IsNullOrEmpty(token), pointsAt);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException)
        {
            return new Registration(false, null, null, false, false);
        }
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
