using System.Diagnostics;

namespace Keylo.Cli;

/// <summary>Starts a program the way a shell would, with extra environment variables.</summary>
internal static class CommandRunner
{
    public static int Run(IReadOnlyList<string> command, IReadOnlyDictionary<string, string> environment)
    {
        if (command.Count == 0) throw new UsageException("Nothing to run. Usage: keylo run --env VAR=secret -- <command> [args]");

        var executable = Resolve(command[0]) ?? throw new UsageException($"'{command[0]}' wasn't found on PATH.");
        var args = command.Skip(1).ToList();

        ProcessStartInfo psi;
        var extension = Path.GetExtension(executable);
        if (OperatingSystem.IsWindows() &&
            (extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".bat", StringComparison.OrdinalIgnoreCase)))
        {
            // Batch files (npm.cmd, etc.) only run through cmd.exe. /s /c "..." keeps the inner quoting intact.
            var line = string.Join(' ', new[] { Quote(executable) }.Concat(args.Select(Quote)));
            psi = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe", $"/d /s /c \"{line}\"");
        }
        else
        {
            psi = new ProcessStartInfo(executable);
            foreach (var arg in args) psi.ArgumentList.Add(arg);
        }

        psi.UseShellExecute = false;
        foreach (var (key, value) in environment) psi.Environment[key] = value;

        using var process = Process.Start(psi)!;
        // Let Ctrl+C reach the child (which shares the console) without killing us first.
        Console.CancelKeyPress += (_, e) => e.Cancel = true;
        process.WaitForExit();
        return process.ExitCode;
    }

    /// <summary>
    /// Resolves like cmd.exe, except the current directory is not searched implicitly (a planted
    /// "git.exe" in a project folder shouldn't receive your secrets).
    /// </summary>
    internal static string? Resolve(string command)
    {
        if (!OperatingSystem.IsWindows()) return ResolveUnix(command);

        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD")
            .Split(';', StringSplitOptions.RemoveEmptyEntries);

        IEnumerable<string> Candidates(string basePath) =>
            Path.HasExtension(basePath) ? [basePath, .. extensions.Select(e => basePath + e)] : extensions.Select(e => basePath + e);

        if (command.Contains(Path.DirectorySeparatorChar) || command.Contains(Path.AltDirectorySeparatorChar) || Path.IsPathRooted(command))
            return Candidates(Path.GetFullPath(command)).FirstOrDefault(File.Exists);

        var directories = (Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return directories
            .SelectMany(dir => Candidates(Path.Combine(dir.Trim('"'), command)))
            .FirstOrDefault(File.Exists);
    }

    /// <summary>PATH lookup like a Unix shell (no implicit current directory), executable files only.</summary>
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static string? ResolveUnix(string command)
    {
        static bool Runnable(string path) =>
            File.Exists(path) && (File.GetUnixFileMode(path) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;

        if (command.Contains('/')) return Runnable(Path.GetFullPath(command)) ? Path.GetFullPath(command) : null;
        return (Environment.GetEnvironmentVariable("PATH") ?? "/usr/bin:/bin")
            .Split(':', StringSplitOptions.RemoveEmptyEntries)
            .Select(dir => Path.Combine(dir, command))
            .FirstOrDefault(Runnable);
    }

    private static string Quote(string arg) =>
        arg.Length > 0 && !arg.Any(c => char.IsWhiteSpace(c) || c == '"') ? arg : "\"" + arg.Replace("\"", "\\\"") + "\"";
}
