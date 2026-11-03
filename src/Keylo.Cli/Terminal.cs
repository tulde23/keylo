using System.Text;

namespace Keylo.Cli;

internal static class Terminal
{
    /// <summary>Reads a secret value: from stdin when it's redirected, otherwise typed without echo.</summary>
    public static byte[] ReadSecret(string prompt, bool confirm)
    {
        if (Console.IsInputRedirected)
        {
            using var stdin = Console.OpenStandardInput();
            using var buffer = new MemoryStream();
            stdin.CopyTo(buffer);
            return TrimOneTrailingNewline(buffer.ToArray());
        }

        var first = ReadHidden(prompt);
        if (confirm)
        {
            var second = ReadHidden("Confirm: ");
            if (first != second) throw new UsageException("Values didn't match.");
        }

        if (first.Length == 0) throw new UsageException("Value is empty.");
        return Encoding.UTF8.GetBytes(first);
    }

    /// <summary>
    /// A backup password: typed without echo (twice when <paramref name="confirm"/>), or the first
    /// line of stdin with <paramref name="fromStdin"/>. Never taken as an argument, which would put
    /// it in shell history and the process list.
    /// </summary>
    public static string ReadPassword(string prompt, bool confirm, bool fromStdin)
    {
        if (fromStdin) return Console.In.ReadLine() ?? throw new UsageException("No password on stdin.");
        if (Console.IsInputRedirected) throw new UsageException("Input is redirected; use --password-stdin to read the password from it.");

        var first = ReadHidden(prompt);
        if (confirm && ReadHidden("Confirm password: ") != first) throw new UsageException("Passwords didn't match.");
        return first;
    }

    public static bool Confirm(string question)
    {
        if (Console.IsInputRedirected) return false;
        Console.Error.Write($"{question} [y/N] ");
        var answer = Console.ReadLine();
        return answer is not null && answer.Trim().StartsWith('y');
    }

    /// <summary>Writes the exact bytes to stdout (binary-safe), adding a newline only on an interactive console.</summary>
    public static void WriteRaw(byte[] value)
    {
        using var stdout = Console.OpenStandardOutput();
        stdout.Write(value);
        if (!Console.IsOutputRedirected) stdout.Write("\r\n"u8);
    }

    public static void Info(string message) => Console.Error.WriteLine(message);

    private static string ReadHidden(string prompt)
    {
        Console.Error.Write(prompt);
        var value = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (value.Length > 0) value.Length--;
                continue;
            }
            if (key.Key == ConsoleKey.Escape) throw new UsageException("Canceled.");
            if (!char.IsControl(key.KeyChar)) value.Append(key.KeyChar);
        }
        Console.Error.WriteLine();
        return value.ToString();
    }

    private static byte[] TrimOneTrailingNewline(byte[] data)
    {
        var length = data.Length;
        if (length > 0 && data[length - 1] == '\n') length--;
        if (length > 0 && data[length - 1] == '\r') length--;
        return data[..length];
    }
}
