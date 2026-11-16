using System.Diagnostics;

namespace Keylo.Platform.Linux;

/// <summary>
/// Asks for a passphrase on the controlling terminal (/dev/tty), not stdin, so it works while a
/// value is being piped in. Echo is turned off with stty while typing.
/// </summary>
internal static class TerminalPrompt
{
    public static bool Available
    {
        get
        {
            try
            {
                using var tty = new FileStream("/dev/tty", FileMode.Open, FileAccess.ReadWrite);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public static string? ReadHidden(string prompt)
    {
        try
        {
            using var tty = new FileStream("/dev/tty", FileMode.Open, FileAccess.ReadWrite);
            using var writer = new StreamWriter(tty) { AutoFlush = true };
            using var reader = new StreamReader(tty);
            writer.Write(prompt);
            Stty("-echo");
            try
            {
                return reader.ReadLine();
            }
            finally
            {
                Stty("echo");
                writer.WriteLine();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void Stty(string mode)
    {
        try
        {
            using var stty = Process.Start(new ProcessStartInfo("/bin/sh", ["-c", $"stty {mode} < /dev/tty"]) { UseShellExecute = false });
            stty?.WaitForExit();
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}
