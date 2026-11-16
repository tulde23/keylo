using System.Runtime.InteropServices;

namespace Keylo.Platform.Linux;

/// <summary>
/// Keeps the unlocked vault key in the kernel's user keyring for a while (like ssh-agent, without a
/// daemon), so each keylo command and the MCP server don't ask for the passphrase again. The key is
/// readable by this user's processes only and expires by itself. Where the keyring syscalls are
/// blocked (Docker's default seccomp profile), caching is simply off.
/// </summary>
internal static class KernelKeyCache
{
    private const int UserKeyring = -4;                  // KEY_SPEC_USER_KEYRING
    private const int SetPerm = 5, Search = 10, Read = 11, SetTimeout = 15, Invalidate = 21;
    private const uint Permissions = 0x3f3f0000;         // possessor: all; user: all; group/other: none

    private static (long AddKey, long KeyCtl)? Syscalls => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => (248, 250),
        Architecture.Arm64 => (217, 219),
        _ => null,
    };

    [DllImport("libc", SetLastError = true)]
    private static extern long syscall(long number, long a1, long a2, long a3, long a4, long a5);

    public static byte[]? Get(string description)
    {
        if (Syscalls is not { } calls) return null;
        var id = WithStrings("user", description, (type, desc) => syscall(calls.KeyCtl, Search, UserKeyring, type, desc, 0));
        if (id <= 0) return null;

        var buffer = Marshal.AllocHGlobal(64);
        try
        {
            var length = syscall(calls.KeyCtl, Read, id, buffer, 64, 0);
            if (length is <= 0 or > 64) return null;
            var key = new byte[length];
            Marshal.Copy(buffer, key, 0, (int)length);
            return key;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void Put(string description, byte[] key, TimeSpan lifetime)
    {
        if (Syscalls is not { } calls || lifetime <= TimeSpan.Zero) return;
        var payload = Marshal.AllocHGlobal(key.Length);
        try
        {
            Marshal.Copy(key, 0, payload, key.Length);
            var id = WithStrings("user", description, (type, desc) => syscall(calls.AddKey, type, desc, payload, key.Length, UserKeyring));
            if (id <= 0) return;
            syscall(calls.KeyCtl, SetPerm, id, Permissions, 0, 0);
            syscall(calls.KeyCtl, SetTimeout, id, (long)lifetime.TotalSeconds, 0, 0);
        }
        finally
        {
            Marshal.Copy(new byte[key.Length], 0, payload, key.Length);
            Marshal.FreeHGlobal(payload);
        }
    }

    public static void Remove(string description)
    {
        if (Syscalls is not { } calls) return;
        var id = WithStrings("user", description, (type, desc) => syscall(calls.KeyCtl, Search, UserKeyring, type, desc, 0));
        if (id > 0) syscall(calls.KeyCtl, Invalidate, id, 0, 0, 0);
    }

    private static long WithStrings(string a, string b, Func<long, long, long> call)
    {
        var pa = Marshal.StringToCoTaskMemUTF8(a);
        var pb = Marshal.StringToCoTaskMemUTF8(b);
        try
        {
            return call(pa, pb);
        }
        catch (EntryPointNotFoundException)
        {
            return -1;
        }
        finally
        {
            Marshal.FreeCoTaskMem(pa);
            Marshal.FreeCoTaskMem(pb);
        }
    }
}
