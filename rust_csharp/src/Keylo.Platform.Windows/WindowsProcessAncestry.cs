using System.Runtime.InteropServices;

using Keylo.Core.Platform;
using Keylo.Core.Security;

namespace Keylo.Platform.Windows;

/// <summary>
/// The chain of processes that started this one (parent first), recorded in the audit log. It is
/// informational only: any process running as this user can arrange to be started by a program of a
/// given name, which is why access is granted by access keys rather than by caller name.
/// </summary>
public sealed class WindowsProcessAncestry : IProcessAncestry
{
    public IReadOnlyList<AncestorProcess> Current(int maxDepth = 12)
    {
        var snapshot = Snapshot();
        var chain = new List<AncestorProcess>();
        var seen = new HashSet<int>();
        var pid = Environment.ProcessId;

        var childStarted = StartTime(pid);
        for (var depth = 0; depth < maxDepth; depth++)
        {
            if (!snapshot.TryGetValue(pid, out var entry) || !seen.Add(pid)) break;
            var parent = entry.ParentId;
            if (parent == 0 || !snapshot.TryGetValue(parent, out var parentEntry)) break;

            // Windows doesn't reparent orphans, and reuses process ids: if the real parent exited,
            // "parent" may be an unrelated, newer process that inherited its id. A genuine parent
            // always started before its child; anything else ends the chain (fails closed).
            var parentStarted = StartTime(parent);
            if (parentStarted is null || childStarted is null || parentStarted > childStarted) break;

            chain.Add(new AncestorProcess(parent, parentEntry.ExeName));
            pid = parent;
            childStarted = parentStarted;
        }

        return chain;
    }

    private static long? StartTime(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            return GetProcessTimes(handle, out var created, out _, out _, out _) ? created : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static Dictionary<int, (int ParentId, string ExeName)> Snapshot()
    {
        var result = new Dictionary<int, (int, string)>();
        var handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (handle == INVALID_HANDLE_VALUE) return result;

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(handle, ref entry)) return result;
            do
            {
                result[(int)entry.th32ProcessID] = ((int)entry.th32ParentProcessID, entry.szExeFile);
            } while (Process32NextW(handle, ref entry));
        }
        finally
        {
            CloseHandle(handle);
        }

        return result;
    }

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr hProcess, out long lpCreationTime, out long lpExitTime, out long lpKernelTime, out long lpUserTime);
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
