using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Keylo.Core.Security;

/// <summary>
/// Puts text on the clipboard marked so Windows keeps it out of clipboard history (Win+V) and
/// cloud clipboard sync, and clears it later only if nothing else has been copied since.
/// </summary>
public static class SecureClipboard
{
    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    /// <summary>Copies <paramref name="text"/> and returns the clipboard sequence number to pass to <see cref="ClearIfUnchanged"/>.</summary>
    public static uint SetText(string text)
    {
        Open();
        try
        {
            if (!EmptyClipboard()) throw new Win32Exception(Marshal.GetLastWin32Error());

            SetData(CF_UNICODETEXT, (text + "\0").ToCharArray().SelectMany(BitConverter.GetBytes).ToArray());
            SetData(RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing"), [0]);
            SetData(RegisterClipboardFormat("CanIncludeInClipboardHistory"), BitConverter.GetBytes(0));
            SetData(RegisterClipboardFormat("CanUploadToCloudClipboard"), BitConverter.GetBytes(0));
        }
        finally
        {
            CloseClipboard();
        }

        return GetClipboardSequenceNumber();
    }

    /// <summary>Empties the clipboard if it still holds what <see cref="SetText"/> put there.</summary>
    public static bool ClearIfUnchanged(uint sequence)
    {
        if (GetClipboardSequenceNumber() != sequence) return false;

        Open();
        try
        {
            return GetClipboardSequenceNumber() == sequence && EmptyClipboard();
        }
        finally
        {
            CloseClipboard();
        }
    }

    private static void Open()
    {
        // Another process may briefly hold the clipboard open.
        for (var attempt = 0; attempt < 10; attempt++)
        {
            if (OpenClipboard(IntPtr.Zero)) return;
            Thread.Sleep(25);
        }
        throw new Win32Exception(Marshal.GetLastWin32Error(), "Couldn't open the clipboard.");
    }

    private static void SetData(uint format, byte[] data)
    {
        var handle = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)data.Length);
        if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

        var target = GlobalLock(handle);
        Marshal.Copy(data, 0, target, data.Length);
        GlobalUnlock(handle);

        // On success the system owns the memory.
        if (SetClipboardData(format, handle) == IntPtr.Zero)
        {
            GlobalFree(handle);
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", EntryPoint = "RegisterClipboardFormatW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterClipboardFormat(string lpszFormat);

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);
}
