using System.Runtime.InteropServices;
using Keylo.Platform.MacOS.Interop;

namespace Keylo.Platform.MacOS;

/// <summary>The login session's state, for locking Keylo along with the screen.</summary>
public static class MacSession
{
    private const string CoreGraphics = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics";

    /// <summary>True while the screen is locked (or the user switched away); false when it can't tell.</summary>
    public static bool IsScreenLocked()
    {
        var session = CGSessionCopyCurrentDictionary();
        if (session == IntPtr.Zero) return false; // no GUI session, e.g. over SSH
        var key = CF.String("CGSSessionScreenIsLocked");
        try
        {
            var value = CF.Get(session, key);
            return value != IntPtr.Zero && value == CF.True;
        }
        finally
        {
            CF.Release(key);
            CF.Release(session);
        }
    }

    [DllImport(CoreGraphics)] private static extern IntPtr CGSessionCopyCurrentDictionary();
}
