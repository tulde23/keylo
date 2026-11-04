using System.Runtime.InteropServices;
using System.Text;

namespace Keylo.Platform.MacOS.Interop;

/// <summary>The few CoreFoundation calls the Keychain needs: strings, data, dictionaries, arrays, dates.</summary>
internal static class CF
{
    private const string Lib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const uint Utf8 = 0x08000100; // kCFStringEncodingUTF8

    private static readonly IntPtr Handle = NativeLibrary.Load(Lib);

    /// <summary>&amp;kCFTypeDictionaryKeyCallBacks / ValueCallBacks: the symbol's address is what's passed.</summary>
    private static readonly IntPtr KeyCallbacks = NativeLibrary.GetExport(Handle, "kCFTypeDictionaryKeyCallBacks");
    private static readonly IntPtr ValueCallbacks = NativeLibrary.GetExport(Handle, "kCFTypeDictionaryValueCallBacks");

    public static readonly IntPtr True = Constant("kCFBooleanTrue");

    /// <summary>The value of an exported <c>const CFTypeRef</c> (the symbol holds the pointer).</summary>
    public static IntPtr Constant(string symbol) => Marshal.ReadIntPtr(NativeLibrary.GetExport(Handle, symbol));

    public static IntPtr String(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value + "\0");
        return CFStringCreateWithCString(IntPtr.Zero, bytes, Utf8);
    }

    public static string? ToString(IntPtr cfString)
    {
        if (cfString == IntPtr.Zero) return null;
        var length = CFStringGetLength(cfString);
        var max = CFStringGetMaximumSizeForEncoding(length, Utf8) + 1;
        var buffer = new byte[max];
        return CFStringGetCString(cfString, buffer, max, Utf8) ? Encoding.UTF8.GetString(buffer, 0, Array.IndexOf(buffer, (byte)0)) : null;
    }

    public static IntPtr Data(byte[] bytes) => CFDataCreate(IntPtr.Zero, bytes, bytes.Length);

    public static byte[] ToBytes(IntPtr cfData)
    {
        if (cfData == IntPtr.Zero) return [];
        var length = (int)CFDataGetLength(cfData);
        var bytes = new byte[length];
        if (length > 0) Marshal.Copy(CFDataGetBytePtr(cfData), bytes, 0, length);
        return bytes;
    }

    /// <summary>A CFDictionary of the given pairs (keys and values are retained by it).</summary>
    public static IntPtr Dictionary(IReadOnlyList<(IntPtr Key, IntPtr Value)> pairs)
    {
        var keys = pairs.Select(p => p.Key).ToArray();
        var values = pairs.Select(p => p.Value).ToArray();
        return CFDictionaryCreate(IntPtr.Zero, keys, values, keys.Length, KeyCallbacks, ValueCallbacks);
    }

    public static IntPtr Get(IntPtr dictionary, IntPtr key) => CFDictionaryGetValue(dictionary, key);

    /// <summary>A CFArray of CF objects (retained by it).</summary>
    public static IntPtr MakeArray(IntPtr[] values) =>
        CFArrayCreate(IntPtr.Zero, values, values.Length, NativeLibrary.GetExport(Handle, "kCFTypeArrayCallBacks"));

    public static int Count(IntPtr array) => (int)CFArrayGetCount(array);

    public static IntPtr At(IntPtr array, int index) => CFArrayGetValueAtIndex(array, index);

    /// <summary>A CFDate as a DateTimeOffset (CF counts seconds from 2001-01-01 UTC).</summary>
    public static DateTimeOffset? ToDate(IntPtr cfDate) =>
        cfDate == IntPtr.Zero ? null : new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero).AddSeconds(CFDateGetAbsoluteTime(cfDate));

    public static void Release(IntPtr value)
    {
        if (value != IntPtr.Zero) CFRelease(value);
    }

    [DllImport(Lib)] private static extern IntPtr CFStringCreateWithCString(IntPtr alloc, byte[] cStr, uint encoding);
    [DllImport(Lib)] private static extern nint CFStringGetLength(IntPtr str);
    [DllImport(Lib)] private static extern nint CFStringGetMaximumSizeForEncoding(nint length, uint encoding);
    [DllImport(Lib)] [return: MarshalAs(UnmanagedType.U1)] private static extern bool CFStringGetCString(IntPtr str, byte[] buffer, nint bufferSize, uint encoding);
    [DllImport(Lib)] private static extern IntPtr CFDataCreate(IntPtr alloc, byte[] bytes, nint length);
    [DllImport(Lib)] private static extern nint CFDataGetLength(IntPtr data);
    [DllImport(Lib)] private static extern IntPtr CFDataGetBytePtr(IntPtr data);
    [DllImport(Lib)] private static extern IntPtr CFDictionaryCreate(IntPtr alloc, IntPtr[] keys, IntPtr[] values, nint count, IntPtr keyCallBacks, IntPtr valueCallBacks);
    [DllImport(Lib)] private static extern IntPtr CFDictionaryGetValue(IntPtr dict, IntPtr key);
    [DllImport(Lib)] private static extern IntPtr CFArrayCreate(IntPtr alloc, IntPtr[] values, nint count, IntPtr callBacks);
    [DllImport(Lib)] private static extern nint CFArrayGetCount(IntPtr array);
    [DllImport(Lib)] private static extern IntPtr CFArrayGetValueAtIndex(IntPtr array, nint index);
    [DllImport(Lib)] private static extern double CFDateGetAbsoluteTime(IntPtr date);
    [DllImport(Lib)] private static extern void CFRelease(IntPtr value);
}
