using System.Runtime.InteropServices;
using Keylo.Core;

namespace Keylo.Platform.MacOS.Interop;

/// <summary>SecItem* on generic-password items in the user's login keychain.</summary>
internal static class Keychain
{
    private const string Lib = "/System/Library/Frameworks/Security.framework/Security";

    public const int Success = 0;
    public const int ItemNotFound = -25300;      // errSecItemNotFound
    public const int DuplicateItem = -25299;     // errSecDuplicateItem
    public const int UserCanceled = -128;        // errSecUserCanceled
    public const int InteractionNotAllowed = -25308;

    private static readonly IntPtr Handle = NativeLibrary.Load(Lib);

    public static readonly IntPtr Class = Constant("kSecClass");
    public static readonly IntPtr ClassGenericPassword = Constant("kSecClassGenericPassword");
    public static readonly IntPtr Service = Constant("kSecAttrService");
    public static readonly IntPtr Account = Constant("kSecAttrAccount");
    public static readonly IntPtr Label = Constant("kSecAttrLabel");
    public static readonly IntPtr Generic = Constant("kSecAttrGeneric");
    public static readonly IntPtr ModificationDate = Constant("kSecAttrModificationDate");
    public static readonly IntPtr ValueData = Constant("kSecValueData");
    public static readonly IntPtr ReturnData = Constant("kSecReturnData");
    public static readonly IntPtr ReturnAttributes = Constant("kSecReturnAttributes");
    public static readonly IntPtr MatchLimit = Constant("kSecMatchLimit");
    public static readonly IntPtr MatchLimitOne = Constant("kSecMatchLimitOne");
    public static readonly IntPtr MatchLimitAll = Constant("kSecMatchLimitAll");
    public static readonly IntPtr UseKeychain = Constant("kSecUseKeychain");
    public static readonly IntPtr MatchSearchList = Constant("kSecMatchSearchList");

    /// <summary>A keychain file by path (it must exist and be unlocked to use it).</summary>
    public static IntPtr Open(string path)
    {
        Check(SecKeychainOpen(path, out var keychain), $"open the keychain {path}");
        return keychain;
    }

    private static IntPtr Constant(string symbol) => Marshal.ReadIntPtr(NativeLibrary.GetExport(Handle, symbol));

    /// <summary>Turns a status into an exception; <see cref="ItemNotFound"/> is the caller's to handle.</summary>
    public static void Check(int status, string what)
    {
        if (status == Success) return;
        var message = SecCopyErrorMessageString(status, IntPtr.Zero) is var cf && cf != IntPtr.Zero
            ? CF.ToString(cf) : null;
        CF.Release(cf);
        throw new KeyloException(status switch
        {
            UserCanceled => $"Keychain access was denied ({what}).",
            InteractionNotAllowed => $"The keychain is locked ({what}). Unlock your Mac session and try again.",
            _ => $"Keychain error {status} while trying to {what}{(message is null ? "" : $": {message}")}.",
        });
    }

    [DllImport(Lib)] public static extern int SecItemAdd(IntPtr attributes, IntPtr result);
    [DllImport(Lib)] public static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);
    [DllImport(Lib)] public static extern int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);
    [DllImport(Lib)] public static extern int SecItemDelete(IntPtr query);
    [DllImport(Lib)] private static extern IntPtr SecCopyErrorMessageString(int status, IntPtr reserved);
    [DllImport(Lib)] private static extern int SecKeychainOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string pathName, out IntPtr keychain);
}
