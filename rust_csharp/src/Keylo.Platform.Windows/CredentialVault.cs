using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Keylo.Core.Platform;
using static Keylo.Platform.Windows.CredentialApi;

namespace Keylo.Platform.Windows;

/// <summary>Safe wrapper over the Cred* API for generic, local-machine credentials.</summary>
internal static class CredentialVault
{
    public static void Write(
        string target,
        byte[] blob,
        string? userName,
        string? comment,
        IReadOnlyDictionary<string, string>? attributes = null)
    {
        if (blob.Length > CRED_MAX_CREDENTIAL_BLOB_SIZE)
            throw new ArgumentException($"Credential blob exceeds {CRED_MAX_CREDENTIAL_BLOB_SIZE} bytes.", nameof(blob));

        var attrs = attributes?.Where(a => !string.IsNullOrEmpty(a.Value)).ToArray() ?? [];
        var attrSize = Marshal.SizeOf<CREDENTIAL_ATTRIBUTE>();
        var blobPtr = IntPtr.Zero;
        var attrArrayPtr = IntPtr.Zero;
        var attrValuePtrs = new List<IntPtr>();

        try
        {
            blobPtr = Marshal.AllocHGlobal(Math.Max(blob.Length, 1));
            Marshal.Copy(blob, 0, blobPtr, blob.Length);

            if (attrs.Length > 0)
            {
                attrArrayPtr = Marshal.AllocHGlobal(attrSize * attrs.Length);
                for (var i = 0; i < attrs.Length; i++)
                {
                    var value = Encoding.UTF8.GetBytes(attrs[i].Value);
                    if (value.Length > CRED_MAX_VALUE_SIZE)
                        throw new ArgumentException($"Attribute '{attrs[i].Key}' exceeds {CRED_MAX_VALUE_SIZE} bytes.");

                    var valuePtr = Marshal.AllocHGlobal(Math.Max(value.Length, 1));
                    attrValuePtrs.Add(valuePtr);
                    Marshal.Copy(value, 0, valuePtr, value.Length);

                    var attr = new CREDENTIAL_ATTRIBUTE
                    {
                        Keyword = attrs[i].Key,
                        ValueSize = (uint)value.Length,
                        Value = valuePtr,
                    };
                    Marshal.StructureToPtr(attr, attrArrayPtr + i * attrSize, fDeleteOld: false);
                }
            }

            var credential = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = target,
                Comment = string.IsNullOrEmpty(comment) ? null : comment,
                CredentialBlobSize = (uint)blob.Length,
                CredentialBlob = blobPtr,
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount = (uint)attrs.Length,
                Attributes = attrArrayPtr,
                UserName = string.IsNullOrEmpty(userName) ? null : userName,
            };

            if (!CredWrite(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"CredWrite failed for '{target}'.");
        }
        finally
        {
            if (blobPtr != IntPtr.Zero)
            {
                // Don't leave a copy of the secret in freed native memory.
                Marshal.Copy(new byte[blob.Length], 0, blobPtr, blob.Length);
                Marshal.FreeHGlobal(blobPtr);
            }

            if (attrArrayPtr != IntPtr.Zero)
            {
                for (var i = 0; i < attrs.Length; i++)
                    Marshal.DestroyStructure<CREDENTIAL_ATTRIBUTE>(attrArrayPtr + i * attrSize);
                Marshal.FreeHGlobal(attrArrayPtr);
            }

            foreach (var p in attrValuePtrs)
                Marshal.FreeHGlobal(p);
        }
    }

    public static RawCredential? Read(string target)
    {
        if (!CredRead(target, CRED_TYPE_GENERIC, 0, out var ptr))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_FOUND) return null;
            throw new Win32Exception(error, $"CredRead failed for '{target}'.");
        }

        try
        {
            return FromPointer(ptr);
        }
        finally
        {
            CredFree(ptr);
        }
    }

    public static bool Exists(string target) => Read(target) is not null;

    public static IReadOnlyList<RawCredential> Enumerate(string filter)
    {
        if (!CredEnumerate(filter, 0, out var count, out var array))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_FOUND) return [];
            throw new Win32Exception(error, $"CredEnumerate failed for '{filter}'.");
        }

        try
        {
            var result = new List<RawCredential>((int)count);
            for (var i = 0; i < count; i++)
            {
                var credPtr = Marshal.ReadIntPtr(array, i * IntPtr.Size);
                result.Add(FromPointer(credPtr));
            }
            return result;
        }
        finally
        {
            CredFree(array);
        }
    }

    public static bool Delete(string target)
    {
        if (CredDelete(target, CRED_TYPE_GENERIC, 0)) return true;

        var error = Marshal.GetLastWin32Error();
        if (error == ERROR_NOT_FOUND) return false;
        throw new Win32Exception(error, $"CredDelete failed for '{target}'.");
    }

    private static RawCredential FromPointer(IntPtr ptr)
    {
        var cred = Marshal.PtrToStructure<CREDENTIAL>(ptr);

        var blob = new byte[cred.CredentialBlobSize];
        if (cred.CredentialBlobSize > 0)
            Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length);

        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var attrSize = Marshal.SizeOf<CREDENTIAL_ATTRIBUTE>();
        for (var i = 0; i < cred.AttributeCount; i++)
        {
            var attr = Marshal.PtrToStructure<CREDENTIAL_ATTRIBUTE>(cred.Attributes + i * attrSize);
            var value = new byte[attr.ValueSize];
            if (attr.ValueSize > 0)
                Marshal.Copy(attr.Value, value, 0, value.Length);
            attributes[attr.Keyword] = Encoding.UTF8.GetString(value);
        }

        var fileTime = ((long)cred.LastWritten.dwHighDateTime << 32) | (uint)cred.LastWritten.dwLowDateTime;

        return new RawCredential(
            cred.TargetName,
            cred.UserName,
            cred.Comment,
            DateTimeOffset.FromFileTime(fileTime),
            blob,
            attributes);
    }
}

/// <summary>Windows Credential Manager as Keylo's <see cref="ICredentialStore"/>: generic credentials, persisted for this user on this machine.</summary>
public sealed class WindowsCredentialStore : ICredentialStore
{
    public int MaxBlobBytes => CRED_MAX_CREDENTIAL_BLOB_SIZE;
    public int MaxAttributeBytes => CRED_MAX_VALUE_SIZE;
    public int MaxAttributes => 64;

    public RawCredential? Read(string target) => CredentialVault.Read(target);

    // Credential Manager filters use '*' as the wildcard.
    public IReadOnlyList<RawCredential> Enumerate(string prefix) => CredentialVault.Enumerate(prefix + "*");

    public void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null) =>
        CredentialVault.Write(target, blob, userName, comment, attributes);

    public bool Delete(string target) => CredentialVault.Delete(target);
}
