using System.Security.Cryptography;
using Keylo.Core.Platform;

namespace Keylo.Platform.Windows;

/// <summary>DPAPI, current-user scope: data only this Windows account on this machine can decrypt.</summary>
public sealed class DpapiProtector : IDataProtector
{
    public byte[] Protect(byte[] data, byte[] entropy) => ProtectedData.Protect(data, entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] data, byte[] entropy) => ProtectedData.Unprotect(data, entropy, DataProtectionScope.CurrentUser);
}
