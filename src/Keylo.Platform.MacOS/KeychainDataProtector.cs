using System.Security.Cryptography;
using Keylo.Core.Platform;

namespace Keylo.Platform.MacOS;

/// <summary>
/// macOS has no DPAPI, so local files (large values, the session) are sealed with AES-256-GCM under
/// a random master key kept in the login keychain: only this user, with the keychain unlocked, can
/// open them. The entropy is bound in as associated data, as DPAPI's optional entropy is.
/// </summary>
public sealed class KeychainDataProtector(KeychainCredentialStore store) : IDataProtector
{
    private const string MasterKeyItem = "keylo-master-key";
    private const int NonceSize = 12, TagSize = 16;

    private byte[]? _key;
    private readonly Lock _lock = new();

    public byte[] Protect(byte[] data, byte[] entropy)
    {
        var output = new byte[NonceSize + data.Length + TagSize];
        RandomNumberGenerator.Fill(output.AsSpan(0, NonceSize));
        using var aes = new AesGcm(Key(), TagSize);
        aes.Encrypt(output.AsSpan(0, NonceSize), data, output.AsSpan(NonceSize, data.Length), output.AsSpan(NonceSize + data.Length), entropy);
        return output;
    }

    public byte[] Unprotect(byte[] data, byte[] entropy)
    {
        if (data.Length < NonceSize + TagSize) throw new CryptographicException("Protected data is too short.");
        var plain = new byte[data.Length - NonceSize - TagSize];
        using var aes = new AesGcm(Key(), TagSize);
        aes.Decrypt(data.AsSpan(0, NonceSize), data.AsSpan(NonceSize, plain.Length), data.AsSpan(NonceSize + plain.Length), plain, entropy);
        return plain;
    }

    /// <summary>The master key, created on first use. It lives under its own keychain service, away from secrets.</summary>
    private byte[] Key()
    {
        lock (_lock)
        {
            if (_key is not null) return _key;
            var existing = store.Read(MasterKeyItem)?.Blob;
            if (existing is { Length: 32 }) return _key = existing;

            var key = RandomNumberGenerator.GetBytes(32);
            store.Write(MasterKeyItem, key, null, "Keylo's key for its encrypted local files. Deleting it makes those files unreadable.");
            return _key = key;
        }
    }
}
