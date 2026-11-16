using System.Security.Cryptography;
using Keylo.Core;
using Keylo.Core.Platform;
using Keylo.Core.Security;

namespace Keylo.Platform.Linux;

/// <summary>Where Keylo keeps secrets on this Linux machine.</summary>
public enum LinuxStoreKind { Keyring, File }

/// <summary>
/// Keylo on Linux: the desktop keyring (Secret Service) where there is one, else Keylo's own
/// passphrase-protected vault file; polkit for the presence check; wl-clipboard / xclip; /proc.
///
/// The store is chosen once and remembered (store.txt in Keylo's data folder), so a machine never
/// ends up with secrets split between the two. KEYLO_STORE=keyring|file overrides the choice.
/// </summary>
public sealed class LinuxPlatform : IKeyloPlatform
{
    private readonly Lazy<LinuxStoreKind> _kind;
    private readonly Lazy<ICredentialStore> _credentials;
    private readonly Lazy<FileVault> _vault;

    public LinuxPlatform()
    {
        var dataDirectory = KeyloPaths.DefaultDataDirectory;
        _vault = new(() => new FileVault(Path.Combine(dataDirectory, "vault.json")));
        _kind = new(() => ChooseStore(dataDirectory));
        _credentials = new(() => _kind.Value == LinuxStoreKind.Keyring ? new SecretServiceStore() : _vault.Value);
        Credentials = new LazyStore(() => _credentials.Value, () => Remember(dataDirectory));
        DataProtector = new AesKeyProtector(() => _kind.Value == LinuxStoreKind.Keyring
            ? KeyringMasterKey()
            : HKDF.DeriveKey(HashAlgorithmName.SHA256, _vault.Value.Key(), 32, info: "keylo-vault:files:v1"u8.ToArray()));
    }

    public string Name => "Linux";
    public string VerifierName => "system authentication";
    public string StoreName => SafeKind() == LinuxStoreKind.File ? "Keylo's encrypted vault" : "the desktop keyring";
    public string FileProtectionName => SafeKind() == LinuxStoreKind.File ? "vault key" : "keyring key";

    // For UI text: the choice can fail (a remembered keyring that isn't reachable), and help text shouldn't.
    private LinuxStoreKind? SafeKind()
    {
        try { return _kind.Value; }
        catch (KeyloException) { return null; }
    }
    public ICredentialStore Credentials { get; }
    public IDataProtector DataProtector { get; }
    public IUserVerifier Verifier { get; } = new PolkitVerifier();
    public ISecureClipboard Clipboard { get; } = new LinuxClipboard();
    public IProcessAncestry Processes { get; } = new LinuxProcessAncestry();

    public LinuxStoreKind StoreKind => _kind.Value;

    /// <summary>The vault file store, when that's the store in use; null with the desktop keyring.</summary>
    public FileVault? Vault => _kind.Value == LinuxStoreKind.File ? _vault.Value : null;

    /// <summary>The Linux platform in use, if it is.</summary>
    public static LinuxPlatform? Current => KeyloPlatform.IsInstalled ? KeyloPlatform.Current as LinuxPlatform : null;

    /// <summary>Makes Linux the platform for this process. Call once at startup.</summary>
    public static void Install() => KeyloPlatform.Install(new LinuxPlatform());

    private LinuxStoreKind ChooseStore(string dataDirectory)
    {
        var setting = Environment.GetEnvironmentVariable("KEYLO_STORE") ?? Remembered(dataDirectory);
        switch (setting?.Trim().ToLowerInvariant())
        {
            case "keyring":
                if (SecretServiceStore.Probe() is { Available: false, Problem: var problem })
                    throw new KeyloException(
                        $"Keylo keeps its secrets in the desktop keyring here, but the keyring isn't available ({problem}). " +
                        "Use Keylo from your desktop session, or unlock the keyring first.");
                return LinuxStoreKind.Keyring;
            case "file":
                return LinuxStoreKind.File;
        }

        if (_vault.Value.Exists) return LinuxStoreKind.File;
        return SecretServiceStore.Probe().Available ? LinuxStoreKind.Keyring : LinuxStoreKind.File;
    }

    private static string StoreFile(string dataDirectory) => Path.Combine(dataDirectory, "store.txt");

    private static string? Remembered(string dataDirectory)
    {
        try { return File.Exists(StoreFile(dataDirectory)) ? File.ReadAllText(StoreFile(dataDirectory)) : null; }
        catch (IOException) { return null; }
    }

    /// <summary>Records the store on the first write, so later runs use the same one.</summary>
    private void Remember(string dataDirectory)
    {
        if (Environment.GetEnvironmentVariable("KEYLO_STORE") is { Length: > 0 } || File.Exists(StoreFile(dataDirectory))) return;
        Directory.CreateDirectory(dataDirectory);
        File.WriteAllText(StoreFile(dataDirectory), _kind.Value == LinuxStoreKind.Keyring ? "keyring\n" : "file\n");
    }

    /// <summary>The key for protected files with the keyring store: a random key in the keyring, under its own service.</summary>
    private static byte[] KeyringMasterKey()
    {
        const string item = "keylo-master-key";
        var store = new SecretServiceStore(SecretServiceStore.DefaultService + ".Internal");
        if (store.Read(item)?.Blob is { Length: 32 } existing) return existing;
        var key = RandomNumberGenerator.GetBytes(32);
        store.Write(item, key, null, "Keylo's key for its encrypted local files. Deleting it makes those files unreadable.");
        return key;
    }

    /// <summary>Picks the store on first use rather than at startup, so 'keylo version' never prompts.</summary>
    private sealed class LazyStore(Func<ICredentialStore> store, Action onWrite) : ICredentialStore
    {
        public int MaxBlobBytes => store().MaxBlobBytes;
        public int MaxAttributeBytes => store().MaxAttributeBytes;
        public int MaxAttributes => store().MaxAttributes;
        public RawCredential? Read(string target) => store().Read(target);
        public IReadOnlyList<RawCredential> Enumerate(string prefix) => store().Enumerate(prefix);

        public void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null)
        {
            store().Write(target, blob, userName, comment, attributes);
            onWrite();
        }

        public bool Delete(string target) => store().Delete(target);
    }
}

/// <summary>
/// Seals local files (large values, the session) with AES-256-GCM under a key from the store, as
/// on macOS. The entropy is bound in as associated data.
/// </summary>
public sealed class AesKeyProtector(Func<byte[]> key) : IDataProtector
{
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

    private byte[] Key()
    {
        lock (_lock) return _key ??= key();
    }
}
