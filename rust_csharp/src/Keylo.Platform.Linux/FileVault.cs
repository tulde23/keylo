using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Keylo.Core;
using Keylo.Core.Platform;

namespace Keylo.Platform.Linux;

/// <summary>
/// Keylo's own encrypted store, for Linux machines without a desktop keyring (servers, containers,
/// WSL). One file holds every item, sealed with AES-256-GCM under a random vault key; the vault key
/// is wrapped with a key derived from the user's passphrase (PBKDF2-SHA256, 600,000 iterations).
///
/// The passphrase comes from KEYLO_PASSPHRASE or KEYLO_PASSPHRASE_FILE, or is asked for on the
/// terminal; the unlocked vault key is then cached in the kernel keyring for
/// KEYLO_VAULT_CACHE_MINUTES (15 by default) so later commands don't ask again.
/// </summary>
public sealed class FileVault : ICredentialStore
{
    private const int Iterations = 600_000, KeySize = 32, NonceSize = 12, TagSize = 16;
    private static readonly byte[] KeyAad = "keylo-vault:key:v1"u8.ToArray();
    private static readonly byte[] DataAad = "keylo-vault:data:v1"u8.ToArray();

    private readonly string _path;
    private readonly string _cacheName;
    private byte[]? _key;

    public FileVault(string path)
    {
        _path = path;
        _cacheName = "keylo:vault:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(System.IO.Path.GetFullPath(path))))[..16];
    }

    /// <summary>Whether terminal prompts are allowed (the CLI, not the MCP server or the app).</summary>
    public static bool CanPromptOnTerminal { get; set; }

    public string Path => _path;
    public bool Exists => File.Exists(_path);
    public bool IsUnlocked => _key is not null;

    public int MaxBlobBytes => 16 * 1024;
    public int MaxAttributeBytes => 1024;
    public int MaxAttributes => 64;

    private sealed record Item(string Target, string? UserName, string? Comment, DateTimeOffset LastWritten, string Blob, Dictionary<string, string> Attributes);
    private sealed record Kdf(string Alg, int Iterations, string Salt);
    private sealed record Envelope(string Format, int Version, Kdf Kdf, string Key, string Data);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>The vault key for other uses (protected files), unlocking first if needed.</summary>
    internal byte[] Key()
    {
        EnsureUnlocked();
        return _key!;
    }

    /// <summary>Unlocks without asking: a cached key, KEYLO_PASSPHRASE, or KEYLO_PASSPHRASE_FILE.</summary>
    public bool TryUnlockQuietly()
    {
        if (_key is not null) return true;
        if (!Exists) return false;

        if (KernelKeyCache.Get(_cacheName) is { Length: KeySize } cached && Decrypts(cached))
        {
            _key = cached;
            return true;
        }
        if (EnvironmentPassphrase() is { } passphrase)
        {
            Unlock(passphrase);
            return true;
        }
        return false;
    }

    /// <summary>Unlocks with <paramref name="passphrase"/>; throws <see cref="KeyloException"/> when it's wrong.</summary>
    public void Unlock(string passphrase)
    {
        var envelope = Load() ?? throw new KeyloException($"There's no Keylo vault at {_path}.");
        var kek = Rfc2898DeriveBytes.Pbkdf2(passphrase, Convert.FromBase64String(envelope.Kdf.Salt), envelope.Kdf.Iterations, HashAlgorithmName.SHA256, KeySize);
        try
        {
            _key = Open(kek, Convert.FromBase64String(envelope.Key), KeyAad);
        }
        catch (CryptographicException)
        {
            throw new KeyloException("That passphrase doesn't unlock Keylo's vault.");
        }
        Cache();
    }

    /// <summary>Creates an empty vault protected by <paramref name="passphrase"/>.</summary>
    public void Create(string passphrase)
    {
        if (Exists) throw new KeyloException($"A Keylo vault already exists at {_path}.");
        var key = RandomNumberGenerator.GetBytes(KeySize);
        var salt = RandomNumberGenerator.GetBytes(16);
        var kek = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Iterations, HashAlgorithmName.SHA256, KeySize);
        var envelope = new Envelope("keylo-vault", 1, new Kdf("pbkdf2-sha256", Iterations, Convert.ToBase64String(salt)),
            Convert.ToBase64String(Seal(kek, key, KeyAad)), "");
        _key = key;
        WithLock(() => Save(envelope, []));
        Cache();
    }

    /// <summary>Forgets the vault key here and in the kernel keyring.</summary>
    public void Lock()
    {
        if (_key is not null) CryptographicOperations.ZeroMemory(_key);
        _key = null;
        KernelKeyCache.Remove(_cacheName);
    }

    public RawCredential? Read(string target) =>
        Items().FirstOrDefault(i => i.Target.Equals(target, StringComparison.OrdinalIgnoreCase)) is { } item ? ToCredential(item) : null;

    public IReadOnlyList<RawCredential> Enumerate(string prefix) =>
        Items().Where(i => i.Target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).Select(ToCredential).ToList();

    public void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null) =>
        Change(items =>
        {
            items.RemoveAll(i => i.Target.Equals(target, StringComparison.OrdinalIgnoreCase));
            items.Add(new Item(target, userName, comment, DateTimeOffset.Now, Convert.ToBase64String(blob),
                attributes?.Where(a => !string.IsNullOrEmpty(a.Value)).ToDictionary(a => a.Key, a => a.Value) ?? []));
            return true;
        });

    public bool Delete(string target) =>
        Change(items => items.RemoveAll(i => i.Target.Equals(target, StringComparison.OrdinalIgnoreCase)) > 0);

    private static RawCredential ToCredential(Item item) =>
        new(item.Target, item.UserName, item.Comment, item.LastWritten, Convert.FromBase64String(item.Blob), item.Attributes);

    private void EnsureUnlocked()
    {
        if (TryUnlockQuietly()) return;

        if (!Exists)
        {
            if (EnvironmentPassphrase() is { } fromEnvironment)
            {
                if (KeyloBackup.CheckPassword(fromEnvironment) is { } weak) throw new KeyloException($"KEYLO_PASSPHRASE can't protect a new vault: {weak}");
                Create(fromEnvironment);
                return;
            }
            if (!CanPromptOnTerminal || !TerminalPrompt.Available)
                throw new KeyloException(
                    "Keylo has no vault yet and there's no desktop keyring. Run any keylo command in a terminal " +
                    "to create one (it asks for a passphrase), or set KEYLO_PASSPHRASE.");
            Console.Error.WriteLine($"No desktop keyring here, so Keylo keeps secrets in an encrypted vault ({_path}).");
            while (true)
            {
                var first = TerminalPrompt.ReadHidden("New vault passphrase: ") ?? throw new KeyloException("Canceled.");
                if (KeyloBackup.CheckPassword(first) is { } problem) { Console.Error.WriteLine(problem); continue; }
                if (TerminalPrompt.ReadHidden("Repeat it: ") != first) { Console.Error.WriteLine("They don't match."); continue; }
                Create(first);
                Console.Error.WriteLine("Vault created. Don't lose the passphrase: without it the vault can't be opened.");
                return;
            }
        }

        if (!CanPromptOnTerminal || !TerminalPrompt.Available)
            throw new KeyloException(
                "Keylo's vault is locked. Run 'keylo unlock' in a terminal (it stays unlocked for a while), " +
                "or set KEYLO_PASSPHRASE / KEYLO_PASSPHRASE_FILE.");
        for (var attempt = 1; ; attempt++)
        {
            var passphrase = TerminalPrompt.ReadHidden("Keylo vault passphrase: ") ?? throw new KeyloException("Canceled.");
            try
            {
                Unlock(passphrase);
                return;
            }
            catch (KeyloException) when (attempt < 3)
            {
                Console.Error.WriteLine("That's not it. Try again.");
            }
        }
    }

    private static string? EnvironmentPassphrase()
    {
        if (Environment.GetEnvironmentVariable("KEYLO_PASSPHRASE") is { Length: > 0 } passphrase) return passphrase;
        if (Environment.GetEnvironmentVariable("KEYLO_PASSPHRASE_FILE") is { Length: > 0 } file)
        {
            try { return File.ReadAllText(file).TrimEnd('\r', '\n'); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new KeyloException($"Couldn't read KEYLO_PASSPHRASE_FILE ({file}): {ex.Message}");
            }
        }
        return null;
    }

    private void Cache()
    {
        var minutes = int.TryParse(Environment.GetEnvironmentVariable("KEYLO_VAULT_CACHE_MINUTES"), out var m) ? m : 15;
        if (_key is not null) KernelKeyCache.Put(_cacheName, _key, TimeSpan.FromMinutes(minutes));
    }

    private bool Decrypts(byte[] key)
    {
        try
        {
            if (Load() is not { } envelope) return false;
            if (envelope.Data.Length > 0) Open(key, Convert.FromBase64String(envelope.Data), DataAad);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private List<Item> Items()
    {
        EnsureUnlocked();
        return Decrypt(Load());
    }

    private List<Item> Decrypt(Envelope? envelope)
    {
        if (envelope is null || envelope.Data.Length == 0) return [];
        try
        {
            return JsonSerializer.Deserialize<List<Item>>(Open(_key!, Convert.FromBase64String(envelope.Data), DataAad), Json) ?? [];
        }
        catch (CryptographicException)
        {
            throw new KeyloException($"Keylo's vault ({_path}) is damaged or was changed outside Keylo.");
        }
    }

    /// <summary>Read, change and write the items under a lock, so the CLI, app and MCP server can't overwrite each other.</summary>
    private bool Change(Func<List<Item>, bool> change)
    {
        EnsureUnlocked();
        return WithLock(() =>
        {
            var envelope = Load() ?? throw new KeyloException($"Keylo's vault ({_path}) is missing.");
            var items = Decrypt(envelope);
            if (!change(items)) return false;
            Save(envelope, items);
            return true;
        });
    }

    private void Save(Envelope envelope, List<Item> items)
    {
        var data = Seal(_key!, JsonSerializer.SerializeToUtf8Bytes(items, Json), DataAad);
        var json = JsonSerializer.SerializeToUtf8Bytes(envelope with { Data = Convert.ToBase64String(data) }, Json);

        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);
        var temp = _path + ".tmp";
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite; // 0600
        using (var stream = new FileStream(temp, options))
        {
            stream.Write(json);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temp, _path, overwrite: true);
    }

    private Envelope? Load()
    {
        if (!File.Exists(_path)) return null;
        try
        {
            return JsonSerializer.Deserialize<Envelope>(File.ReadAllBytes(_path), Json)
                   ?? throw new KeyloException($"Keylo's vault ({_path}) is empty.");
        }
        catch (JsonException)
        {
            throw new KeyloException($"Keylo's vault ({_path}) isn't readable.");
        }
    }

    private T WithLock<T>(Func<T> action)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (true)
        {
            try
            {
                using var _ = new FileStream(_path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                return action();
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }
        }
    }

    private void WithLock(Action action) => WithLock(() => { action(); return true; });

    private static byte[] Seal(byte[] key, byte[] plain, byte[] aad)
    {
        var output = new byte[NonceSize + plain.Length + TagSize];
        RandomNumberGenerator.Fill(output.AsSpan(0, NonceSize));
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(output.AsSpan(0, NonceSize), plain, output.AsSpan(NonceSize, plain.Length), output.AsSpan(NonceSize + plain.Length), aad);
        return output;
    }

    private static byte[] Open(byte[] key, byte[] sealedData, byte[] aad)
    {
        if (sealedData.Length < NonceSize + TagSize) throw new CryptographicException("Too short.");
        var plain = new byte[sealedData.Length - NonceSize - TagSize];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(sealedData.AsSpan(0, NonceSize), sealedData.AsSpan(NonceSize, plain.Length), sealedData.AsSpan(NonceSize + plain.Length), plain, aad);
        return plain;
    }
}
