using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keylo.Core;

public sealed class BackupPasswordException() : KeyloException("Wrong password, or the backup file is damaged.");

public sealed record BackupSecret(string Name, string? Category, string? Username, string? Notes, string? Icon, string? Color, byte[] Value);

/// <summary>A decrypted backup, held in memory only.</summary>
public sealed record BackupContents(
    DateTimeOffset CreatedAt,
    IReadOnlyList<BackupSecret> Secrets,
    IReadOnlyDictionary<string, CategoryStyle> Categories,
    IReadOnlyDictionary<string, byte[]> Icons);

public sealed record BackupSummary(string Path, int Secrets, int Categories, int Icons, long Bytes);

public sealed record RestoreResult(int Added, int Replaced, int Skipped, int CategoriesAdded, IReadOnlyList<string> Errors);

/// <summary>
/// Password-protected backups, portable to another Windows account or PC (unlike DPAPI).
///
/// File layout (all integers little-endian):
///   "KEYLOBK1"  8-byte magic
///   version     1 byte (1)
///   iterations  4 bytes, PBKDF2-SHA256
///   salt        16 bytes
///   nonce       12 bytes
///   ciphertext  AES-256-GCM of the gzip-compressed JSON payload
///   tag         16 bytes
/// The header (everything before the ciphertext) is the GCM associated data, so changing the
/// iteration count or salt is detected rather than silently weakening the file. Nothing about the
/// secrets, not even their names, is readable without the password.
/// </summary>
public static class KeyloBackup
{
    public const int MinPasswordLength = 10;
    public const int DefaultIterations = 600_000; // OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256
    public const string FileExtension = ".keylo";

    private static readonly byte[] Magic = "KEYLOBK1"u8.ToArray();
    private const byte Version = 1;
    private const int SaltSize = 16, NonceSize = 12, TagSize = 16, KeySize = 32;
    private const int HeaderSize = 8 + 1 + 4 + SaltSize + NonceSize;
    private const int MaxIterations = 10_000_000;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string? CheckPassword(ReadOnlySpan<char> password) =>
        password.Length < MinPasswordLength ? $"Use at least {MinPasswordLength} characters — a passphrase of a few words is ideal." : null;

    /// <summary>Writes every secret, category and uploaded icon to <paramref name="path"/>, encrypted with <paramref name="password"/>.</summary>
    public static BackupSummary Create(SecretStore store, CategoryCatalog catalog, string path, ReadOnlySpan<char> password, int iterations = DefaultIterations)
    {
        if (CheckPassword(password) is { } problem) throw new KeyloException(problem);

        var infos = store.List();
        var secrets = infos.Select(info => new BackupSecret(info.Name, info.Category, info.Username, info.Notes, info.Icon, info.Color, store.Get(info.Name).Value)).ToList();
        var categories = catalog.All(infos).ToDictionary(c => c.Name, c => new CategoryStyle { Icon = c.Icon, Color = c.Color }, StringComparer.OrdinalIgnoreCase);

        // Only the uploaded images something still refers to.
        var icons = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var icon in secrets.Select(s => s.Icon).Concat(categories.Values.Select(c => c.Icon)).OfType<string>().Distinct())
        {
            var file = Path.Combine(KeyloPaths.IconDirectory, icon.Length > 3 ? icon[3..] + ".png" : "");
            if (icon.StartsWith("img", StringComparison.Ordinal) && File.Exists(file)) icons[icon] = File.ReadAllBytes(file);
        }

        var payload = Compress(JsonSerializer.SerializeToUtf8Bytes(new Payload(DateTimeOffset.Now, secrets, categories, icons), Json));
        try
        {
            var file = Encrypt(payload, password, iterations);
            var temp = path + ".tmp";
            File.WriteAllBytes(temp, file);
            File.Move(temp, path, overwrite: true);
            return new BackupSummary(path, secrets.Count, categories.Count, icons.Count, file.Length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            foreach (var secret in secrets) CryptographicOperations.ZeroMemory(secret.Value);
        }
    }

    /// <summary>Decrypts a backup. Throws <see cref="BackupPasswordException"/> for a wrong password or a damaged file.</summary>
    public static BackupContents Read(string path, ReadOnlySpan<char> password)
    {
        var file = File.ReadAllBytes(path);
        if (file.Length < HeaderSize + TagSize || !file.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new KeyloException($"'{Path.GetFileName(path)}' isn't a Keylo backup.");
        if (file[8] != Version)
            throw new KeyloException($"This backup was made by a newer version of Keylo (format {file[8]}).");

        var iterations = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(9, 4));
        if (iterations is < 1 or > MaxIterations) throw new BackupPasswordException();

        var header = file.AsSpan(0, HeaderSize);
        var salt = file.AsSpan(13, SaltSize);
        var nonce = file.AsSpan(13 + SaltSize, NonceSize);
        var ciphertext = file.AsSpan(HeaderSize, file.Length - HeaderSize - TagSize);
        var tag = file.AsSpan(file.Length - TagSize);

        var key = DeriveKey(password, salt, iterations);
        var compressed = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, compressed, header);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new BackupPasswordException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        var json = Decompress(compressed);
        CryptographicOperations.ZeroMemory(compressed);
        try
        {
            var payload = JsonSerializer.Deserialize<Payload>(json, Json) ?? throw new BackupPasswordException();
            return new BackupContents(payload.CreatedAt, payload.Secrets, payload.Categories, payload.Icons);
        }
        catch (JsonException)
        {
            throw new KeyloException("The backup decrypted but its contents are unreadable.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }
    }

    /// <summary>
    /// Restores into this machine's store. Existing secrets are skipped unless <paramref name="overwrite"/>;
    /// categories are always merged (their styles only replace existing ones when overwriting).
    /// </summary>
    public static RestoreResult Restore(SecretStore store, CategoryCatalog catalog, BackupContents contents, bool overwrite)
    {
        Directory.CreateDirectory(KeyloPaths.IconDirectory);
        foreach (var (icon, png) in contents.Icons)
        {
            var file = Path.Combine(KeyloPaths.IconDirectory, icon[3..] + ".png");
            if (icon.StartsWith("img", StringComparison.Ordinal) && icon.Length == 35 && icon[3..].All(char.IsAsciiHexDigit) && !File.Exists(file))
                File.WriteAllBytes(file, png);
        }

        var categoriesAdded = contents.Categories.Count(c => catalog.Merge(c.Key, c.Value, overwrite));

        int added = 0, replaced = 0, skipped = 0;
        var errors = new List<string>();
        foreach (var secret in contents.Secrets)
        {
            try
            {
                var existing = store.Find(secret.Name);
                if (existing is not null && !overwrite)
                {
                    skipped++;
                    continue;
                }

                store.Save(new SecretDraft(secret.Name, secret.Value, secret.Category, secret.Username, secret.Notes, secret.Icon, secret.Color),
                    originalName: existing?.Name);
                if (existing is null) added++; else replaced++;
            }
            catch (KeyloException ex)
            {
                errors.Add($"{secret.Name}: {ex.Message}");
            }
        }

        return new RestoreResult(added, replaced, skipped, categoriesAdded, errors);
    }

    private static byte[] Encrypt(byte[] plaintext, ReadOnlySpan<char> password, int iterations)
    {
        var file = new byte[HeaderSize + plaintext.Length + TagSize];
        Magic.CopyTo(file, 0);
        file[8] = Version;
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(9, 4), iterations);
        RandomNumberGenerator.Fill(file.AsSpan(13, SaltSize));
        RandomNumberGenerator.Fill(file.AsSpan(13 + SaltSize, NonceSize));

        var key = DeriveKey(password, file.AsSpan(13, SaltSize), iterations);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(file.AsSpan(13 + SaltSize, NonceSize), plaintext, file.AsSpan(HeaderSize, plaintext.Length),
                file.AsSpan(file.Length - TagSize), file.AsSpan(0, HeaderSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return file;
    }

    private static byte[] DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt, int iterations)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password.ToArray());
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static byte[] Compress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true)) gzip.Write(data);
        CryptographicOperations.ZeroMemory(data);
        return output.ToArray();
    }

    private static byte[] Decompress(byte[] data)
    {
        using var input = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
    }

    private sealed record Payload(
        DateTimeOffset CreatedAt,
        List<BackupSecret> Secrets,
        Dictionary<string, CategoryStyle> Categories,
        Dictionary<string, byte[]> Icons);
}
