using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Keylo.Core.Native;

namespace Keylo.Core;

/// <summary>
/// Secrets stored as generic Credential Manager entries named "{prefix}{name}".
///
/// Each entry's blob starts with a one-byte kind tag:
///   0x01 inline: the remaining bytes are the value.
///   0x02 file:   a 16-byte id and a 4-byte length; the value is a DPAPI-encrypted file
///                blobs\{id}.bin, for values too large for Credential Manager.
///
/// Username and notes use the credential's own UserName and Comment fields (so they show in
/// Control Panel's Credential Manager); the category is a credential attribute.
/// </summary>
public sealed class SecretStore
{
    public const string DefaultPrefix = "Keylo:";

    public const int MaxInlineBytes = Native.CredentialApi.CRED_MAX_CREDENTIAL_BLOB_SIZE - 1;
    public const int MaxValueBytes = 4 * 1024 * 1024;
    public const int MaxNameLength = 128;
    public const int MaxCategoryLength = 64;
    public const int MaxUsernameLength = 512;
    public const int MaxNotesLength = 255;

    private const byte KindInline = 0x01;
    private const byte KindFile = 0x02;
    private const string CategoryAttribute = "KeyloCategory";
    private const string IconAttribute = "KeyloIcon";
    private const string ColorAttribute = "KeyloColor";

    private readonly string _prefix;
    private readonly string _blobDirectory;

    public SecretStore(string? dataDirectory = null, string? prefix = null)
    {
        _prefix = prefix ?? KeyloPaths.CredentialPrefix;
        _blobDirectory = Path.Combine(dataDirectory ?? KeyloPaths.DefaultDataDirectory, "blobs");
    }

    public IReadOnlyList<SecretInfo> List() =>
        CredentialVault.Enumerate(_prefix + "*")
            .Select(ToInfo)
            .OfType<SecretInfo>()
            .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public IReadOnlyList<string> Categories() =>
        List()
            .Select(s => s.Category)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();

    public SecretInfo? Find(string name) =>
        CredentialVault.Read(Target(name)) is { } raw ? ToInfo(raw) : null;

    public bool Exists(string name) => Find(name) is not null;

    public Secret Get(string name)
    {
        var raw = CredentialVault.Read(Target(name)) ?? throw new SecretNotFoundException(name);
        var info = ToInfo(raw) ?? throw new KeyloException($"'{name}' is not a Keylo secret or is corrupt.");

        if (raw.Blob[0] == KindInline)
            return new Secret(info, raw.Blob[1..]);

        var (id, length) = ReadFileReference(raw.Blob);
        var path = BlobPath(id);
        if (!File.Exists(path))
            throw new KeyloException($"The encrypted file for '{name}' is missing ({path}).");

        var value = ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy(id), DataProtectionScope.CurrentUser);
        if (value.Length != length)
            throw new KeyloException($"The encrypted file for '{name}' does not match its entry.");

        return new Secret(info, value);
    }

    /// <summary>
    /// Adds a secret, or updates one when <paramref name="originalName"/> is given (which may differ
    /// from the draft's name, renaming it). Adding fails if the name is taken; so does renaming onto
    /// another existing secret.
    /// </summary>
    public SecretInfo Save(SecretDraft draft, string? originalName = null)
    {
        var name = NormalizeName(draft.Name);
        var category = NormalizeOptional(draft.Category, MaxCategoryLength, "Category");
        var username = NormalizeOptional(draft.Username, MaxUsernameLength, "Username");
        var notes = NormalizeOptional(draft.Notes, MaxNotesLength, "Notes", allowNewlines: true);

        if (draft.Value.Length > MaxValueBytes)
            throw new KeyloException($"Value is larger than {MaxValueBytes / (1024 * 1024)} MB.");

        RawCredential? previous = null;
        var renaming = false;
        if (originalName is not null)
        {
            previous = CredentialVault.Read(Target(originalName)) ?? throw new SecretNotFoundException(originalName);
            renaming = !string.Equals(originalName, name, StringComparison.Ordinal);
            var caseOnly = renaming && string.Equals(originalName, name, StringComparison.OrdinalIgnoreCase);
            if (renaming && !caseOnly && Exists(name))
                throw new SecretExistsException(name);
        }
        else if (Exists(name))
        {
            throw new SecretExistsException(name);
        }

        Guid? newFileId = null;
        byte[] blob;
        if (draft.Value.Length <= MaxInlineBytes)
        {
            blob = new byte[draft.Value.Length + 1];
            blob[0] = KindInline;
            draft.Value.CopyTo(blob, 1);
        }
        else
        {
            newFileId = Guid.NewGuid();
            WriteBlobFile(newFileId.Value, draft.Value);
            blob = new byte[1 + 16 + 4];
            blob[0] = KindFile;
            newFileId.Value.TryWriteBytes(blob.AsSpan(1, 16));
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(17, 4), draft.Value.Length);
        }

        var attributes = Attributes(category, NormalizeIcon(draft.Icon), NormalizeColor(draft.Color));

        try
        {
            // Credential Manager names are case-insensitive, so a case-only rename has to remove
            // the old entry first or the write lands on it and keeps the old spelling.
            if (renaming && string.Equals(originalName, name, StringComparison.OrdinalIgnoreCase))
                CredentialVault.Delete(Target(originalName!));

            CredentialVault.Write(Target(name), blob, username, notes, attributes);
        }
        catch
        {
            if (newFileId is { } orphan) TryDelete(BlobPath(orphan));
            if (previous is not null && !CredentialVault.Exists(previous.Target))
                CredentialVault.Write(previous.Target, previous.Blob, previous.UserName, previous.Comment, previous.Attributes);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
        }

        if (renaming && !string.Equals(originalName, name, StringComparison.OrdinalIgnoreCase))
            CredentialVault.Delete(Target(originalName!));

        if (previous is not null && previous.Blob[0] == KindFile)
        {
            var (oldId, _) = ReadFileReference(previous.Blob);
            if (oldId != newFileId) TryDelete(BlobPath(oldId));
        }

        return Find(name)!;
    }

    /// <summary>
    /// Changes category, icon and/or colour without reading the value: the stored blob is written
    /// back as-is, so large (file-backed) values are never decrypted. A null argument keeps the
    /// current setting; an empty string clears it.
    /// </summary>
    public SecretInfo UpdateDetails(string name, string? category = null, string? icon = null, string? color = null)
    {
        var raw = CredentialVault.Read(Target(name)) ?? throw new SecretNotFoundException(name);
        var info = ToInfo(raw) ?? throw new KeyloException($"'{name}' is not a Keylo secret or is corrupt.");

        var attributes = Attributes(
            category is null ? info.Category : NormalizeOptional(category, MaxCategoryLength, "Category"),
            icon is null ? info.Icon : NormalizeIcon(icon),
            color is null ? info.Color : NormalizeColor(color));

        try
        {
            CredentialVault.Write(raw.Target, raw.Blob, raw.UserName, raw.Comment, attributes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw.Blob);
        }

        return Find(name)!;
    }

    /// <summary>Moves every secret in <paramref name="from"/> to <paramref name="to"/> (null: uncategorized). Returns how many moved.</summary>
    public int RecategorizeAll(string from, string? to)
    {
        var moved = 0;
        foreach (var secret in List().Where(s => string.Equals(s.Category, from, StringComparison.OrdinalIgnoreCase)))
        {
            UpdateDetails(secret.Name, category: to ?? "");
            moved++;
        }
        return moved;
    }

    public bool Delete(string name)
    {
        var raw = CredentialVault.Read(Target(name));
        if (raw is null) return false;

        CredentialVault.Delete(raw.Target);
        if (raw.Blob.Length > 0 && raw.Blob[0] == KindFile)
            TryDelete(BlobPath(ReadFileReference(raw.Blob).Id));
        return true;
    }

    public static bool IsValidName(string? name)
    {
        try
        {
            NormalizeName(name ?? "");
            return true;
        }
        catch (KeyloException)
        {
            return false;
        }
    }

    public static string NormalizeName(string name)
    {
        name = name.Trim();
        if (name.Length == 0)
            throw new KeyloException("Name is required.");
        if (name.Length > MaxNameLength)
            throw new KeyloException($"Name is longer than {MaxNameLength} characters.");
        if (name.Any(char.IsControl))
            throw new KeyloException("Name cannot contain control characters.");
        // '*' is the wildcard in Credential Manager filters, so a name containing it would match others.
        if (name.Contains('*'))
            throw new KeyloException("Name cannot contain '*'.");
        return name;
    }

    private static string? NormalizeOptional(string? value, int maxLength, string field, bool allowNewlines = false)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value)) return null;
        if (value.Length > maxLength)
            throw new KeyloException($"{field} is longer than {maxLength} characters.");
        if (value.Any(c => char.IsControl(c) && !(allowNewlines && c is '\n' or '\r' or '\t')))
            throw new KeyloException($"{field} cannot contain control characters.");
        return value;
    }

    /// <summary>Icon names are identifiers like "Cloud24"; anything else is rejected.</summary>
    internal static string? NormalizeIcon(string? icon)
    {
        icon = icon?.Trim();
        if (string.IsNullOrEmpty(icon)) return null;
        if (icon.Length > 64 || !icon.All(char.IsAsciiLetterOrDigit))
            throw new KeyloException($"'{icon}' isn't a valid icon name.");
        return icon;
    }

    /// <summary>Colours are "#RRGGBB".</summary>
    internal static string? NormalizeColor(string? color)
    {
        color = color?.Trim();
        if (string.IsNullOrEmpty(color)) return null;
        if (color.Length != 7 || color[0] != '#' || !color[1..].All(char.IsAsciiHexDigit))
            throw new KeyloException($"'{color}' isn't a colour like #6366F1.");
        return color.ToUpperInvariant();
    }

    private static Dictionary<string, string> Attributes(string? category, string? icon, string? color)
    {
        var attributes = new Dictionary<string, string>();
        if (category is not null) attributes[CategoryAttribute] = category;
        if (icon is not null) attributes[IconAttribute] = icon;
        if (color is not null) attributes[ColorAttribute] = color;
        return attributes;
    }

    private string Target(string name) => _prefix + name.Trim();

    private SecretInfo? ToInfo(RawCredential raw)
    {
        if (raw.Blob.Length == 0 || !raw.Target.StartsWith(_prefix, StringComparison.OrdinalIgnoreCase))
            return null;

        int size;
        StorageKind storage;
        switch (raw.Blob[0])
        {
            case KindInline:
                size = raw.Blob.Length - 1;
                storage = StorageKind.CredentialManager;
                break;
            case KindFile when raw.Blob.Length == 21:
                size = ReadFileReference(raw.Blob).Length;
                storage = StorageKind.EncryptedFile;
                break;
            default:
                return null;
        }

        raw.Attributes.TryGetValue(CategoryAttribute, out var category);
        raw.Attributes.TryGetValue(IconAttribute, out var icon);
        raw.Attributes.TryGetValue(ColorAttribute, out var color);

        return new SecretInfo(
            raw.Target[_prefix.Length..],
            string.IsNullOrEmpty(category) ? null : category,
            raw.UserName,
            raw.Comment,
            raw.LastWritten,
            size,
            storage,
            string.IsNullOrEmpty(icon) ? null : icon,
            string.IsNullOrEmpty(color) ? null : color);
    }

    private static (Guid Id, int Length) ReadFileReference(byte[] blob) =>
        (new Guid(blob.AsSpan(1, 16)), BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(17, 4)));

    private string BlobPath(Guid id) => Path.Combine(_blobDirectory, id.ToString("N") + ".bin");

    private static byte[] Entropy(Guid id) => Encoding.UTF8.GetBytes("keylo:blob:" + id.ToString("N"));

    private void WriteBlobFile(Guid id, byte[] value)
    {
        Directory.CreateDirectory(_blobDirectory);
        var path = BlobPath(id);
        var temp = path + ".tmp";
        File.WriteAllBytes(temp, ProtectedData.Protect(value, Entropy(id), DataProtectionScope.CurrentUser));
        File.Move(temp, path, overwrite: true);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
