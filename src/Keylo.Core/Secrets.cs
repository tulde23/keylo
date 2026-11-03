namespace Keylo.Core;

/// <summary>Where a secret's value physically lives.</summary>
public enum StorageKind
{
    /// <summary>Inline in the Credential Manager entry (values up to <see cref="SecretStore.MaxInlineBytes"/>).</summary>
    CredentialManager,

    /// <summary>A DPAPI-encrypted file under the data directory, referenced from the Credential Manager entry.</summary>
    EncryptedFile,
}

/// <summary>
/// Everything about a secret except its value. Safe to list and display. <see cref="Icon"/> is an
/// icon name chosen in the app and <see cref="Color"/> a "#RRGGBB" accent; both are optional.
/// </summary>
public sealed record SecretInfo(
    string Name,
    string? Category,
    string? Username,
    string? Notes,
    DateTimeOffset UpdatedAt,
    int Size,
    StorageKind Storage,
    string? Icon = null,
    string? Color = null);

/// <summary>A secret together with its value.</summary>
public sealed record Secret(SecretInfo Info, byte[] Value);

/// <summary>The fields supplied when adding or updating a secret.</summary>
public sealed record SecretDraft(
    string Name,
    byte[] Value,
    string? Category = null,
    string? Username = null,
    string? Notes = null,
    string? Icon = null,
    string? Color = null);

public class KeyloException(string message) : Exception(message);

public sealed class SecretNotFoundException(string name)
    : KeyloException($"No secret named '{name}'.");

public sealed class SecretExistsException(string name)
    : KeyloException($"A secret named '{name}' already exists.");
