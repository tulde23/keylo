namespace Keylo.Core.Providers;

/// <summary>An item found in a linked vault (no values).</summary>
/// <param name="Location">Provider-specific scope such as a 1Password account; null when the provider has only one.</param>
public sealed record LinkedItemSummary(
    string ItemId,
    string Title,
    string? VaultId,
    string? VaultName,
    string? Location,
    string? Category);

/// <summary>A field of a linked item. <see cref="Id"/> must be stable between describing and resolving an item.</summary>
public sealed record LinkedField(string Id, string Label, bool Secret);

/// <summary>Where a linked secret lives in its vault.</summary>
public sealed record LinkTarget(string Provider, string ItemId, string? VaultId, string? Location);

/// <summary>
/// A vault Keylo can link secrets to: a Keylo secret then holds only a reference, and the value
/// is read from the vault each time it's used (never copied into Keylo). Built in: 1Password.
/// Plugins in %LOCALAPPDATA%\Keylo\plugins can implement this (with or without
/// <see cref="IVaultProvider"/>), e.g. for Bitwarden, KeePass, Azure Key Vault or AWS Secrets Manager.
///
/// Values must never travel on a command line; read them from an API or a process's stdout.
/// </summary>
public interface ILinkedVaultProvider
{
    /// <summary>Stable id stored in links, e.g. "1password". Shared with <see cref="IVaultProvider.Id"/> when a class is both.</summary>
    string Id { get; }

    string DisplayName { get; }

    /// <summary>Settings read from config ("providers.{id}"), with a description of each.</summary>
    IReadOnlyDictionary<string, string> SettingDescriptions { get; }

    /// <summary>Whether the provider can be used with these settings (cheap, no I/O).</summary>
    bool IsConfigured(IReadOnlyDictionary<string, string> settings) => true;

    /// <summary>Items whose title (or vault/category) contains <paramref name="query"/>; all items when it's empty.</summary>
    Task<IReadOnlyList<LinkedItemSummary>> SearchAsync(string? query, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);

    /// <summary>The item's fields, without values.</summary>
    Task<IReadOnlyList<LinkedField>> DescribeAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);

    /// <summary>The item's current field values, keyed by <see cref="LinkedField.Id"/>.</summary>
    Task<IReadOnlyDictionary<string, string>> ResolveAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);
}
