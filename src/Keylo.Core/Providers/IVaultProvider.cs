namespace Keylo.Core.Providers;

/// <summary>Whether a provider can be used right now, and if not, what the user should do.</summary>
public sealed record ProviderStatus(bool Ready, string Message);

public sealed record PushResult(string Name, bool Succeeded, string Message, string? RemoteId = null);

/// <summary>Where a push would go, shown to the user before it happens.</summary>
/// <param name="Target">E.g. "the “Private” vault (my.1password.com)".</param>
/// <param name="Exists">Whether it would update an item pushed before; null when unknown.</param>
/// <param name="Destination">The place itself, e.g. the vault name.</param>
/// <param name="DestinationDetail">Where that is, e.g. the account.</param>
public sealed record PushPreview(string Target, bool? Exists, string? Destination = null, string? DestinationDetail = null);

/// <summary>
/// An external vault Keylo can push secrets into (1Password, Bitwarden, KeePass, ...).
///
/// Built-in providers live in this assembly. Others are discovered from DLLs in
/// %LOCALAPPDATA%\Keylo\plugins: any public, non-abstract type implementing this interface with a
/// parameterless constructor is loaded. Plugins run with full trust as the current user, so only
/// install ones you've built or reviewed.
///
/// Implementations must never pass secret values on a command line (it is visible to every process
/// via the process list); use stdin, a temp file the provider deletes, or an API.
/// </summary>
public interface IVaultProvider
{
    /// <summary>Stable id used in config and on the command line, e.g. "1password".</summary>
    string Id { get; }

    string DisplayName { get; }

    /// <summary>Settings this provider reads from config ("providers.{id}"), with a description of each.</summary>
    IReadOnlyDictionary<string, string> SettingDescriptions { get; }

    /// <summary>
    /// Whether the required settings are filled in (cheap, no I/O). Push is offered only when true;
    /// <see cref="GetStatusAsync"/> then checks the provider is actually reachable.
    /// </summary>
    bool IsConfigured(IReadOnlyDictionary<string, string> settings) => true;

    Task<ProviderStatus> GetStatusAsync(IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);

    /// <summary>Where <paramref name="secretName"/> would be pushed, for a confirmation (no values are read).</summary>
    Task<PushPreview> PreviewAsync(string secretName, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default) =>
        Task.FromResult(new PushPreview(DisplayName, null));

    /// <summary>Creates the secret in the external vault, or updates the item Keylo pushed before.</summary>
    Task<PushResult> PushAsync(Secret secret, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);
}
