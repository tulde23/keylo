namespace Keylo.Core.Providers;

/// <summary>Whether a provider can be used right now, and if not, what the user should do.</summary>
public sealed record ProviderStatus(bool Ready, string Message);

public sealed record PushResult(string Name, bool Succeeded, string Message, string? RemoteId = null);

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

    Task<ProviderStatus> GetStatusAsync(IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);

    /// <summary>Creates the secret in the external vault, or updates the item Keylo pushed before.</summary>
    Task<PushResult> PushAsync(Secret secret, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default);
}
