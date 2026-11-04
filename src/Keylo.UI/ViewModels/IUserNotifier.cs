namespace Keylo.App.ViewModels;

/// <summary>Toasts and confirmations, implemented by the main window.</summary>
public interface IUserNotifier
{
    void Success(string message);
    void Info(string message);
    void Error(string message);
    Task<bool> ConfirmAsync(string title, string message, string confirmText);

    /// <summary>Shows the import options dialog; null when canceled.</summary>
    Task<ImportOptions?> AskImportOptionsAsync(ImportOptionsViewModel options);

    /// <summary>Asks for a backup password (a new one entered twice when <paramref name="isNew"/>); null when canceled.</summary>
    Task<string?> AskPasswordAsync(string heading, string message, string okText, bool isNew, string? error = null);

    /// <summary>Three-way choice: true = primary, false = secondary, null = canceled.</summary>
    Task<bool?> ChooseAsync(string title, string message, string primaryText, string? secondaryText);

    /// <summary>Shows a newly created access key (the only time it's visible) and how to register it with Claude Code.</summary>
    Task ShowAccessKeyAsync(string name, string token);

    /// <summary>Asks before pushing a secret to another vault; true to go ahead.</summary>
    Task<bool> ConfirmPushAsync(PushConfirmation push);

    /// <summary>Shows the link dialog: the new secret's name ("first|count" when several were linked), or null when canceled.</summary>
    Task<string?> LinkSecretAsync();
}

/// <summary>What a push will do, for the push dialog. Symbol, image and tile are the UI toolkit's objects.</summary>
public sealed record PushConfirmation(
    string ProviderName,
    string SecretName,
    string SecretDetail,
    object? SecretSymbol,
    object? SecretImage,
    object SecretTileBrush,
    string Destination,
    string DestinationDetail,
    bool? Exists);
