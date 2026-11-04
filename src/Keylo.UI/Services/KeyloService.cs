using System.Text;
using Keylo.Core;
using Keylo.Core.Providers;
using Keylo.Core.Security;

namespace Keylo.App.Services;

/// <summary>The app's single entry point to secrets: store, Hello gate, clipboard and settings.</summary>
public sealed class KeyloService : IDisposable
{
    private readonly IUiTimer _clipboardTimer;
    private uint? _clipboardSequence;

    public KeyloService()
    {
        Config = KeyloConfig.Load();
        Gate = new AccessGate(Config, Keylo.Core.Platform.KeyloPlatform.Current.Verifier);
        Categories = new CategoryCatalog(Store);

        _clipboardTimer = Ui.Host.CreateTimer(TimeSpan.FromSeconds(Config.ClipboardSeconds), ClearClipboard);
        Ui.Host.SessionLocked += OnSessionLocked;
    }

    public SecretStore Store { get; } = new();
    public CategoryCatalog Categories { get; }
    public KeyloConfig Config { get; }
    public AccessGate Gate { get; }
    public ProviderRegistry Providers { get; } = new();

    public SecretTypeCatalog TypeCatalog { get; } = new();

    /// <summary>Pinned secrets and recent uses (Home).</summary>
    public Activity Activity { get; } = new();

    /// <summary>Built-in and custom secret types, cached; call <see cref="RefreshTypes"/> after editing them.</summary>
    public IReadOnlyList<SecretTypeDefinition> Types => _types ??= LoadTypes();
    private IReadOnlyList<SecretTypeDefinition>? _types;

    public SecretTypeDefinition? TypeOf(string? id) =>
        id is null ? null
        : id == LinkedSecrets.TypeId ? LinkedType
        : Types.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>For list icons and subtitles; a linked secret's real fields come from <see cref="LinkedSecrets.AsType"/>.</summary>
    private static readonly SecretTypeDefinition LinkedType = new() { Id = LinkedSecrets.TypeId, Name = "Linked", Icon = "Link24", IsBuiltIn = true };

    /// <summary>A linked secret's current values, read from its vault.</summary>
    public Task<Dictionary<string, string>> ResolveLinkedAsync(SecretInfo info) => LinkedSecrets.ResolveAsync(info, Providers, Config);

    public void RefreshTypes() => _types = null;

    private IReadOnlyList<SecretTypeDefinition> LoadTypes()
    {
        try
        {
            return TypeCatalog.All();
        }
        catch (KeyloException)
        {
            return SecretTypeCatalog.BuiltIn; // A broken types.json shouldn't stop the app.
        }
    }

    /// <summary>Owner window for Windows Hello prompts (unused by Touch ID).</summary>
    public IntPtr WindowHandle { get; set; }

    /// <summary>Raised when the app must lock (the computer locked, or the user asked).</summary>
    public event EventHandler? Locked;

    public bool IsUnlocked => Gate.IsUnlocked;

    public Task UnlockAsync() => Gate.UnlockAsync(WindowHandle);

    /// <summary>Before showing, copying or editing a value.</summary>
    public Task EnsureValueAccessAsync(string what) => Gate.EnsureAsync(WindowHandle, $"Keylo: {what}", valueAccess: true);

    /// <summary>Before changing secrets: the session must still be valid.</summary>
    public Task EnsureBrowseAsync() => Gate.EnsureAsync(WindowHandle, "Unlock Keylo", valueAccess: false);

    /// <summary>A fresh Windows Hello check regardless of session (unless Hello is off), for exporting everything.</summary>
    public Task ConfirmAsync(string what) => Gate.ConfirmAsync(WindowHandle, $"Keylo: {what}");

    private DateTime _lastActivity;

    /// <summary>The user did something in the window: slide the Windows Hello session (throttled).</summary>
    public void NoteActivity()
    {
        var now = DateTime.UtcNow;
        if (now - _lastActivity < TimeSpan.FromSeconds(20)) return;
        _lastActivity = now;
        Gate.ExtendSession();
    }

    public void Lock()
    {
        Gate.Lock();
        Locked?.Invoke(this, EventArgs.Empty);
    }

    public void CopyToClipboard(string text)
    {
        _clipboardSequence = SecureClipboard.SetText(text);
        _clipboardTimer.Interval = TimeSpan.FromSeconds(Config.ClipboardSeconds);
        _clipboardTimer.Stop();
        _clipboardTimer.Start();
    }

    public void ClearClipboard()
    {
        _clipboardTimer.Stop();
        if (_clipboardSequence is { } sequence) SecureClipboard.ClearIfUnchanged(sequence);
        _clipboardSequence = null;
    }

    /// <summary>
    /// Re-reads config.json into <see cref="Config"/> (same instance, which the gate holds). Other
    /// processes change it too: the CLI, and approval windows adding secrets to access keys.
    /// </summary>
    public void RefreshConfig()
    {
        var fresh = KeyloConfig.Load();
        Config.Hello = fresh.Hello;
        Config.SessionMinutes = fresh.SessionMinutes;
        Config.ClipboardSeconds = fresh.ClipboardSeconds;
        Config.AuditRetentionDays = fresh.AuditRetentionDays;
        Config.AccessKeys = fresh.AccessKeys;
        Config.Providers = fresh.Providers;
    }

    /// <summary>
    /// Keeps access keys pointing at a category through a plain rename. A delete or a merge into
    /// another category (<paramref name="newName"/> null or <paramref name="merged"/>) just removes it
    /// from keys: a key never silently gains another category's secrets. Narrowing or keeping a
    /// key's reach needs no Windows Hello.
    /// </summary>
    public void UpdateKeysForCategory(string oldName, string? newName, bool merged = false)
    {
        RefreshConfig();
        var changed = false;
        foreach (var key in Config.AccessKeys)
        {
            var i = key.Categories.FindIndex(c => c.Equals(oldName, StringComparison.OrdinalIgnoreCase));
            if (i < 0) continue;
            changed = true;
            if (newName is null || merged || key.Categories.Contains(newName, StringComparer.OrdinalIgnoreCase)) key.Categories.RemoveAt(i);
            else key.Categories[i] = newName.Trim();
        }
        if (changed) Config.Save();
    }

    /// <summary>Saves settings after a fresh Windows Hello check (they decide what skips it).</summary>
    public async Task SaveConfigAsync(KeyloConfig updated)
    {
        await Gate.ConfirmAsync(WindowHandle, "Keylo: change settings");

        // Applied to the existing instance, which the gate reads, so the change takes effect at once.
        Config.Hello = updated.Hello;
        Config.SessionMinutes = updated.SessionMinutes;
        Config.ClipboardSeconds = updated.ClipboardSeconds;
        Config.AuditRetentionDays = updated.AuditRetentionDays;
        Config.AccessKeys = updated.AccessKeys;
        Config.Providers = updated.Providers;
        Config.Save();
    }

    public static string? DecodeText(byte[] value)
    {
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(value);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private void OnSessionLocked(object? sender, EventArgs e) => Ui.Host.Post(Lock);

    public void Dispose()
    {
        Ui.Host.SessionLocked -= OnSessionLocked;
        ClearClipboard();
    }
}
