using System.Text;
using System.Windows.Threading;
using Keylo.Core;
using Keylo.Core.Providers;
using Keylo.Core.Security;
using Microsoft.Win32;

namespace Keylo.App.Services;

/// <summary>The app's single entry point to secrets: store, Hello gate, clipboard and settings.</summary>
public sealed class KeyloService : IDisposable
{
    private readonly DispatcherTimer _clipboardTimer = new();
    private uint? _clipboardSequence;

    public KeyloService()
    {
        Config = KeyloConfig.Load();
        Gate = new AccessGate(Config, new WindowsHelloVerifier());
        Categories = new CategoryCatalog(Store);

        _clipboardTimer.Tick += (_, _) => ClearClipboard();
        SystemEvents.SessionSwitch += OnSessionSwitch;
    }

    public SecretStore Store { get; } = new();
    public CategoryCatalog Categories { get; }
    public KeyloConfig Config { get; }
    public AccessGate Gate { get; }
    public ProviderRegistry Providers { get; } = new();

    public SecretTypeCatalog TypeCatalog { get; } = new();

    /// <summary>Built-in and custom secret types, cached; call <see cref="RefreshTypes"/> after editing them.</summary>
    public IReadOnlyList<SecretTypeDefinition> Types => _types ??= LoadTypes();
    private IReadOnlyList<SecretTypeDefinition>? _types;

    public SecretTypeDefinition? TypeOf(string? id) =>
        id is null ? null : Types.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

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

    /// <summary>Owner window for Windows Hello prompts.</summary>
    public IntPtr WindowHandle { get; set; }

    /// <summary>Raised when the app must lock (Windows locked, or the user asked).</summary>
    public event EventHandler? Locked;

    public bool IsUnlocked => Gate.IsUnlocked;

    public Task UnlockAsync() => Gate.UnlockAsync(WindowHandle);

    /// <summary>Before showing, copying or editing a value.</summary>
    public Task EnsureValueAccessAsync(string what) => Gate.EnsureAsync(WindowHandle, $"Keylo: {what}", valueAccess: true);

    /// <summary>Before changing secrets: the session must still be valid.</summary>
    public Task EnsureBrowseAsync() => Gate.EnsureAsync(WindowHandle, "Unlock Keylo", valueAccess: false);

    /// <summary>A fresh Windows Hello check regardless of session (unless Hello is off), for exporting everything.</summary>
    public Task ConfirmAsync(string what) => Gate.ConfirmAsync(WindowHandle, $"Keylo: {what}");

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
        Config.AccessKeys = fresh.AccessKeys;
        Config.Providers = fresh.Providers;
    }

    /// <summary>Saves settings after a fresh Windows Hello check (they decide what skips it).</summary>
    public async Task SaveConfigAsync(KeyloConfig updated)
    {
        await Gate.ConfirmAsync(WindowHandle, "Keylo: change settings");

        // Applied to the existing instance, which the gate reads, so the change takes effect at once.
        Config.Hello = updated.Hello;
        Config.SessionMinutes = updated.SessionMinutes;
        Config.ClipboardSeconds = updated.ClipboardSeconds;
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

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        if (e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
            System.Windows.Application.Current?.Dispatcher.BeginInvoke(Lock);
    }

    public void Dispose()
    {
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        ClearClipboard();
    }
}
