using System.Runtime.InteropServices;
using System.Text.Json;
using Keylo.Core;
using Keylo.Core.Platform;
using Keylo.Platform.Linux.Interop;

namespace Keylo.Platform.Linux;

/// <summary>
/// The desktop keyring (Secret Service: GNOME Keyring, KWallet, KeePassXC…) as Keylo's
/// <see cref="ICredentialStore"/>. Each secret is an item in the default collection labelled with its
/// target and found by the attributes service + account. Everything else (the value, username,
/// notes, attributes) is inside the encrypted secret as JSON, so nothing about it is readable
/// without unlocking the keyring.
/// </summary>
public sealed class SecretServiceStore(string service = SecretServiceStore.DefaultService) : ICredentialStore
{
    public const string DefaultService = "Keylo";
    private const string SchemaName = "io.github.tulde23.keylo";

    private static readonly Lazy<IntPtr> Schema = new(() => LibSecret.Schema(SchemaName, "service", "account"));

    public int MaxBlobBytes => 16 * 1024;
    public int MaxAttributeBytes => 1024;
    public int MaxAttributes => 64;

    private sealed record Payload(string Value, string? UserName, string? Comment, Dictionary<string, string>? Attributes);

    /// <summary>Whether a Secret Service answers on this session's D-Bus; the reason when it doesn't.</summary>
    public static (bool Available, string? Problem) Probe()
    {
        try
        {
            using var query = new LibSecret.Attributes(("service", DefaultService + ".Probe"), ("account", "probe"));
            var found = LibSecret.secret_password_lookupv_sync(Schema.Value, query.Table, IntPtr.Zero, out var error);
            if (found != IntPtr.Zero) LibSecret.secret_password_free(found);
            return LibSecret.TakeError(error) is { } problem ? (false, problem) : (true, null);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return (false, "libsecret isn't installed");
        }
    }

    public RawCredential? Read(string target) =>
        Search(target).FirstOrDefault(c => c.Target.Equals(target, StringComparison.OrdinalIgnoreCase));

    public IReadOnlyList<RawCredential> Enumerate(string prefix) =>
        Search(null).Where(c => c.Target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>Keylo's items (or the one for <paramref name="account"/>), unlocking the keyring if needed.</summary>
    private List<RawCredential> Search(string? account)
    {
        using var query = account is null
            ? new LibSecret.Attributes(("service", service))
            : new LibSecret.Attributes(("service", service), ("account", account));
        var list = LibSecret.secret_password_searchv_sync(Schema.Value, query.Table,
            LibSecret.SearchAll | LibSecret.SearchUnlock | LibSecret.SearchLoadSecrets, IntPtr.Zero, out var error);
        Check(error, account is null ? "list Keylo items" : $"read '{account}'");
        try
        {
            var results = new List<RawCredential>();
            foreach (var item in LibSecret.Items(list))
            {
                var attributes = LibSecret.secret_retrievable_get_attributes(item);
                var target = LibSecret.Lookup(attributes, "account");
                LibSecret.g_hash_table_unref(attributes);
                if (target is null) continue;

                var value = LibSecret.secret_retrievable_retrieve_secret_sync(item, IntPtr.Zero, out var valueError);
                Check(valueError, $"read '{target}'");
                if (value == IntPtr.Zero) continue;
                try
                {
                    var modified = DateTimeOffset.FromUnixTimeSeconds((long)LibSecret.secret_retrievable_get_modified(item)).ToLocalTime();
                    results.Add(ToCredential(target, Marshal.PtrToStringUTF8(LibSecret.secret_value_get_text(value)) ?? "", modified));
                }
                finally
                {
                    LibSecret.secret_value_unref(value);
                }
            }
            return results;
        }
        finally
        {
            LibSecret.FreeObjectList(list);
        }
    }

    public void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null)
    {
        var payload = JsonSerializer.Serialize(new Payload(Convert.ToBase64String(blob), userName, comment,
            attributes?.Where(a => !string.IsNullOrEmpty(a.Value)).ToDictionary(a => a.Key, a => a.Value)));
        using var query = new LibSecret.Attributes(("service", service), ("account", target));
        // Storing with the same attributes replaces the existing item.
        LibSecret.secret_password_storev_sync(Schema.Value, query.Table, IntPtr.Zero, $"{service}: {target}", payload, IntPtr.Zero, out var error);
        Check(error, $"save '{target}'");
    }

    public bool Delete(string target)
    {
        using var query = new LibSecret.Attributes(("service", service), ("account", target));
        var removed = LibSecret.secret_password_clearv_sync(Schema.Value, query.Table, IntPtr.Zero, out var error);
        Check(error, $"delete '{target}'");
        return removed != 0;
    }

    private static RawCredential ToCredential(string target, string secret, DateTimeOffset modified)
    {
        Payload? payload = null;
        try { payload = JsonSerializer.Deserialize<Payload>(secret); }
        catch (JsonException) { /* an item written by something else */ }

        return new RawCredential(
            target,
            payload?.UserName,
            payload?.Comment,
            modified,
            payload is null ? System.Text.Encoding.UTF8.GetBytes(secret) : Convert.FromBase64String(payload.Value),
            payload?.Attributes ?? new Dictionary<string, string>());
    }

    private static void Check(IntPtr error, string what)
    {
        if (LibSecret.TakeError(error) is { } message)
            throw new KeyloException($"Couldn't {what} in the keyring: {message}");
    }
}
