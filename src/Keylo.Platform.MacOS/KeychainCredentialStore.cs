using System.Text.Json;
using Keylo.Core.Platform;
using Keylo.Platform.MacOS.Interop;

namespace Keylo.Platform.MacOS;

/// <summary>
/// The macOS login keychain as Keylo's <see cref="ICredentialStore"/>. Each secret is a generic
/// password (service <c>Keylo</c>, account = the target, so it shows in Keychain Access as such):
/// the value is the item's data, and username, notes and attributes ride along as JSON in the
/// item's "generic" attribute.
///
/// <paramref name="keychainPath"/> uses a specific keychain file instead of the login keychain
/// (KEYLO_KEYCHAIN; e.g. a throwaway one for tests, or from an SSH session where the login keychain
/// is locked).
/// </summary>
public sealed class KeychainCredentialStore(string service = KeychainCredentialStore.DefaultService, string? keychainPath = null) : ICredentialStore
{
    public const string DefaultService = "Keylo";

    // Opened once and kept for the process's life.
    private readonly IntPtr _keychain = keychainPath is { Length: > 0 } ? Keychain.Open(keychainPath) : IntPtr.Zero;
    private IntPtr _searchList;

    // Keychain items can be far larger; this keeps everyday secrets in the keychain and certificates
    // and key bundles in protected files, as on Windows.
    public int MaxBlobBytes => 16 * 1024;
    public int MaxAttributeBytes => 1024;
    public int MaxAttributes => 64;

    private sealed record Metadata(string? UserName, string? Comment, Dictionary<string, string>? Attributes);

    public RawCredential? Read(string target)
    {
        var query = Query(target, (Keychain.ReturnData, CF.True), (Keychain.ReturnAttributes, CF.True), (Keychain.MatchLimit, Keychain.MatchLimitOne));
        try
        {
            var status = Keychain.SecItemCopyMatching(query.Dictionary, out var result);
            if (status == Keychain.ItemNotFound) return null;
            Keychain.Check(status, $"read '{target}'");
            try
            {
                return ToCredential(target, result, CF.ToBytes(CF.Get(result, Keychain.ValueData)));
            }
            finally
            {
                CF.Release(result);
            }
        }
        finally
        {
            query.Dispose();
        }
    }

    public IReadOnlyList<RawCredential> Enumerate(string prefix)
    {
        // Attributes for every Keylo item first (returning data for "all" isn't allowed), then each value.
        var query = Query(null, (Keychain.ReturnAttributes, CF.True), (Keychain.MatchLimit, Keychain.MatchLimitAll));
        var accounts = new List<string>();
        try
        {
            var status = Keychain.SecItemCopyMatching(query.Dictionary, out var array);
            if (status == Keychain.ItemNotFound) return [];
            Keychain.Check(status, "list Keylo items");
            try
            {
                for (var i = 0; i < CF.Count(array); i++)
                    if (CF.ToString(CF.Get(CF.At(array, i), Keychain.Account)) is { } account &&
                        account.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        accounts.Add(account);
            }
            finally
            {
                CF.Release(array);
            }
        }
        finally
        {
            query.Dispose();
        }

        return accounts.Select(Read).OfType<RawCredential>().ToList();
    }

    public void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null)
    {
        var metadata = JsonSerializer.SerializeToUtf8Bytes(new Metadata(userName, comment,
            attributes?.Where(a => !string.IsNullOrEmpty(a.Value)).ToDictionary(a => a.Key, a => a.Value)));
        var data = CF.Data(blob);
        var generic = CF.Data(metadata);
        try
        {
            // Update in place when it exists (keeps the item's access list), else add.
            var query = Query(target);
            var changes = CF.Dictionary([(Keychain.ValueData, data), (Keychain.Generic, generic)]);
            try
            {
                var status = Keychain.SecItemUpdate(query.Dictionary, changes);
                if (status != Keychain.ItemNotFound)
                {
                    Keychain.Check(status, $"update '{target}'");
                    return;
                }
            }
            finally
            {
                CF.Release(changes);
                query.Dispose();
            }

            var add = Query(target, adding: true, (Keychain.Label, CF.String(target)), (Keychain.ValueData, data), (Keychain.Generic, generic));
            try
            {
                Keychain.Check(Keychain.SecItemAdd(add.Dictionary, IntPtr.Zero), $"add '{target}'");
            }
            finally
            {
                add.Dispose(releaseExtras: [0]); // the label string is ours; data and generic are released below
            }
        }
        finally
        {
            CF.Release(data);
            CF.Release(generic);
        }
    }

    public bool Delete(string target)
    {
        var query = Query(target);
        try
        {
            var status = Keychain.SecItemDelete(query.Dictionary);
            if (status == Keychain.ItemNotFound) return false;
            Keychain.Check(status, $"delete '{target}'");
            return true;
        }
        finally
        {
            query.Dispose();
        }
    }

    private RawCredential ToCredential(string target, IntPtr attributes, byte[] blob)
    {
        Metadata? metadata = null;
        var generic = CF.ToBytes(CF.Get(attributes, Keychain.Generic));
        if (generic.Length > 0)
        {
            try { metadata = JsonSerializer.Deserialize<Metadata>(generic); }
            catch (JsonException) { /* an item written by something else: no metadata */ }
        }

        return new RawCredential(
            target,
            metadata?.UserName,
            metadata?.Comment,
            CF.ToDate(CF.Get(attributes, Keychain.ModificationDate)) ?? DateTimeOffset.Now,
            blob,
            metadata?.Attributes ?? new Dictionary<string, string>());
    }

    private QueryHandle Query(string? account, params (IntPtr Key, IntPtr Value)[] extra) => Query(account, adding: false, extra);

    /// <summary>
    /// class + service (+ account), plus extra pairs; with a specific keychain, where to add or
    /// search. Dispose releases what it created.
    /// </summary>
    private QueryHandle Query(string? account, bool adding, params (IntPtr Key, IntPtr Value)[] extra)
    {
        if (_keychain != IntPtr.Zero)
        {
            if (adding) extra = [.. extra, (Keychain.UseKeychain, _keychain)];
            else
            {
                if (_searchList == IntPtr.Zero) _searchList = CF.MakeArray([_keychain]);
                extra = [.. extra, (Keychain.MatchSearchList, _searchList)];
            }
        }

        var serviceString = CF.String(service);
        var accountString = account is null ? IntPtr.Zero : CF.String(account);
        var pairs = new List<(IntPtr, IntPtr)> { (Keychain.Class, Keychain.ClassGenericPassword), (Keychain.Service, serviceString) };
        if (account is not null) pairs.Add((Keychain.Account, accountString));
        pairs.AddRange(extra);
        return new QueryHandle(CF.Dictionary(pairs), [serviceString, accountString], extra.Select(e => e.Value).ToArray());
    }

    private sealed class QueryHandle(IntPtr dictionary, IntPtr[] owned, IntPtr[] extraValues)
    {
        public IntPtr Dictionary { get; } = dictionary;

        /// <param name="releaseExtras">Indexes of extra values this call created and owns.</param>
        public void Dispose(int[]? releaseExtras = null)
        {
            CF.Release(Dictionary);
            foreach (var value in owned) CF.Release(value);
            foreach (var i in releaseExtras ?? []) CF.Release(extraValues[i]);
        }
    }
}
