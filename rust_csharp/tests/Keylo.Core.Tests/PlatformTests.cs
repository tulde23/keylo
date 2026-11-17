using System.Security.Cryptography;
using System.Text;
using Keylo.Core.Platform;
using Keylo.Core.Security;

namespace Keylo.Core.Tests;

/// <summary>
/// Core runs against any <see cref="IKeyloPlatform"/>: these use an in-memory one (with different
/// limits from Windows) to show nothing in Core still assumes Credential Manager or DPAPI.
/// </summary>
public sealed class PlatformTests : IDisposable
{
    private sealed class MemoryStore : ICredentialStore
    {
        public readonly Dictionary<string, RawCredential> Items = new(StringComparer.OrdinalIgnoreCase);
        public int MaxBlobBytes => 64; // tiny, so values spill to protected files sooner than on Windows
        public int MaxAttributeBytes => 128;
        public int MaxAttributes => 16;

        public RawCredential? Read(string target) => Items.GetValueOrDefault(target);

        public IReadOnlyList<RawCredential> Enumerate(string prefix) =>
            Items.Values.Where(i => i.Target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToList();

        public void Write(string target, byte[] blob, string? userName, string? comment, IReadOnlyDictionary<string, string>? attributes = null) =>
            Items[target] = new RawCredential(target, userName, comment, DateTimeOffset.Now, blob.ToArray(),
                new Dictionary<string, string>(attributes ?? new Dictionary<string, string>()));

        public bool Delete(string target) => Items.Remove(target);
    }

    /// <summary>AES-GCM with a per-process key: enough to show Core never touches DPAPI itself.</summary>
    private sealed class MemoryProtector : IDataProtector
    {
        private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

        public byte[] Protect(byte[] data, byte[] entropy)
        {
            var output = new byte[12 + data.Length + 16];
            RandomNumberGenerator.Fill(output.AsSpan(0, 12));
            using var aes = new AesGcm(_key, 16);
            aes.Encrypt(output.AsSpan(0, 12), data, output.AsSpan(12, data.Length), output.AsSpan(12 + data.Length), entropy);
            return output;
        }

        public byte[] Unprotect(byte[] data, byte[] entropy)
        {
            var plain = new byte[data.Length - 28];
            using var aes = new AesGcm(_key, 16);
            aes.Decrypt(data.AsSpan(0, 12), data.AsSpan(12, plain.Length), data.AsSpan(12 + plain.Length), plain, entropy);
            return plain;
        }
    }

    private sealed class MemoryPlatform : IKeyloPlatform
    {
        public string Name => "Test";
        public MemoryStore Store { get; } = new();
        public ICredentialStore Credentials => Store;
        public IDataProtector DataProtector { get; } = new MemoryProtector();
        public IUserVerifier Verifier => throw new NotSupportedException();
        public ISecureClipboard Clipboard => throw new NotSupportedException();
        public IProcessAncestry Processes => throw new NotSupportedException();
    }

    private readonly IKeyloPlatform _windows = KeyloPlatform.Current;
    private readonly MemoryPlatform _platform = new();
    private readonly string _dataDir = Directory.CreateTempSubdirectory("keylo-platform-").FullName;

    public PlatformTests() => KeyloPlatform.Install(_platform);

    public void Dispose()
    {
        KeyloPlatform.Install(_windows); // tests run one at a time (AssemblyInfo), so this doesn't leak
        Directory.Delete(_dataDir, recursive: true);
    }

    [Fact]
    public void Secrets_round_trip_on_a_non_windows_platform_using_its_limits()
    {
        var store = new SecretStore(_dataDir, "Test:");
        Assert.Equal(63, SecretStore.MaxInlineBytes);

        store.Save(new SecretDraft("small", "s3cret"u8.ToArray(), "dev", "me"));
        var big = RandomNumberGenerator.GetBytes(500);
        store.Save(new SecretDraft("big", big));

        Assert.Equal("s3cret", Encoding.UTF8.GetString(store.Get("small").Value));
        Assert.Equal(StorageKind.EncryptedFile, store.Find("big")!.Storage);
        Assert.Equal(big, store.Get("big").Value);
        Assert.Equal(["big", "small"], store.List().Select(s => s.Name));

        store.Save(new SecretDraft("renamed", "x"u8.ToArray()), originalName: "small");
        Assert.Null(store.Find("small"));
        Assert.True(store.Delete("big"));
        Assert.Equal(["Test:renamed"], _platform.Store.Items.Keys);
    }

    [Fact]
    public void Typed_secrets_respect_the_platforms_attribute_limit()
    {
        var store = new SecretStore(_dataDir, "Test:");
        var database = SecretTypeCatalog.BuiltIn.Single(t => t.Id == "database");

        store.Save(TypedSecrets.Draft(database, "db", new Dictionary<string, string?> { ["host"] = "db.local", ["password"] = "pw" }));
        Assert.Equal("db.local", store.Find("db")!.Fields!["host"]);

        var tooLong = new Dictionary<string, string?> { ["host"] = new string('h', 200), ["password"] = "pw" };
        var ex = Assert.Throws<KeyloException>(() => store.Save(TypedSecrets.Draft(database, "db2", tooLong)));
        Assert.Contains("128 bytes", ex.Message);
    }
}
