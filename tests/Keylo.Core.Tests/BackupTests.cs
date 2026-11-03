using System.Text;
using Keylo.Core;

namespace Keylo.Core.Tests;

public sealed class BackupTests : IDisposable
{
    private const string Password = "correct horse battery staple";
    private const int FastIterations = 1_000; // the real default is 600,000; tests don't need the delay

    private readonly string _dir = Directory.CreateTempSubdirectory("keylo-backup-tests-").FullName;
    private readonly SecretStore _source;
    private readonly SecretStore _target;

    public BackupTests()
    {
        _source = new SecretStore(Path.Combine(_dir, "a"), $"KeyloUnitTestA-{Guid.NewGuid():N}:");
        _target = new SecretStore(Path.Combine(_dir, "b"), $"KeyloUnitTestB-{Guid.NewGuid():N}:");
    }

    public void Dispose()
    {
        foreach (var store in new[] { _source, _target })
        foreach (var secret in store.List())
            store.Delete(secret.Name);
        Directory.Delete(_dir, recursive: true);
    }

    private string File => Path.Combine(_dir, "backup.keylo");

    [Fact]
    public void Round_trips_secrets_large_values_and_categories_into_another_store()
    {
        var big = System.Security.Cryptography.RandomNumberGenerator.GetBytes(10_000);
        _source.Save(new SecretDraft("api", "s3cret"u8.ToArray(), "cloud", "key-id", "note", "Cloud24", "#0EA5E9"));
        _source.Save(new SecretDraft("cert", big, "certs"));
        var sourceCatalog = new CategoryCatalog(_source, Path.Combine(_dir, "a"));
        sourceCatalog.Create("empty", "Folder24", null);

        var summary = KeyloBackup.Create(_source, sourceCatalog, File, Password, FastIterations);
        Assert.Equal(2, summary.Secrets);

        // Nothing readable in the file: not the value, the details, or even the name. Long markers,
        // because random ciphertext can contain a short string like "api" by chance.
        _source.Save(new SecretDraft("name-marker-5b1f9c2e", "value-marker-0d7a4e6b"u8.ToArray(), "category-marker-93c1"));
        KeyloBackup.Create(_source, sourceCatalog, File, Password, FastIterations);
        var raw = Encoding.Latin1.GetString(System.IO.File.ReadAllBytes(File));
        Assert.DoesNotContain("name-marker", raw);
        Assert.DoesNotContain("value-marker", raw);
        Assert.DoesNotContain("category-marker", raw);
        _source.Delete("name-marker-5b1f9c2e");
        KeyloBackup.Create(_source, sourceCatalog, File, Password, FastIterations);

        var contents = KeyloBackup.Read(File, Password);
        var targetCatalog = new CategoryCatalog(_target, Path.Combine(_dir, "b"));
        var result = KeyloBackup.Restore(_target, targetCatalog, contents, overwrite: false);

        Assert.Equal((2, 0, 0), (result.Added, result.Replaced, result.Skipped));
        var api = _target.Get("api");
        Assert.Equal("s3cret", Encoding.UTF8.GetString(api.Value));
        Assert.Equal(("cloud", "key-id", "note", "Cloud24", "#0EA5E9"), (api.Info.Category, api.Info.Username, api.Info.Notes, api.Info.Icon, api.Info.Color));
        Assert.Equal(big, _target.Get("cert").Value);
        Assert.Contains(targetCatalog.All(), c => c is { Name: "empty", Icon: "Folder24" });
    }

    [Fact]
    public void Wrong_password_is_rejected()
    {
        _source.Save(new SecretDraft("x", "v"u8.ToArray()));
        KeyloBackup.Create(_source, new CategoryCatalog(_source, _dir), File, Password, FastIterations);

        Assert.Throws<BackupPasswordException>(() => KeyloBackup.Read(File, "not the right password"));
    }

    [Theory]
    [InlineData(10)]  // iteration count in the header
    [InlineData(-1)]  // last byte of the tag
    [InlineData(60)]  // inside the ciphertext
    public void Any_tampering_is_detected(int offset)
    {
        _source.Save(new SecretDraft("x", "value value value"u8.ToArray()));
        KeyloBackup.Create(_source, new CategoryCatalog(_source, _dir), File, Password, FastIterations);

        var bytes = System.IO.File.ReadAllBytes(File);
        var index = offset < 0 ? bytes.Length + offset : Math.Min(offset, bytes.Length - 17);
        bytes[index] ^= 0x01;
        System.IO.File.WriteAllBytes(File, bytes);

        Assert.Throws<BackupPasswordException>(() => KeyloBackup.Read(File, Password));
    }

    [Fact]
    public void Short_passwords_are_refused()
    {
        Assert.Throws<KeyloException>(() => KeyloBackup.Create(_source, new CategoryCatalog(_source, _dir), File, "short", FastIterations));
        Assert.False(System.IO.File.Exists(File));
    }

    [Fact]
    public void Restore_skips_or_replaces_existing_secrets()
    {
        _source.Save(new SecretDraft("shared", "from-backup"u8.ToArray()));
        KeyloBackup.Create(_source, new CategoryCatalog(_source, _dir), File, Password, FastIterations);
        _target.Save(new SecretDraft("shared", "local"u8.ToArray()));
        var catalog = new CategoryCatalog(_target, Path.Combine(_dir, "b"));

        var skip = KeyloBackup.Restore(_target, catalog, KeyloBackup.Read(File, Password), overwrite: false);
        Assert.Equal(1, skip.Skipped);
        Assert.Equal("local", Encoding.UTF8.GetString(_target.Get("shared").Value));

        var replace = KeyloBackup.Restore(_target, catalog, KeyloBackup.Read(File, Password), overwrite: true);
        Assert.Equal(1, replace.Replaced);
        Assert.Equal("from-backup", Encoding.UTF8.GetString(_target.Get("shared").Value));
    }
}
