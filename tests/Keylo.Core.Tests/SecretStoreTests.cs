using System.Text;
using Keylo.Core;

namespace Keylo.Core.Tests;

/// <summary>Runs against the real Credential Manager under a unique prefix, removed afterwards.</summary>
public sealed class SecretStoreTests : IDisposable
{
    private readonly string _dataDir = Directory.CreateTempSubdirectory("keylo-tests-").FullName;
    private readonly SecretStore _store;

    public SecretStoreTests() => _store = new SecretStore(_dataDir, $"KeyloUnitTest-{Guid.NewGuid():N}:");

    public void Dispose()
    {
        foreach (var secret in _store.List()) _store.Delete(secret.Name);
        Directory.Delete(_dataDir, recursive: true);
    }

    [Fact]
    public void Small_value_round_trips_inline_with_details()
    {
        _store.Save(new SecretDraft("api", "s3cret"u8.ToArray(), "cloud", "me", "note"));

        var secret = _store.Get("api");
        Assert.Equal("s3cret", Encoding.UTF8.GetString(secret.Value));
        Assert.Equal(("cloud", "me", "note"), (secret.Info.Category, secret.Info.Username, secret.Info.Notes));
        Assert.Equal(StorageKind.CredentialManager, secret.Info.Storage);
    }

    [Fact]
    public void Import_names_default_to_the_file_name_and_can_be_overridden()
    {
        var folder = Directory.CreateTempSubdirectory("keylo-import-").FullName;
        try
        {
            var a = Path.Combine(folder, "github-token.txt");
            var b = Path.Combine(folder, "db.env");
            File.WriteAllText(a, "tok");
            File.WriteAllText(b, "pw");

            var result = SecretImporter.Import(_store, [a, b], names: new Dictionary<string, string> { [b] = "  prod-db  " }, inferTypes: false);

            Assert.Equal(["github-token", "prod-db"], result.Imported.Select(i => i.Name).Order());
            Assert.Equal("pw", Encoding.UTF8.GetString(_store.Get("prod-db").Value));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void Import_guesses_types_unless_told_otherwise()
    {
        var folder = Directory.CreateTempSubdirectory("keylo-import-").FullName;
        try
        {
            var url = Path.Combine(folder, "orders-db.txt");
            var token = Path.Combine(folder, "github-token");
            File.WriteAllText(url, "postgres://alice:pw@db.local:5432/orders\n");
            File.WriteAllText(token, "ghp_123\n");

            SecretImporter.Import(_store, [url, token], types: new Dictionary<string, string> { [token] = "" });

            var db = _store.Get("orders-db");
            Assert.Equal(("database", "db.local"), (db.Info.Type, db.Info.Fields!["host"]));
            Assert.Null(_store.Find("github-token")!.Type); // chosen plain
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void Large_value_goes_to_an_encrypted_file_and_delete_removes_it()
    {
        var value = RandomBytes(SecretStore.MaxInlineBytes + 1);
        _store.Save(new SecretDraft("cert", value));

        Assert.Equal(StorageKind.EncryptedFile, _store.Find("cert")!.Storage);
        Assert.Equal(value, _store.Get("cert").Value);
        Assert.Single(BlobFiles());

        Assert.True(_store.Delete("cert"));
        Assert.Empty(BlobFiles());
    }

    [Fact]
    public void Value_at_the_inline_limit_stays_inline()
    {
        _store.Save(new SecretDraft("edge", RandomBytes(SecretStore.MaxInlineBytes)));
        Assert.Equal(StorageKind.CredentialManager, _store.Find("edge")!.Storage);
    }

    [Fact]
    public void Shrinking_a_large_value_removes_its_old_file()
    {
        _store.Save(new SecretDraft("k", RandomBytes(5000)));
        _store.Save(new SecretDraft("k", "small"u8.ToArray()), originalName: "k");

        Assert.Empty(BlobFiles());
        Assert.Equal("small", Encoding.UTF8.GetString(_store.Get("k").Value));
    }

    [Fact]
    public void Adding_an_existing_name_fails()
    {
        _store.Save(new SecretDraft("dup", "1"u8.ToArray()));
        Assert.Throws<SecretExistsException>(() => _store.Save(new SecretDraft("dup", "2"u8.ToArray())));
    }

    [Fact]
    public void Rename_moves_the_secret_and_keeps_large_values()
    {
        var value = RandomBytes(4000);
        _store.Save(new SecretDraft("old", value, "a"));
        _store.Save(new SecretDraft("new", value, "b"), originalName: "old");

        Assert.Null(_store.Find("old"));
        Assert.Equal(value, _store.Get("new").Value);
        Assert.Equal("b", _store.Find("new")!.Category);
        Assert.Single(BlobFiles());
    }

    [Fact]
    public void Case_only_rename_changes_the_spelling()
    {
        _store.Save(new SecretDraft("token", "v"u8.ToArray()));
        _store.Save(new SecretDraft("Token", "v"u8.ToArray()), originalName: "token");

        Assert.Equal("Token", Assert.Single(_store.List()).Name);
    }

    [Fact]
    public void Renaming_onto_another_secret_fails_and_changes_nothing()
    {
        _store.Save(new SecretDraft("a", "1"u8.ToArray()));
        _store.Save(new SecretDraft("b", "2"u8.ToArray()));

        Assert.Throws<SecretExistsException>(() => _store.Save(new SecretDraft("b", "1"u8.ToArray()), originalName: "a"));
        Assert.Equal("2", Encoding.UTF8.GetString(_store.Get("b").Value));
        Assert.NotNull(_store.Find("a"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("has*star")]
    [InlineData("tab\tname")]
    public void Invalid_names_are_rejected(string name) =>
        Assert.Throws<KeyloException>(() => _store.Save(new SecretDraft(name, "v"u8.ToArray())));

    [Fact]
    public void Categories_are_distinct_and_sorted()
    {
        _store.Save(new SecretDraft("1", "v"u8.ToArray(), "Zeta"));
        _store.Save(new SecretDraft("2", "v"u8.ToArray(), "alpha"));
        _store.Save(new SecretDraft("3", "v"u8.ToArray(), "ALPHA"));
        _store.Save(new SecretDraft("4", "v"u8.ToArray()));

        Assert.Equal(["alpha", "Zeta"], _store.Categories());
    }

    [Fact]
    public void Import_names_by_file_categorizes_by_subfolder_and_skips_existing()
    {
        var source = Directory.CreateDirectory(Path.Combine(_dataDir, "src"));
        Directory.CreateDirectory(Path.Combine(source.FullName, "cloud"));
        File.WriteAllText(Path.Combine(source.FullName, "cloud", "aws.txt"), "a");
        File.WriteAllText(Path.Combine(source.FullName, "root.key"), "b");
        File.WriteAllText(Path.Combine(source.FullName, "root.txt"), "c");
        _store.Save(new SecretDraft("aws", "existing"u8.ToArray()));

        var result = SecretImporter.Import(_store, [source.FullName]);

        Assert.Equal(["root.key", "root.txt"], result.Imported.Select(i => i.Name).Order());
        Assert.Contains(result.Skipped, s => s.Reason.Contains("already exists"));
        Assert.Equal("existing", Encoding.UTF8.GetString(_store.Get("aws").Value));

        var again = SecretImporter.Import(_store, [source.FullName], overwrite: true);
        Assert.Equal(3, again.Imported.Count);
        Assert.Equal("cloud", _store.Find("aws")!.Category);
    }

    [Fact]
    public void Update_details_changes_category_icon_and_colour_but_not_the_value()
    {
        var value = RandomBytes(4000);
        _store.Save(new SecretDraft("cert", value, "old", "me", "n", "Key24", "#112233"));
        var blobBefore = BlobFiles().Single();

        var info = _store.UpdateDetails("cert", category: "new", icon: "Cloud24");

        Assert.Equal(("new", "Cloud24", "#112233", "me", "n"), (info.Category, info.Icon, info.Color, info.Username, info.Notes));
        Assert.Equal(value, _store.Get("cert").Value);
        Assert.Equal(blobBefore, BlobFiles().Single());

        Assert.Null(_store.UpdateDetails("cert", category: "", color: "").Category);
        Assert.Null(_store.Find("cert")!.Color);
    }

    [Theory]
    [InlineData("not an icon", null)]
    [InlineData(null, "red")]
    [InlineData(null, "#12345G")]
    public void Bad_icons_and_colours_are_rejected(string? icon, string? color) =>
        Assert.Throws<KeyloException>(() => _store.Save(new SecretDraft("x", "v"u8.ToArray(), Icon: icon, Color: color)));

    [Fact]
    public void Catalog_rename_merges_and_delete_moves_or_removes_secrets()
    {
        var catalog = new CategoryCatalog(_store, _dataDir);
        _store.Save(new SecretDraft("a", "1"u8.ToArray(), "cloud"));
        _store.Save(new SecretDraft("b", "2"u8.ToArray(), "aws"));
        _store.Save(new SecretDraft("c", "3"u8.ToArray(), "temp"));
        catalog.Create("empty", "Folder24", "#6366F1");
        catalog.SetStyle("aws", "Cloud24", null);

        Assert.Contains(catalog.All(), x => x is { Name: "empty", Count: 0, Icon: "Folder24" });

        Assert.Equal(1, catalog.Rename("aws", "cloud"));
        Assert.Equal(2, catalog.All().Single(x => x.Name == "cloud").Count);
        Assert.DoesNotContain(catalog.All(), x => x.Name == "aws");

        Assert.Equal(2, catalog.Delete("cloud", moveTo: "infra"));
        Assert.Equal("infra", _store.Find("a")!.Category);

        Assert.Equal(1, catalog.Delete("temp", deleteSecrets: true));
        Assert.Null(_store.Find("c"));

        // Persisted: a fresh catalog sees the same empty category and style.
        Assert.Contains(new CategoryCatalog(_store, _dataDir).All(), x => x is { Name: "empty", Color: "#6366F1" });
    }

    private IEnumerable<string> BlobFiles() =>
        Directory.Exists(Path.Combine(_dataDir, "blobs")) ? Directory.EnumerateFiles(Path.Combine(_dataDir, "blobs")) : [];

    private static byte[] RandomBytes(int length) => System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);
}
