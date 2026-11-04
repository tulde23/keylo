using System.Text;
using Keylo.Core;

namespace Keylo.Core.Tests;

public sealed class SecretTypeTests : IDisposable
{
    private readonly string _dataDir = Directory.CreateTempSubdirectory("keylo-tests-").FullName;
    private readonly SecretStore _store;
    private readonly SecretTypeCatalog _types;

    public SecretTypeTests()
    {
        _store = new SecretStore(_dataDir, $"KeyloUnitTest-{Guid.NewGuid():N}:");
        _types = new SecretTypeCatalog(_dataDir);
    }

    public void Dispose()
    {
        foreach (var secret in _store.List()) _store.Delete(secret.Name);
        Directory.Delete(_dataDir, recursive: true);
    }

    private static SecretTypeDefinition Database => SecretTypeCatalog.BuiltIn.Single(t => t.Id == "database");

    private static Dictionary<string, string?> DbFields() => new()
    {
        ["engine"] = "postgres", ["host"] = "db.local", ["port"] = "5432", ["database"] = "app",
        ["username"] = "alice", ["password"] = "p@ss word",
    };

    [Fact]
    public void Typed_secret_keeps_secret_fields_in_the_value_and_the_rest_as_metadata()
    {
        _store.Save(TypedSecrets.Draft(Database, "prod-db", DbFields(), category: "prod"));

        var secret = _store.Get("prod-db");
        Assert.Equal("database", secret.Info.Type);
        Assert.Equal("alice", secret.Info.Username);
        Assert.Equal("db.local", secret.Info.Fields!["host"]);
        Assert.False(secret.Info.Fields.ContainsKey("password"));

        var stored = Encoding.UTF8.GetString(secret.Value);
        Assert.Contains("p@ss word", stored);
        Assert.DoesNotContain("db.local", stored);

        var fields = TypedSecrets.ReadFields(Database, secret.Info, secret.Value);
        Assert.Equal("p@ss word", fields["password"]);
        Assert.Equal("alice", fields["username"]);
    }

    [Fact]
    public void Database_connection_string_is_derived_unless_stored()
    {
        _store.Save(TypedSecrets.Draft(Database, "prod-db", DbFields()));
        var secret = _store.Get("prod-db");

        Assert.Equal("postgresql://alice:p%40ss%20word@db.local:5432/app", TypedSecrets.ReadFields(Database, secret.Info, secret.Value)["connection_string"]);
        Assert.False(TypedSecrets.ReadFields(Database, secret.Info, secret.Value, derive: false).ContainsKey("connection_string"));

        var withOwn = DbFields();
        withOwn["connection_string"] = "Host=custom";
        _store.Save(TypedSecrets.Draft(Database, "prod-db", withOwn), originalName: "prod-db");
        secret = _store.Get("prod-db");
        Assert.Equal("Host=custom", TypedSecrets.ReadFields(Database, secret.Info, secret.Value)["connection_string"]);
    }

    [Fact]
    public void Recategorizing_keeps_type_and_fields()
    {
        _store.Save(TypedSecrets.Draft(Database, "prod-db", DbFields()));
        _store.UpdateDetails("prod-db", category: "ops");

        var info = _store.Find("prod-db")!;
        Assert.Equal(("ops", "database", "db.local"), (info.Category, info.Type, info.Fields!["host"]));
    }

    [Fact]
    public void Unknown_fields_and_oversized_metadata_are_rejected()
    {
        Assert.Throws<KeyloException>(() => TypedSecrets.Draft(Database, "x", new Dictionary<string, string?> { ["nope"] = "1", ["password"] = "p" }));

        var fields = DbFields();
        fields["host"] = new string('h', 300);
        Assert.Throws<KeyloException>(() => _store.Save(TypedSecrets.Draft(Database, "x", fields)));
    }

    [Fact]
    public void Custom_types_save_with_ids_from_labels_and_are_validated()
    {
        var custom = new SecretTypeDefinition
        {
            Name = "Wi-Fi",
            Fields = [new() { Label = "Network name", Kind = FieldKind.Text }, new() { Label = "Pass phrase", Kind = FieldKind.Password }],
        };
        _types.SaveCustom([custom]);

        var loaded = _types.Find("wi_fi")!;
        Assert.Equal(["network_name", "pass_phrase"], loaded.Fields.Select(f => f.Id));
        Assert.Equal("pass_phrase", loaded.Primary!.Id);
        Assert.Equal("Wi-Fi", _types.Resolve("wi-fi")!.Name);

        Assert.Throws<KeyloException>(() => _types.SaveCustom([new SecretTypeDefinition { Name = "No secret", Fields = [new() { Label = "a" }] }]));
        Assert.Throws<KeyloException>(() => _types.SaveCustom([new SecretTypeDefinition { Name = "Login", Fields = [new() { Label = "p", Kind = FieldKind.Password }] }]));
    }

    [Fact]
    public void Built_in_styles_override_icon_and_colour_only()
    {
        _types.SaveBuiltInStyles(new Dictionary<string, (string?, string?)> { ["login"] = ("Globe24", "#22C55E") });
        var login = _types.Find("login")!;
        Assert.Equal(("Globe24", "#22C55E", 3), (login.Icon, login.Color, login.Fields.Count));
    }

    [Fact]
    public void Search_matches_fields_and_type()
    {
        _store.Save(TypedSecrets.Draft(Database, "prod-db", DbFields()));
        var info = _store.Find("prod-db")!;
        Assert.True(SecretSearch.Matches(info, "db.local"));
        Assert.True(SecretSearch.Matches(info, "type:datab"));
        Assert.False(SecretSearch.Matches(info, "type:login"));
    }
}
