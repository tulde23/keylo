using Keylo.Core.Providers;

namespace Keylo.Core.Tests;

public sealed class VaultEnvironmentTests
{
    private static Dictionary<string, string> Environments() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["env:dev"] = "acme-dev|eu-west-2|",
        ["env:uat"] = "acme-uat|eu-west-2|",
        ["env:prod"] = "acme-prod-readonly|eu-west-1|ask",
        [VaultEnvironments.DefaultKey] = "dev",
        ["region"] = "us-east-1",
    };

    [Fact]
    public void Environments_round_trip_through_settings()
    {
        var settings = Environments();
        var read = VaultEnvironments.Read(settings);

        Assert.Equal(["dev", "prod", "uat"], read.Select(e => e.Name));
        Assert.Equal(new VaultEnvironment("prod", "acme-prod-readonly", "eu-west-1", true), read[1]);
        Assert.Equal("dev", VaultEnvironments.Default(settings));

        VaultEnvironments.Write(settings, [new("staging", "acme-stg", null, false)], null);
        Assert.Equal("staging", Assert.Single(VaultEnvironments.Read(settings)).Name);
        Assert.Equal("staging", VaultEnvironments.Default(settings)); // the only one
        Assert.Equal("us-east-1", settings["region"]);                 // other settings untouched
        Assert.Throws<KeyloException>(() => VaultEnvironments.Write(settings, [new("bad name", null, null, false)], null));
    }

    [Fact]
    public void Production_names_start_as_always_ask()
    {
        Assert.True(VaultEnvironments.LooksLikeProduction("prod"));
        Assert.True(VaultEnvironments.LooksLikeProduction("Production"));
        Assert.False(VaultEnvironments.LooksLikeProduction("dev"));
    }

    [Theory]
    [InlineData("orders-db", "orders-db", null, null)]
    [InlineData("orders-db:password", "orders-db", null, "password")]
    [InlineData("orders-db@prod", "orders-db", "prod", null)]
    [InlineData("orders-db@prod:password", "orders-db", "prod", "password")]
    [InlineData("me@example.com", "me@example.com", null, null)]   // an exact name wins
    [InlineData("me@example.com:token", "me@example.com", null, "token")]
    public void References_name_an_environment_and_a_field(string text, string name, string? environment, string? field)
    {
        var known = new HashSet<string> { "orders-db", "me@example.com" };
        Assert.Equal(new SecretReference(name, environment, field), SecretReference.Parse(text, known.Contains));
    }

    [Fact]
    public void Unknown_names_are_not_references()
    {
        Assert.Null(SecretReference.Parse("nope@prod:password", _ => false));
        Assert.Equal("orders-db@prod", new SecretReference("orders-db", "prod", "password").Display);
    }
}
