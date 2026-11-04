using Keylo.Core.Providers;

namespace Keylo.Core.Tests;

public sealed class LinkedSecretTests : IDisposable
{
    private sealed class FakeVault : ILinkedVaultProvider
    {
        public Dictionary<string, string> Values { get; } = new() { ["username"] = "alice", ["password"] = "hunter2-hunter2", ["website"] = "https://example.com" };
        public int Resolves { get; private set; }

        public string Id => "fake";
        public string DisplayName => "Fake Vault";
        public IReadOnlyDictionary<string, string> SettingDescriptions { get; } = new Dictionary<string, string>();

        public Task<IReadOnlyList<LinkedItemSummary>> SearchAsync(string? query, IReadOnlyDictionary<string, string> settings, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<LinkedItemSummary>>([new("item1", "Example", "v1", "Private", null, "LOGIN")]);

        public Task<IReadOnlyList<LinkedField>> DescribeAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<LinkedField>>([new("username", "Username", false), new("password", "Password", true), new("website", "Website", false)]);

        public Task<IReadOnlyDictionary<string, string>> ResolveAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken ct = default)
        {
            Resolves++;
            return Task.FromResult<IReadOnlyDictionary<string, string>>(new Dictionary<string, string>(Values));
        }
    }

    private readonly string _dataDir = Directory.CreateTempSubdirectory("keylo-tests-").FullName;
    private readonly SecretStore _store;
    private readonly ProviderRegistry _registry;
    private readonly FakeVault _vault = new();

    public LinkedSecretTests()
    {
        _store = new SecretStore(_dataDir, $"KeyloUnitTest-{Guid.NewGuid():N}:");
        _registry = new ProviderRegistry(_dataDir);
        _registry.Register(_vault);
    }

    public void Dispose()
    {
        foreach (var secret in _store.List()) _store.Delete(secret.Name);
        Directory.Delete(_dataDir, recursive: true);
    }

    private async Task<LinkedSecrets.Link> LinkAsync(string? only = null)
    {
        var target = new LinkTarget("fake", "item1", "v1", null);
        return new LinkedSecrets.Link(target, "Example", "Private", await _vault.DescribeAsync(target, new Dictionary<string, string>()), only);
    }

    [Fact]
    public async Task A_link_stores_only_the_reference_and_round_trips()
    {
        _store.Save(LinkedSecrets.Draft("example", await LinkAsync(), category: "web"));

        var secret = _store.Get("example");
        Assert.True(LinkedSecrets.IsLinked(secret.Info));
        Assert.DoesNotContain("hunter2", System.Text.Encoding.UTF8.GetString(secret.Value));
        Assert.DoesNotContain(secret.Info.Fields!.Values, v => v.Contains("hunter2"));

        var link = LinkedSecrets.Read(secret.Info)!;
        Assert.Equal(("fake", "item1", "v1"), (link.Target.Provider, link.Target.ItemId, link.Target.VaultId));
        Assert.Equal(["username", "password", "website"], link.Fields.Select(f => f.Id));
        Assert.Equal("password", link.MainField);
        Assert.Equal("password", LinkedSecrets.AsType(link, "Fake Vault").Primary!.Id);
    }

    [Fact]
    public async Task Values_are_read_live_from_the_vault()
    {
        _store.Save(LinkedSecrets.Draft("example", await LinkAsync()));
        var info = _store.Find("example")!;

        Assert.Equal("hunter2-hunter2", (await LinkedSecrets.ResolveAsync(info, _registry, new KeyloConfig()))["password"]);

        _vault.Values["password"] = "rotated-in-the-vault";
        Assert.Equal("rotated-in-the-vault", (await LinkedSecrets.ResolveAsync(info, _registry, new KeyloConfig()))["password"]);
        Assert.Equal(2, _vault.Resolves);
    }

    [Fact]
    public async Task A_single_field_link_exposes_only_that_field()
    {
        _store.Save(LinkedSecrets.Draft("example-user", await LinkAsync(only: "username")));
        var info = _store.Find("example-user")!;
        var link = LinkedSecrets.Read(info)!;

        Assert.Equal("username", link.MainField);
        Assert.Equal(["username"], (await LinkedSecrets.ResolveAsync(info, _registry, new KeyloConfig())).Keys);
    }

    [Fact]
    public void Default_category_is_provider_and_vault_plus_account_when_there_are_several()
    {
        var personal = new LinkedItemSummary("1", "GitHub", "v", "Private", "my.1password.com", "LOGIN");
        var work = personal with { Location = "redteamsoftware.1password.com" };

        Assert.Equal("1Password · Private", LinkedSecrets.DefaultCategory("1Password", personal, severalLocations: false));
        Assert.Equal("1Password · Private (personal)", LinkedSecrets.DefaultCategory("1Password", personal, severalLocations: true));
        Assert.Equal("1Password · Private (redteamsoftware)", LinkedSecrets.DefaultCategory("1Password", work, severalLocations: true));
        Assert.Equal("1Password", LinkedSecrets.DefaultCategory("1Password", personal with { VaultName = null }, severalLocations: false));
    }

    [Fact]
    public async Task Plain_text_fields_of_a_link_count_as_secret_but_usernames_and_urls_do_not()
    {
        var link = await LinkAsync() with { Fields = [new("username", "Username", false), new("production", "Production", false), new("website", "Website", false)] };
        _store.Save(LinkedSecrets.Draft("keys", link));

        var fields = LinkedSecrets.Read(_store.Find("keys")!)!.Fields;
        Assert.Equal([false, true, false], fields.Select(f => f.Secret));
    }

    [Fact]
    public async Task A_missing_provider_is_a_clear_error()
    {
        var link = await LinkAsync() with { Target = new LinkTarget("nope", "item1", null, null) };
        _store.Save(LinkedSecrets.Draft("orphan", link));

        var ex = await Assert.ThrowsAsync<KeyloException>(() => LinkedSecrets.ResolveAsync(_store.Find("orphan")!, _registry, new KeyloConfig()));
        Assert.Contains("isn't installed", ex.Message);
    }
}
