using System.Text;
using System.Text.Json.Nodes;
using Keylo.Core.Providers;

namespace Keylo.Core.Tests;

/// <summary>The AWS Secrets Manager provider against an in-memory stand-in for AWS.</summary>
public sealed class AwsSecretsManagerTests
{
    private sealed class FakeAws(string region) : IAwsSecrets
    {
        public sealed class Stored(string arn, string name, AwsSecretValue value)
        {
            public string Arn { get; } = arn;
            public string Name { get; } = name;
            public string? Description { get; init; }
            public AwsSecretValue Value { get; set; } = value;
            public Dictionary<string, string> Tags { get; init; } = new();
            public string? KmsKeyId { get; set; }
        }

        public List<Stored> Secrets { get; } = [];
        public string Region { get; } = region;

        public Stored Add(string name, string? text, byte[]? binary = null, string? description = null, Dictionary<string, string>? tags = null)
        {
            var stored = new Stored($"arn:aws:secretsmanager:{Region}:123456789012:secret:{name}-AbCdEf", name, new AwsSecretValue(text, binary))
                { Description = description, Tags = tags ?? new() };
            Secrets.Add(stored);
            return stored;
        }

        private Stored? Find(string id) => Secrets.FirstOrDefault(s => s.Arn == id || s.Name == id);

        private static AwsSecretSummary Summary(Stored s) => new(s.Arn, s.Name, s.Description, s.Tags);

        public Task<IReadOnlyList<AwsSecretSummary>> ListAsync(int? limit, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<AwsSecretSummary>>(Secrets.Take(limit ?? int.MaxValue).Select(Summary).ToList());

        public Task<AwsSecretValue> GetValueAsync(string secretId, CancellationToken ct) =>
            Task.FromResult(Find(secretId)?.Value ?? throw new InvalidOperationException("no such secret"));

        public Task<AwsSecretSummary?> DescribeAsync(string secretId, CancellationToken ct) =>
            Task.FromResult(Find(secretId) is { } s ? Summary(s) : null);

        public Task<string> CreateAsync(string name, AwsSecretValue value, string description, string? kmsKeyId,
            IReadOnlyDictionary<string, string> tags, CancellationToken ct)
        {
            var stored = Add(name, value.Text, value.Binary, description, tags.ToDictionary());
            stored.KmsKeyId = kmsKeyId;
            return Task.FromResult(stored.Arn);
        }

        public Task<string> PutValueAsync(string secretId, AwsSecretValue value, CancellationToken ct)
        {
            var stored = Find(secretId)!;
            stored.Value = value;
            return Task.FromResult(stored.Arn);
        }
    }

    private readonly FakeAws _aws = new("eu-west-2");
    private readonly List<(string? Profile, string? Region)> _connections = [];
    private readonly AwsSecretsManagerProvider _provider;

    public AwsSecretsManagerTests()
    {
        _provider = new AwsSecretsManagerProvider((profile, region) =>
        {
            _connections.Add((profile, region));
            return _aws;
        });
    }

    private static Dictionary<string, string> Settings(params (string Key, string Value)[] pairs) => pairs.ToDictionary(p => p.Key, p => p.Value);

    private static Secret Plain(string name, string value, string? username = null, string? category = null) =>
        new(new SecretInfo(name, category, username, null, DateTimeOffset.Now, value.Length, StorageKind.CredentialManager), Encoding.UTF8.GetBytes(value));

    // ------------------------------------------------------------------ linking

    [Fact]
    public async Task Search_matches_names_descriptions_and_tags_and_records_profile_and_region()
    {
        _aws.Add("prod/db", "{}", description: "Orders database");
        _aws.Add("stripe-key", "sk_test", tags: new() { ["team"] = "billing" });
        _aws.Add("unrelated", "x");

        var byDescription = await _provider.SearchAsync("orders", Settings(("profile", "work")));
        var item = Assert.Single(byDescription);
        Assert.Equal(("prod/db", "work", "eu-west-2"), (item.Title, item.VaultId, item.Location));
        Assert.StartsWith("arn:aws:secretsmanager:", item.ItemId);

        Assert.Equal("stripe-key", Assert.Single(await _provider.SearchAsync("billing", Settings())).Title);
        Assert.Equal(3, (await _provider.SearchAsync(null, Settings())).Count);
        Assert.Equal(("work", (string?)null), _connections[0]);
    }

    [Fact]
    public async Task Listing_returns_names_and_tags_never_values()
    {
        _aws.Add("payments/stripe", "sk_live_secret", tags: new() { ["team"] = "billing" });
        _aws.Add("payments/db", """{"password":"pw"}""");

        var (region, secrets) = await _provider.ListSecretsAsync("work", null, "payments");

        Assert.Equal("eu-west-2", region);
        Assert.Equal(["payments/db", "payments/stripe"], secrets.Select(s => s.Name));
        Assert.Equal("billing", secrets[1].Tags["team"]);
        Assert.DoesNotContain(secrets, s => s.ToString().Contains("sk_live_secret"));
    }

    [Fact]
    public void A_json_object_becomes_one_field_per_key()
    {
        var fields = AwsSecretsManagerProvider.Fields(new AwsSecretValue(
            """{"username":"app","password":"s3cret","host":"db.internal","port":5432,"options":{"ssl":true}}""", null));

        Assert.Equal(["username", "password", "host", "port", "options"], fields.Select(f => f.Field.Id));
        Assert.Equal("s3cret", fields.Single(f => f.Field.Id == "password").Value);
        Assert.Equal("5432", fields.Single(f => f.Field.Id == "port").Value);
        Assert.Equal("""{"ssl":true}""", fields.Single(f => f.Field.Id == "options").Value);
        Assert.False(fields.Single(f => f.Field.Id == "username").Field.Secret);
        Assert.True(fields.Single(f => f.Field.Id == "password").Field.Secret);
    }

    [Fact]
    public void Text_and_binary_values_are_a_single_field()
    {
        var text = Assert.Single(AwsSecretsManagerProvider.Fields(new AwsSecretValue("sk_live_123", null)));
        Assert.Equal(("value", "sk_live_123", true), (text.Field.Id, text.Value, text.Field.Secret));

        var notAnObject = Assert.Single(AwsSecretsManagerProvider.Fields(new AwsSecretValue("[1,2]", null)));
        Assert.Equal("[1,2]", notAnObject.Value);

        var binary = Assert.Single(AwsSecretsManagerProvider.Fields(new AwsSecretValue(null, [1, 2, 3])));
        Assert.Equal("AQID", binary.Value);
    }

    [Fact]
    public async Task A_link_reads_the_current_value_with_its_own_profile_and_region()
    {
        var stored = _aws.Add("prod/db", """{"username":"app","password":"first"}""");
        var target = new LinkTarget("aws", stored.Arn, "work", "eu-west-2");

        Assert.Equal("first", (await _provider.ResolveAsync(target, Settings(("profile", "other"))))["password"]);

        stored.Value = new AwsSecretValue("""{"username":"app","password":"rotated"}""", null);
        Assert.Equal("rotated", (await _provider.ResolveAsync(target, Settings()))["password"]);
        Assert.All(_connections, c => Assert.Equal(("work", "eu-west-2"), c));
    }

    [Fact]
    public async Task Linked_aws_secrets_resolve_through_keylo_links()
    {
        var registry = new ProviderRegistry(Directory.CreateTempSubdirectory("keylo-tests-").FullName);
        registry.Register(_provider);
        var stored = _aws.Add("api", "token-123");
        var target = new LinkTarget("aws", stored.Arn, null, "eu-west-2");
        var link = new LinkedSecrets.Link(target, "api", "eu-west-2", await _provider.DescribeAsync(target, Settings()));
        var draft = LinkedSecrets.Draft("api", link);
        var info = new SecretInfo("api", null, null, null, DateTimeOffset.Now, 2, StorageKind.CredentialManager, Type: draft.Type, Fields: draft.Fields);

        Assert.Equal("token-123", (await LinkedSecrets.ResolveAsync(info, registry, new KeyloConfig()))["value"]);
        Assert.Equal("value", link.MainField);
    }

    [Fact]
    public async Task A_per_environment_link_reads_from_the_environment_asked_for()
    {
        _aws.Add("orders/db", """{"password":"from-any-account"}""");
        _aws.Add("orders/db-prod", """{"password":"prod-only-name"}""");
        var registry = new ProviderRegistry(Directory.CreateTempSubdirectory("keylo-tests-").FullName);
        registry.Register(_provider);
        var config = new KeyloConfig();
        config.Providers["aws"] = new Dictionary<string, string>
        {
            ["env:dev"] = "acme-dev|eu-west-2|",
            ["env:prod"] = "acme-prod|eu-west-1|ask",
            [VaultEnvironments.DefaultKey] = "dev",
        };

        var target = new LinkTarget("aws", "orders/db", null, LinkedSecrets.PerEnvironment);
        var link = new LinkedSecrets.Link(target, "orders/db", "per environment", [new("password", "password", true)],
            EnvironmentNames: new Dictionary<string, string> { ["prod"] = "orders/db-prod" });
        var draft = LinkedSecrets.Draft("orders-db", link);
        var info = new SecretInfo("orders-db", null, null, null, DateTimeOffset.Now, 2, StorageKind.CredentialManager, Type: draft.Type, Fields: draft.Fields);

        Assert.True(LinkedSecrets.Read(info)!.IsPerEnvironment);
        Assert.Equal("from-any-account", (await LinkedSecrets.ResolveAsync(info, registry, config))["password"]);
        Assert.Equal(("acme-dev", "eu-west-2"), _connections[^1]!);

        Assert.Equal("prod-only-name", (await LinkedSecrets.ResolveAsync(info, registry, config, "prod"))["password"]);
        Assert.Equal(("acme-prod", "eu-west-1"), _connections[^1]!);
        Assert.True(LinkedSecrets.EnvironmentFor(info, config, "prod")!.AlwaysAsk);

        Assert.Contains("no environment 'qa'", (await Assert.ThrowsAsync<KeyloException>(() => LinkedSecrets.ResolveAsync(info, registry, config, "qa"))).Message);
    }

    [Fact]
    public void Naming_an_environment_for_an_ordinary_link_is_an_error()
    {
        var link = new LinkedSecrets.Link(new LinkTarget("aws", "arn:x", "work", "eu-west-2"), "x", null, [new("value", "Value", true)]);
        var draft = LinkedSecrets.Draft("x", link);
        var info = new SecretInfo("x", null, null, null, DateTimeOffset.Now, 2, StorageKind.CredentialManager, Type: draft.Type, Fields: draft.Fields);

        Assert.Null(LinkedSecrets.EnvironmentFor(info, new KeyloConfig(), null));
        Assert.Throws<KeyloException>(() => LinkedSecrets.EnvironmentFor(info, new KeyloConfig(), "prod"));
    }

    [Fact]
    public async Task Searching_an_environment_uses_its_profile_and_region()
    {
        _aws.Add("orders/db", "{}");
        var settings = Settings(("env:uat", "acme-uat|ap-southeast-2|"), (LinkedSecrets.EnvironmentSetting, "uat"));

        Assert.Single(await _provider.SearchAsync(null, settings));
        Assert.Equal(("acme-uat", "ap-southeast-2"), _connections[^1]!);
    }

    // ------------------------------------------------------------------ pushing

    [Fact]
    public async Task Push_creates_a_tagged_secret_under_the_prefix_then_updates_it()
    {
        var settings = Settings(("region", "eu-west-2"), ("kms_key_id", "alias/keylo"));

        var created = await _provider.PushAsync(Plain("stripe key", "sk_test_1", category: "billing"), settings);
        Assert.True(created.Succeeded, created.Message);
        var stored = Assert.Single(_aws.Secrets);
        Assert.Equal("keylo/stripe-key", stored.Name);
        Assert.Equal("sk_test_1", stored.Value.Text);
        Assert.Equal("alias/keylo", stored.KmsKeyId);
        Assert.Equal(("true", "stripe key", "billing"), (stored.Tags["keylo:managed"], stored.Tags["keylo:name"], stored.Tags["keylo:category"]));

        var updated = await _provider.PushAsync(Plain("stripe key", "sk_test_2"), settings);
        Assert.True(updated.Succeeded, updated.Message);
        Assert.Equal("sk_test_2", Assert.Single(_aws.Secrets).Value.Text);
        Assert.True((await _provider.PreviewAsync("stripe key", settings)).Exists);
    }

    [Fact]
    public async Task Push_never_overwrites_a_secret_keylo_did_not_create()
    {
        _aws.Add("keylo/shared", "theirs");

        var result = await _provider.PushAsync(Plain("shared", "mine"), Settings(("region", "eu-west-2")));

        Assert.False(result.Succeeded);
        Assert.Contains("wasn't created by Keylo", result.Message);
        Assert.Equal("theirs", _aws.Secrets[0].Value.Text);
    }

    [Fact]
    public void A_username_or_a_type_makes_a_json_value()
    {
        var login = AwsSecretsManagerProvider.ValueFor(Plain("svc", "pw", username: "alice"));
        Assert.Equal(("alice", "pw"), (JsonNode.Parse(login.Text!)!["username"]!.GetValue<string>(), JsonNode.Parse(login.Text!)!["password"]!.GetValue<string>()));

        var database = new SecretTypeCatalog().Find("database")!;
        var draft = TypedSecrets.Draft(database, "db", new Dictionary<string, string?> { ["host"] = "db.local", ["username"] = "app", ["password"] = "pw" });
        var info = new SecretInfo("db", null, draft.Username, null, DateTimeOffset.Now, draft.Value.Length, StorageKind.CredentialManager,
            Type: draft.Type, Fields: draft.Fields);
        var json = JsonNode.Parse(AwsSecretsManagerProvider.ValueFor(new Secret(info, draft.Value)).Text!)!;
        Assert.Equal(("db.local", "app", "pw"), (json["host"]!.GetValue<string>(), json["username"]!.GetValue<string>(), json["password"]!.GetValue<string>()));
        Assert.Null(json["connection_string"]);
    }

    [Fact]
    public void Push_is_offered_once_a_profile_or_region_is_chosen()
    {
        Assert.False(((IVaultProvider)_provider).IsConfigured(Settings()));
        Assert.True(((IVaultProvider)_provider).IsConfigured(Settings(("region", "us-east-1"))));
        Assert.True(((ILinkedVaultProvider)_provider).IsConfigured(Settings()));
        Assert.Equal("team/x-y", AwsSecretsManagerProvider.AwsName("x y", Settings(("prefix", "team/"))));
    }

    [Fact]
    public async Task Aws_errors_become_messages_with_the_fix()
    {
        var failing = new AwsSecretsManagerProvider((_, _) => throw new Amazon.Runtime.AmazonClientException("Unable to get credentials. SSO token expired."));

        var ex = await Assert.ThrowsAsync<KeyloException>(() => failing.SearchAsync(null, Settings(("profile", "work"))));
        Assert.Contains("aws sso login --profile work", ex.Message);
        Assert.False((await failing.GetStatusAsync(Settings(("profile", "work")))).Ready);

        var noRegion = new AwsSecretsManagerProvider((_, _) => throw new Amazon.Runtime.AmazonClientException("No RegionEndpoint or ServiceURL configured"));
        Assert.Contains("no region chosen", (await Assert.ThrowsAsync<KeyloException>(() => noRegion.SearchAsync(null, Settings()))).Message);
    }
}
