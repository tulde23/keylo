using Keylo.Core;
using Keylo.Core.Security;

namespace Keylo.Core.Tests;

public sealed class SearchTests
{
    private static SecretInfo Info(string name, string? category = null, string? user = null, string? notes = null) =>
        new(name, category, user, notes, DateTimeOffset.Now, 1, StorageKind.CredentialManager);

    [Fact]
    public void All_terms_must_match_some_field()
    {
        var secret = Info("cf-token", "cloud", "tulde23", "DNS edit");

        Assert.True(SecretSearch.Matches(secret, "cloud dns"));
        Assert.True(SecretSearch.Matches(secret, "TULDE"));
        Assert.False(SecretSearch.Matches(secret, "cloud postgres"));
    }

    [Fact]
    public void Cat_prefix_only_matches_the_category()
    {
        Assert.True(SecretSearch.Matches(Info("x", "cloud"), "cat:clo"));
        Assert.False(SecretSearch.Matches(Info("cloud-thing", "db"), "cat:cloud"));
    }

    [Fact]
    public void Filter_by_category_is_exact()
    {
        var secrets = new[] { Info("a", "db"), Info("b", "dbx"), Info("c") };
        Assert.Equal(["a"], SecretSearch.Filter(secrets, null, "DB").Select(s => s.Name));
    }
}

public sealed class AccessKeyTests
{
    private static SecretInfo Info(string name, string? category) =>
        new(name, category, null, null, DateTimeOffset.Now, 1, StorageKind.CredentialManager);

    private static (KeyloConfig Config, string Token) Config(bool allowGet = false, DateTimeOffset? expires = null)
    {
        var (key, token) = AccessKeys.Create("agents", expires);
        key.Categories = ["dev"];
        key.Secrets = ["one-off"];
        key.AllowGet = allowGet;
        return (new KeyloConfig { AccessKeys = [key] }, token);
    }

    [Fact]
    public void A_token_finds_its_key_and_only_the_hash_is_stored()
    {
        var (config, token) = Config();
        Assert.StartsWith("kyl_", token);
        Assert.Equal("agents", AccessKeys.Find(config, token)?.Name);
        Assert.DoesNotContain(token, System.Text.Json.JsonSerializer.Serialize(config));
    }

    [Fact]
    public void Wrong_missing_or_expired_tokens_find_nothing()
    {
        var (config, token) = Config();
        Assert.Null(AccessKeys.Find(config, token + "x"));
        Assert.Null(AccessKeys.Find(config, null));
        Assert.Null(AccessKeys.Find(config, "kyl_"));

        var (expired, expiredToken) = Config(expires: DateTimeOffset.Now.AddMinutes(-1));
        Assert.Null(AccessKeys.Find(expired, expiredToken));
    }

    [Fact]
    public void Run_is_allowed_for_covered_secrets()
    {
        var key = Config().Config.AccessKeys[0];
        Assert.True(key.Allows(SecretOperation.Run, [Info("x", "DEV"), Info("one-off", null)]));
    }

    [Fact]
    public void Get_needs_allow_get()
    {
        Assert.False(Config().Config.AccessKeys[0].Allows(SecretOperation.Get, [Info("x", "dev")]));
        Assert.True(Config(allowGet: true).Config.AccessKeys[0].Allows(SecretOperation.Get, [Info("x", "dev")]));
    }

    [Fact]
    public void Scope_all_covers_everything_and_an_empty_key_covers_nothing()
    {
        var key = new AccessKey { Scope = KeyScope.All };
        Assert.True(key.Allows(SecretOperation.Run, [Info("anything", null), Info("bank", "personal")]));
        Assert.False(key.Allows(SecretOperation.Get, [Info("anything", null)]));

        Assert.False(new AccessKey().Covers(Info("anything", "dev")));
    }

    [Fact]
    public void Every_secret_must_be_covered()
    {
        var key = Config().Config.AccessKeys[0];
        Assert.False(key.Allows(SecretOperation.Run, [Info("x", "dev"), Info("bank", "personal")]));
        Assert.False(key.Allows(SecretOperation.Run, []));
    }

    [Fact]
    public void Grant_adds_secrets_once_to_the_named_key()
    {
        var (config, _) = Config();
        var id = config.AccessKeys[0].Id;
        Assert.True(AccessKeys.Grant(config, id, ["bank", "BANK", "one-off"]));
        Assert.Equal(["one-off", "bank"], config.AccessKeys[0].Secrets);
        Assert.False(AccessKeys.Grant(config, "nope", ["x"]));
    }

    [Fact]
    public void Approval_requests_round_trip_and_clip_long_text()
    {
        var request = new ApprovalRequest(SecretOperation.Run, ["a", "b"], "id1", "Claude Code", new string('r', 5000), "echo hi", true);
        var decoded = ApprovalRequest.Decode(request.Encode());
        Assert.NotNull(decoded);
        Assert.Equal(["a", "b"], decoded.Secrets);
        Assert.Equal("echo hi", decoded.Command);
        Assert.True(decoded.Reason!.Length < 2100);
        Assert.Null(ApprovalRequest.Decode("not base64!"));
    }
}

public sealed class RedactorTests
{
    [Fact]
    public void Values_and_their_trimmed_form_are_replaced()
    {
        var redactor = new OutputRedactor();
        redactor.Add("token", "s3cr3t-value\n");
        Assert.Equal("auth=[keylo:token] ok", redactor.Redact("auth=s3cr3t-value ok"));
    }

    [Fact]
    public void Longer_values_win_and_short_ones_are_left_alone()
    {
        var redactor = new OutputRedactor();
        redactor.Add("short", "abc");
        redactor.Add("inner", "pass");
        redactor.Add("outer", "password123");
        Assert.Equal("[keylo:outer] [keylo:inner] abc", redactor.Redact("password123 pass abc"));
        Assert.Equal(11, redactor.LongestValue);
    }
}
