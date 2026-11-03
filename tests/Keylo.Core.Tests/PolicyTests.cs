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

public sealed class TrustPolicyTests
{
    private static readonly IReadOnlyList<AncestorProcess> ClaudeChain =
        [new(1, "bash.exe"), new(2, "claude.exe"), new(3, "pwsh.exe")];

    private static SecretInfo Info(string name, string? category) =>
        new(name, category, null, null, DateTimeOffset.Now, 1, StorageKind.CredentialManager);

    private static KeyloConfig Config(bool allowGet = false) => new()
    {
        TrustGroups = [new TrustGroup { Name = "agents", Callers = ["claude"], Categories = ["dev"], Secrets = ["one-off"], AllowGet = allowGet }],
    };

    [Fact]
    public void Run_is_trusted_for_covered_secrets_from_a_listed_caller()
    {
        var decision = TrustPolicy.Find(Config(), SecretOperation.Run, [Info("x", "dev"), Info("one-off", null)], ClaudeChain);
        Assert.Equal("claude.exe", decision?.Caller.ExecutableName);
    }

    [Fact]
    public void Get_needs_allow_get()
    {
        Assert.Null(TrustPolicy.Find(Config(), SecretOperation.Get, [Info("x", "dev")], ClaudeChain));
        Assert.NotNull(TrustPolicy.Find(Config(allowGet: true), SecretOperation.Get, [Info("x", "dev")], ClaudeChain));
    }

    [Fact]
    public void One_uncovered_secret_makes_the_whole_request_untrusted()
    {
        Assert.Null(TrustPolicy.Find(Config(), SecretOperation.Run, [Info("x", "dev"), Info("bank", "personal")], ClaudeChain));
    }

    [Fact]
    public void Other_callers_are_not_trusted()
    {
        Assert.Null(TrustPolicy.Find(Config(), SecretOperation.Run, [Info("x", "dev")], [new(1, "node.exe")]));
        Assert.Null(TrustPolicy.Find(Config(), SecretOperation.Run, [Info("x", "dev")], []));
    }
}
