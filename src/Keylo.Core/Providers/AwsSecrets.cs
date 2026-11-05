using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

namespace Keylo.Core.Providers;

/// <summary>A secret in AWS Secrets Manager, without its value.</summary>
public sealed record AwsSecretSummary(string Arn, string Name, string? Description, IReadOnlyDictionary<string, string> Tags);

/// <summary>A secret's value: text (SecretString) or bytes (SecretBinary).</summary>
internal sealed record AwsSecretValue(string? Text, byte[]? Binary);

/// <summary>The few Secrets Manager calls Keylo makes, so tests can stand in for AWS.</summary>
internal interface IAwsSecrets
{
    /// <summary>The region the client talks to, e.g. "us-east-1".</summary>
    string Region { get; }

    Task<IReadOnlyList<AwsSecretSummary>> ListAsync(int? limit, CancellationToken cancellationToken);

    Task<AwsSecretValue> GetValueAsync(string secretId, CancellationToken cancellationToken);

    /// <summary>The secret, or null when there's none with that name or ARN.</summary>
    Task<AwsSecretSummary?> DescribeAsync(string secretId, CancellationToken cancellationToken);

    /// <returns>The new secret's ARN.</returns>
    Task<string> CreateAsync(string name, AwsSecretValue value, string description, string? kmsKeyId,
        IReadOnlyDictionary<string, string> tags, CancellationToken cancellationToken);

    /// <returns>The secret's ARN.</returns>
    Task<string> PutValueAsync(string secretId, AwsSecretValue value, CancellationToken cancellationToken);
}

/// <summary>
/// <see cref="IAwsSecrets"/> through the AWS SDK. Credentials come from the standard chain: a named
/// profile from ~/.aws (including SSO and assumed roles) when one is given, else environment
/// variables, the default profile, and so on. Keylo stores no AWS credentials of its own.
/// </summary>
internal sealed class SdkAwsSecrets : IAwsSecrets
{
    private readonly AmazonSecretsManagerClient _client;

    public SdkAwsSecrets(string? profile, string? region)
    {
        var config = new AmazonSecretsManagerConfig();
        AWSCredentials? credentials = null;
        if (profile is not null)
        {
            var store = new CredentialProfileStoreChain();
            if (!store.TryGetAWSCredentials(profile, out credentials))
                throw new KeyloException($"AWS: there's no profile named '{profile}' in ~/.aws/config or ~/.aws/credentials.");
            if (region is null && store.TryGetProfile(profile, out var found) && found.Region is { } profileRegion)
                config.RegionEndpoint = profileRegion;
        }
        if (region is not null) config.RegionEndpoint = RegionEndpoint.GetBySystemName(region);

        try
        {
            _client = credentials is null ? new AmazonSecretsManagerClient(config) : new AmazonSecretsManagerClient(credentials, config);
        }
        catch (Exception ex) when (ex is AmazonClientException or AmazonServiceException)
        {
            throw AwsSecretsManagerProvider.Explain(ex, profile);
        }
        Region = _client.Config.RegionEndpoint?.SystemName
                 ?? throw new KeyloException("AWS: no region set. Choose one in Settings → Vault providers, or: keylo provider set aws region us-east-1");
    }

    public string Region { get; }

    public async Task<IReadOnlyList<AwsSecretSummary>> ListAsync(int? limit, CancellationToken cancellationToken)
    {
        var results = new List<AwsSecretSummary>();
        string? next = null;
        do
        {
            var page = await _client.ListSecretsAsync(new ListSecretsRequest { MaxResults = limit ?? 100, NextToken = next }, cancellationToken);
            foreach (var s in page.SecretList ?? [])
                results.Add(new AwsSecretSummary(s.ARN, s.Name, s.Description, TagsOf(s.Tags)));
            next = page.NextToken;
        } while (next is not null && limit is null && results.Count < 5000);
        return results;
    }

    public async Task<AwsSecretValue> GetValueAsync(string secretId, CancellationToken cancellationToken)
    {
        var response = await _client.GetSecretValueAsync(new GetSecretValueRequest { SecretId = secretId }, cancellationToken);
        return new AwsSecretValue(response.SecretString, response.SecretBinary?.ToArray());
    }

    public async Task<AwsSecretSummary?> DescribeAsync(string secretId, CancellationToken cancellationToken)
    {
        try
        {
            var s = await _client.DescribeSecretAsync(new DescribeSecretRequest { SecretId = secretId }, cancellationToken);
            return new AwsSecretSummary(s.ARN, s.Name, s.Description, TagsOf(s.Tags));
        }
        catch (ResourceNotFoundException)
        {
            return null;
        }
    }

    public async Task<string> CreateAsync(string name, AwsSecretValue value, string description, string? kmsKeyId,
        IReadOnlyDictionary<string, string> tags, CancellationToken cancellationToken)
    {
        var request = new CreateSecretRequest
        {
            Name = name,
            Description = description,
            KmsKeyId = kmsKeyId,
            Tags = tags.Select(t => new Tag { Key = t.Key, Value = t.Value }).ToList(),
        };
        SetValue(value, s => request.SecretString = s, b => request.SecretBinary = b);
        return (await _client.CreateSecretAsync(request, cancellationToken)).ARN;
    }

    public async Task<string> PutValueAsync(string secretId, AwsSecretValue value, CancellationToken cancellationToken)
    {
        var request = new PutSecretValueRequest { SecretId = secretId };
        SetValue(value, s => request.SecretString = s, b => request.SecretBinary = b);
        return (await _client.PutSecretValueAsync(request, cancellationToken)).ARN;
    }

    private static void SetValue(AwsSecretValue value, Action<string> text, Action<MemoryStream> binary)
    {
        if (value.Text is not null) text(value.Text);
        else binary(new MemoryStream(value.Binary ?? []));
    }

    private static Dictionary<string, string> TagsOf(List<Tag>? tags) =>
        (tags ?? []).Where(t => t.Key is not null).GroupBy(t => t.Key).ToDictionary(g => g.Key, g => g.First().Value ?? "", StringComparer.Ordinal);
}

/// <summary>A profile from ~/.aws/config or ~/.aws/credentials: its name, region and how it signs in (never its keys).</summary>
public sealed record AwsProfile(string Name, string? Region, string SignIn);

/// <summary>What's set up for AWS on this computer: profiles, regions and the AWS CLI. Read with the SDK, so it works without the CLI.</summary>
public static class AwsSetup
{
    public static IReadOnlyList<AwsProfile> Profiles() =>
        new CredentialProfileStoreChain().ListProfiles()
            .GroupBy(p => p.Name, StringComparer.Ordinal)
            .Select(g => g.First())
            .Select(p => new AwsProfile(p.Name, p.Region?.SystemName, SignInOf(p.Options)))
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    /// <summary>Every region the SDK knows, e.g. "us-east-1".</summary>
    public static IReadOnlyList<string> Regions() =>
        RegionEndpoint.EnumerableAllRegions.Select(r => r.SystemName).Order(StringComparer.Ordinal).ToList();

    /// <summary>AWS_REGION or AWS_DEFAULT_REGION, if set.</summary>
    public static string? EnvironmentRegion =>
        Environment.GetEnvironmentVariable("AWS_REGION") is { Length: > 0 } region ? region : Environment.GetEnvironmentVariable("AWS_DEFAULT_REGION") is { Length: > 0 } d ? d : null;

    /// <summary>The aws CLI on PATH (needed to sign in with SSO), or null.</summary>
    public static string? CliPath()
    {
        var names = OperatingSystem.IsWindows() ? new[] { "aws.exe", "aws.cmd" } : ["aws"];
        var directories = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Concat(OperatingSystem.IsWindows() ? [] : ["/usr/local/bin", "/opt/homebrew/bin"]);
        return directories.SelectMany(d => names.Select(n => Path.Combine(d.Trim('"'), n))).FirstOrDefault(File.Exists);
    }

    private static string SignInOf(CredentialProfileOptions o) =>
        !string.IsNullOrEmpty(o.SsoSession) || !string.IsNullOrEmpty(o.SsoStartUrl) ? "sso"
        : !string.IsNullOrEmpty(o.RoleArn) ? "assume role"
        : !string.IsNullOrEmpty(o.CredentialProcess) ? "credential process"
        : !string.IsNullOrEmpty(o.WebIdentityTokenFile) ? "web identity"
        : !string.IsNullOrEmpty(o.AccessKey) ? "access keys"
        : "other";
}
