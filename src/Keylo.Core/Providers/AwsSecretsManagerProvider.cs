using System.Text.Json;
using System.Text.Json.Nodes;
using Amazon.Runtime;

namespace Keylo.Core.Providers;

/// <summary>
/// AWS Secrets Manager, through the AWS SDK with the standard credential chain (profiles in ~/.aws,
/// SSO, environment variables). Keylo keeps no AWS credentials.
///
/// Linking: a Keylo secret points at a secret by ARN, with the profile and region it was found
/// with; the value is read each time it's used, so rotated secrets (RDS, Lambda rotation) are
/// always current. A JSON object becomes one field per key ("prod-db:password"), anything else a
/// single "value" field.
///
/// Pushing: copies Keylo secrets to "{prefix}{name}" (prefix "keylo/" by default) as JSON for
/// typed secrets and plain text otherwise, tagged keylo:managed so later pushes update them.
/// Secrets Keylo didn't create are never overwritten.
/// </summary>
public sealed class AwsSecretsManagerProvider : IVaultProvider, ILinkedVaultProvider
{
    public const string DefaultPrefix = "keylo/";
    private const string ManagedTag = "keylo:managed", NameTag = "keylo:name", CategoryTag = "keylo:category";

    private readonly Func<string?, string?, IAwsSecrets> _connect;

    public AwsSecretsManagerProvider() : this((profile, region) => new SdkAwsSecrets(profile, region))
    {
    }

    /// <param name="connect">Makes a client for a profile and region (either may be null: the defaults).</param>
    internal AwsSecretsManagerProvider(Func<string?, string?, IAwsSecrets> connect) => _connect = connect;

    public string Id => "aws";

    public string DisplayName => "AWS Secrets Manager";

    public IReadOnlyDictionary<string, string> SettingDescriptions { get; } = new Dictionary<string, string>
    {
        ["profile"] = "AWS profile from ~/.aws (optional; the default credentials otherwise)",
        ["region"] = "Region, e.g. us-east-1 (optional; the profile's region otherwise)",
        ["prefix"] = $"Name prefix for pushed secrets (optional; {DefaultPrefix} otherwise)",
        ["kms_key_id"] = "KMS key for pushed secrets (optional; the account's default key otherwise)",
    };

    /// <summary>The profiles in ~/.aws and every region, for the settings page (any other text is accepted too).</summary>
    public IReadOnlyList<string>? SettingOptions(string key)
    {
        try
        {
            return key switch
            {
                "profile" => AwsSetup.Profiles().Select(p => p.Name).ToList(),
                "region" => AwsSetup.Regions(),
                _ => null,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or FormatException)
        {
            return []; // An unreadable ~/.aws: an empty list, so a name can still be typed.
        }
    }

    /// <summary>Pushing is offered once a profile or region is chosen, so AWS isn't offered to everyone.</summary>
    public bool IsConfigured(IReadOnlyDictionary<string, string> settings) => Setting(settings, "profile") is not null || Setting(settings, "region") is not null;

    // Linking works with the default credentials; each link records the profile and region it used.
    bool ILinkedVaultProvider.IsConfigured(IReadOnlyDictionary<string, string> settings) => true;

    // ------------------------------------------------------------------ linking

    /// <summary>Environments (dev, uat, prod…) each name a profile and region; see <see cref="VaultEnvironments"/>.</summary>
    public bool HasEnvironments => true;

    /// <summary>
    /// The profile and region to use: the environment's when settings name one (the Link dialog, or
    /// a per-environment link being read), else the configured profile and region.
    /// </summary>
    internal static (string? Profile, string? Region) ScopeFor(IReadOnlyDictionary<string, string> settings)
    {
        if (Setting(settings, LinkedSecrets.EnvironmentSetting) is not { } name) return (Setting(settings, "profile"), Setting(settings, "region"));
        var env = VaultEnvironments.Find(settings, name)
                  ?? throw new KeyloException($"There's no AWS environment '{name}'. Add it in Settings → Vault providers.");
        return (env.Profile, env.Region);
    }

    public async Task<IReadOnlyList<LinkedItemSummary>> SearchAsync(string? query, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default)
    {
        var (profile, region) = ScopeFor(settings);
        var aws = Connect(profile, region);
        var secrets = await CallAsync(() => aws.ListAsync(null, cancellationToken), profile);
        return secrets
            .Where(s => Matches(s, query))
            .Select(s => new LinkedItemSummary(s.Arn, s.Name, profile, profile, aws.Region, null))
            .OrderBy(s => s.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Secrets (names, descriptions and tags; never values) in a profile and region, and the region used.</summary>
    public async Task<(string Region, IReadOnlyList<AwsSecretSummary> Secrets)> ListSecretsAsync(string? profile, string? region, string? query,
        CancellationToken cancellationToken = default)
    {
        var aws = Connect(profile, region);
        var secrets = await CallAsync(() => aws.ListAsync(null, cancellationToken), profile);
        return (aws.Region, secrets.Where(s => Matches(s, query)).OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList());
    }

    public async Task<IReadOnlyList<LinkedField>> DescribeAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default) =>
        Fields(await GetValueAsync(target, settings, cancellationToken)).Select(f => f.Field).ToList();

    public async Task<IReadOnlyDictionary<string, string>> ResolveAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default) =>
        Fields(await GetValueAsync(target, settings, cancellationToken))
            .Where(f => f.Value.Length > 0)
            .ToDictionary(f => f.Field.Id, f => f.Value, StringComparer.OrdinalIgnoreCase);

    private async Task<AwsSecretValue> GetValueAsync(LinkTarget target, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken)
    {
        string? profile, region;
        var secretId = target.ItemId;
        if (target.Location == LinkedSecrets.PerEnvironment)
        {
            // Per environment: the item is the secret's name; the environment (else the default) picks the account.
            var scoped = new Dictionary<string, string>(settings, StringComparer.OrdinalIgnoreCase);
            if (Setting(scoped, LinkedSecrets.EnvironmentSetting) is null)
                scoped[LinkedSecrets.EnvironmentSetting] = VaultEnvironments.Default(settings)
                                                           ?? throw new KeyloException("This secret is linked per environment; choose one (name@env), or set a default environment.");
            (profile, region) = ScopeFor(scoped);
            secretId = Setting(settings, LinkedSecrets.SecretIdSetting) ?? secretId;
        }
        else
        {
            // An ordinary link uses the profile and region it was made with (VaultId and Location), whatever the settings say now.
            profile = string.IsNullOrEmpty(target.VaultId) ? null : target.VaultId;
            region = string.IsNullOrEmpty(target.Location) ? null : target.Location;
        }

        var aws = Connect(profile, region);
        return await CallAsync(() => aws.GetValueAsync(secretId, cancellationToken), profile);
    }

    private static bool Matches(AwsSecretSummary secret, string? query) =>
        string.IsNullOrWhiteSpace(query) ||
        query.Split(' ', StringSplitOptions.RemoveEmptyEntries).All(term =>
            secret.Name.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            (secret.Description?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
            secret.Tags.Values.Any(v => v.Contains(term, StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// A value's fields with stable ids: each key of a JSON object (nested values as JSON), else one
    /// "value" field (bytes as base64).
    /// </summary>
    internal static List<(LinkedField Field, string Value)> Fields(AwsSecretValue value)
    {
        if (value.Text is null)
            return [(new LinkedField("value", "Value (base64)", true), Convert.ToBase64String(value.Binary ?? []))];

        if (TryParseObject(value.Text) is not { } json)
            return [(new LinkedField("value", "Value", true), value.Text)];

        var fields = new List<(LinkedField, string)>();
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, node) in json)
        {
            var id = FieldDefinition.IdFor(key);
            if (id.Length == 0) id = "field";
            var unique = id;
            for (var n = 2; !used.Add(unique); n++) unique = $"{id}_{n}";

            var text = node switch
            {
                null => "",
                JsonValue v when v.GetValueKind() == JsonValueKind.String => v.GetValue<string>(),
                _ => node.ToJsonString(),
            };
            fields.Add((new LinkedField(unique, key, !LinkedSecrets.LooksPublic(unique)), text));
        }
        return fields;
    }

    private static JsonObject? TryParseObject(string text)
    {
        if (!text.TrimStart().StartsWith('{')) return null;
        try
        {
            return JsonNode.Parse(text) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    // ------------------------------------------------------------------ pushing

    public async Task<ProviderStatus> GetStatusAsync(IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default)
    {
        var profile = Setting(settings, "profile");
        try
        {
            var aws = Connect(profile, Setting(settings, "region"));
            await CallAsync(() => aws.ListAsync(1, cancellationToken), profile);
            return new ProviderStatus(true, $"Ready ({aws.Region}, {profile ?? "default credentials"})");
        }
        catch (KeyloException ex)
        {
            return new ProviderStatus(false, ex.Message);
        }
    }

    public async Task<PushPreview> PreviewAsync(string secretName, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default)
    {
        var profile = Setting(settings, "profile");
        var name = AwsName(secretName, settings);
        try
        {
            var aws = Connect(profile, Setting(settings, "region"));
            var existing = await CallAsync(() => aws.DescribeAsync(name, cancellationToken), profile);
            var where = $"{aws.Region} · {profile ?? "default credentials"}";
            return new PushPreview($"AWS Secrets Manager as “{name}” ({where})", existing is not null, name, where);
        }
        catch (KeyloException)
        {
            return new PushPreview($"AWS Secrets Manager as “{name}”", null, name, profile ?? "default credentials");
        }
    }

    public async Task<PushResult> PushAsync(Secret secret, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default)
    {
        var info = secret.Info;
        var profile = Setting(settings, "profile");
        var name = AwsName(info.Name, settings);
        try
        {
            var aws = Connect(profile, Setting(settings, "region"));
            var value = ValueFor(secret);
            var existing = await CallAsync(() => aws.DescribeAsync(name, cancellationToken), profile);
            if (existing is not null)
            {
                if (!existing.Tags.ContainsKey(ManagedTag))
                    return new PushResult(info.Name, false, $"“{name}” already exists in {aws.Region} and wasn't created by Keylo, so it was left alone.");
                var arn = await CallAsync(() => aws.PutValueAsync(existing.Arn, value, cancellationToken), profile);
                return new PushResult(info.Name, true, $"Updated “{name}” in {aws.Region}", arn);
            }

            var tags = new Dictionary<string, string> { [ManagedTag] = "true", [NameTag] = TagValue(info.Name) };
            if (info.Category is not null) tags[CategoryTag] = TagValue(info.Category);
            var created = await CallAsync(() => aws.CreateAsync(name, value, "Pushed from Keylo", Setting(settings, "kms_key_id"), tags, cancellationToken), profile);
            return new PushResult(info.Name, true, $"Created “{name}” in {aws.Region}", created);
        }
        catch (KeyloException ex)
        {
            return new PushResult(info.Name, false, ex.Message);
        }
    }

    /// <summary>
    /// Typed secrets as a JSON object of their fields; a plain secret with a username as
    /// {"username","password"} (the shape RDS uses); otherwise its text, or its bytes.
    /// </summary>
    internal static AwsSecretValue ValueFor(Secret secret)
    {
        var info = secret.Info;
        if (new SecretTypeCatalog().Find(info.Type) is { } type)
        {
            var fields = TypedSecrets.ReadFields(type, info, secret.Value, derive: false);
            return new AwsSecretValue(new JsonObject(fields.Select(f => KeyValuePair.Create(f.Key, (JsonNode?)f.Value))).ToJsonString(), null);
        }

        if (TypedSecrets.DecodeText(secret.Value) is not { } text) return new AwsSecretValue(null, secret.Value);
        return info.Username is null
            ? new AwsSecretValue(text, null)
            : new AwsSecretValue(new JsonObject { ["username"] = info.Username, ["password"] = text }.ToJsonString(), null);
    }

    /// <summary>"{prefix}{name}", with characters Secrets Manager doesn't allow in names replaced by '-'.</summary>
    internal static string AwsName(string secretName, IReadOnlyDictionary<string, string> settings)
    {
        var prefix = Setting(settings, "prefix") ?? DefaultPrefix;
        return new string((prefix + secretName).Select(c => char.IsAsciiLetterOrDigit(c) || "/_+=.@-".Contains(c) ? c : '-').ToArray());
    }

    /// <summary>Tag values allow letters, digits, spaces and _ . : / = + - @ (max 256).</summary>
    private static string TagValue(string text)
    {
        var clean = new string(text.Select(c => char.IsLetterOrDigit(c) || " _.:/=+-@".Contains(c) ? c : '-').ToArray());
        return clean.Length <= 256 ? clean : clean[..256];
    }

    // ------------------------------------------------------------------ shared

    private IAwsSecrets Connect(string? profile, string? region)
    {
        try
        {
            return _connect(profile, region);
        }
        catch (Exception ex) when (ex is AmazonClientException or AmazonServiceException)
        {
            throw Explain(ex, profile);
        }
        catch (ArgumentException ex)
        {
            throw new KeyloException($"AWS: {ex.Message}");
        }
    }

    private static async Task<T> CallAsync<T>(Func<Task<T>> call, string? profile)
    {
        try
        {
            return await call();
        }
        catch (Exception ex) when (ex is AmazonClientException or AmazonServiceException)
        {
            throw Explain(ex, profile);
        }
    }

    /// <summary>An AWS error as a message, with the fix for the usual causes (no credentials, an expired SSO session).</summary>
    internal static KeyloException Explain(Exception ex, string? profile)
    {
        var message = ex.Message.Split('\n')[0].Trim();
        var login = profile is null ? "aws sso login" : $"aws sso login --profile {profile}";
        if (message.Contains("RegionEndpoint", StringComparison.Ordinal))
            return new KeyloException("AWS: no region chosen. Pick one, or set it in Settings → Vault providers (keylo provider set aws region us-east-1).");
        if (ex is AmazonServiceException { ErrorCode: "AccessDeniedException" })
            return new KeyloException($"AWS denied access: {message}");
        if (ex is AmazonServiceException { ErrorCode: "UnrecognizedClientException" or "InvalidClientTokenId" or "ExpiredTokenException" or "InvalidSignatureException" })
            return new KeyloException($"AWS: {message} Check your credentials, or sign in again (for SSO: {login}).");
        if (ex is not AmazonServiceException &&
            (message.Contains("credential", StringComparison.OrdinalIgnoreCase) || message.Contains("token", StringComparison.OrdinalIgnoreCase) ||
             message.Contains("SSO", StringComparison.Ordinal)))
            return new KeyloException($"AWS: {message} Sign in (for SSO: {login}) or choose a profile in Settings → Vault providers.");
        return new KeyloException($"AWS: {message}");
    }

    private static string? Setting(IReadOnlyDictionary<string, string> settings, string key) =>
        settings.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
}
