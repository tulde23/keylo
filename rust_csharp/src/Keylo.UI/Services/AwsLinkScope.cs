using Keylo.Core;
using Keylo.Core.Providers;

namespace Keylo.App.Services;

/// <summary>
/// What to search AWS Secrets Manager with: an environment (dev, uat, prod…, which links per
/// environment), or a profile (<see cref="Name"/> null means the default credentials).
/// </summary>
public sealed record AwsProfileChoice(string? Name, string Label, string? Region, string? Environment = null)
{
    public override string ToString() => Label;
}

/// <summary>The profile and region pickers the Link dialog shows for AWS Secrets Manager.</summary>
public static class AwsLinkScope
{
    public const string ProviderId = "aws";

    /// <summary>
    /// The environments ("dev environment · acme-dev · eu-west-2"), then "Default credentials", then
    /// every profile in ~/.aws ("work · sso · eu-west-2").
    /// </summary>
    public static IReadOnlyList<AwsProfileChoice> Profiles(IReadOnlyDictionary<string, string>? settings = null)
    {
        var choices = new List<AwsProfileChoice>();
        foreach (var e in VaultEnvironments.Read(settings ?? new Dictionary<string, string>()))
            choices.Add(new AwsProfileChoice(e.Profile, string.Join(" · ", new[] { $"{e.Name} environment", e.Profile, e.Region }.Where(s => !string.IsNullOrEmpty(s))),
                e.Region, e.Name));
        choices.Add(new(null, "Default credentials", AwsSetup.EnvironmentRegion));
        try
        {
            choices.AddRange(AwsSetup.Profiles().Select(p =>
                new AwsProfileChoice(p.Name, string.Join(" · ", new[] { p.Name, p.SignIn, p.Region }.Where(s => !string.IsNullOrEmpty(s))), p.Region)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or FormatException)
        {
            // A missing or unreadable ~/.aws leaves just the default credentials.
        }
        return choices;
    }

    public static IReadOnlyList<string> Regions() => AwsSetup.Regions();

    /// <summary>The default environment, else the configured profile (Settings → Vault providers), else the default credentials.</summary>
    public static AwsProfileChoice Initial(IReadOnlyList<AwsProfileChoice> choices, IReadOnlyDictionary<string, string> settings)
    {
        if (VaultEnvironments.Default(settings) is { } env && choices.FirstOrDefault(c => c.Environment == env) is { } environment) return environment;
        return settings.GetValueOrDefault("profile") is { Length: > 0 } profile && choices.FirstOrDefault(c => c.Environment is null && c.Name == profile) is { } match
            ? match
            : choices.First(c => c.Environment is null);
    }

    /// <summary>The region to start with: an environment's own; else the configured one, the profile's, or AWS_REGION.</summary>
    public static string? InitialRegion(AwsProfileChoice profile, IReadOnlyDictionary<string, string> settings) =>
        profile.Environment is not null ? profile.Region
        : settings.GetValueOrDefault("region") is { Length: > 0 } region ? region : profile.Region ?? AwsSetup.EnvironmentRegion;

    /// <summary>
    /// The provider settings with the picked profile and region in place of the configured ones, or
    /// with the picked environment (whose own profile and region apply).
    /// </summary>
    public static IReadOnlyDictionary<string, string> Apply(IReadOnlyDictionary<string, string> settings, AwsProfileChoice? profile, string? region)
    {
        var result = new Dictionary<string, string>(settings, StringComparer.OrdinalIgnoreCase);
        if (profile?.Environment is { } env)
        {
            result[LinkedSecrets.EnvironmentSetting] = env;
            return result;
        }
        result.Remove("profile");
        result.Remove("region");
        if (profile?.Name is { } name) result["profile"] = name;
        if (!string.IsNullOrEmpty(region)) result["region"] = region;
        return result;
    }
}
