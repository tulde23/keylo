using System.Text;
using System.Text.Json;

namespace Keylo.Core.Security;

public enum ApprovalResult
{
    Denied = 10,
    AllowedOnce = 11,

    /// <summary>Allowed, and the secrets were added to the requesting access key's scope.</summary>
    AllowedAlways = 12,
}

/// <summary>
/// A request from an agent (via <c>keylo mcp</c>) for secrets its access key doesn't cover. The
/// Keylo app shows it (<c>keylow --approve</c>), verifies with Windows Hello, and answers with an
/// <see cref="ApprovalResult"/> exit code. The reason and command come from the agent: untrusted text.
/// <see cref="GrantOnly"/> requests (request_access) only offer adding the secrets to the key.
/// </summary>
public sealed record ApprovalRequest(
    SecretOperation Operation,
    IReadOnlyList<string> Secrets,
    string? KeyId,
    string? KeyName,
    string? Reason,
    string? Command,
    bool CanAlwaysAllow,
    bool GrantOnly = false)
{
    public const string Argument = "--approve";
    private const int MaxText = 2000;

    public string Encode() => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(this with
    {
        Reason = Clip(Reason),
        Command = Clip(Command),
    }));

    public static ApprovalRequest? Decode(string encoded)
    {
        try
        {
            return JsonSerializer.Deserialize<ApprovalRequest>(Encoding.UTF8.GetString(Convert.FromBase64String(encoded)));
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return null;
        }
    }

    private static string? Clip(string? text) => text is { Length: > MaxText } ? text[..MaxText] + "…" : text;
}
