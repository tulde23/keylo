using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Keylo.Core.Providers;

/// <summary>
/// Pushes secrets to 1Password through the 1Password CLI ("op"). Items are created from a JSON
/// template piped on stdin, so values never appear on a command line. A secret with a username
/// becomes a Login item, otherwise a Password item; it is tagged "keylo" plus its category.
/// </summary>
public sealed class OnePasswordProvider : IVaultProvider
{
    public string Id => "1password";

    public string DisplayName => "1Password";

    public IReadOnlyDictionary<string, string> SettingDescriptions { get; } = new Dictionary<string, string>
    {
        ["vault"] = "Vault to push into (required), e.g. Private",
        ["account"] = "Account shorthand or sign-in address, when signed in to more than one (optional)",
    };

    public async Task<ProviderStatus> GetStatusAsync(IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default)
    {
        if (!settings.TryGetValue("vault", out var vault) || string.IsNullOrWhiteSpace(vault))
            return new ProviderStatus(false, "Set a vault: keylo provider set 1password vault <name>");

        var (code, output, error) = await RunOpAsync(["vault", "get", vault, "--format", "json", .. AccountArgs(settings)], null, cancellationToken);
        if (code is null)
            return new ProviderStatus(false, "1Password CLI (op) isn't installed: winget install AgileBits.1Password.CLI");
        if (code != 0)
            return new ProviderStatus(false, FirstLine(error) ?? "op couldn't open the vault. Is the 1Password app unlocked with CLI integration on?");

        var name = JsonNode.Parse(output)?["name"]?.GetValue<string>() ?? vault;
        return new ProviderStatus(true, $"Ready (vault '{name}')");
    }

    public async Task<PushResult> PushAsync(Secret secret, IReadOnlyDictionary<string, string> settings, CancellationToken cancellationToken = default)
    {
        var info = secret.Info;
        if (!settings.TryGetValue("vault", out var vault) || string.IsNullOrWhiteSpace(vault))
            return new PushResult(info.Name, false, "No 1Password vault configured.");

        // Typed secrets: the main field is the password; the others go along as labelled fields.
        var type = new SecretTypeCatalog().Find(info.Type);
        Dictionary<string, string>? typed = type is null ? null : TypedSecrets.ReadFields(type, info, secret.Value);
        var value = type is null ? TypedSecrets.DecodeText(secret.Value) : typed!.GetValueOrDefault(type.Primary?.Id ?? "", "");
        if (value is null) return new PushResult(info.Name, false, "Binary values can't be stored in a 1Password field.");

        var item = BuildItem(info, value);
        if (type is not null && item["fields"] is JsonArray itemFields)
        {
            foreach (var field in type.Fields.Where(f => f != type.Primary && f.Kind != FieldKind.Username))
            {
                if (!typed!.TryGetValue(field.Id, out var text)) continue;
                itemFields.Add(new JsonObject
                {
                    ["id"] = field.Id,
                    ["type"] = field.IsSecret ? "CONCEALED" : field.Kind == FieldKind.Url ? "URL" : "STRING",
                    ["label"] = field.Label,
                    ["value"] = text,
                });
            }
        }
        var account = AccountArgs(settings);

        var existingId = await FindItemIdAsync(info.Name, vault, account, cancellationToken);
        var args = existingId is null
            ? new[] { "item", "create", "--vault", vault, "--format", "json" }.Concat(account).Append("-")
            : new[] { "item", "edit", existingId, "--vault", vault, "--format", "json" }.Concat(account).Append("-");

        var (code, output, error) = await RunOpAsync(args.ToArray(), item.ToJsonString(), cancellationToken);
        if (code is null) return new PushResult(info.Name, false, "1Password CLI (op) isn't installed.");
        if (code != 0) return new PushResult(info.Name, false, FirstLine(error) ?? $"op exited with {code}.");

        var id = JsonNode.Parse(output)?["id"]?.GetValue<string>();
        return new PushResult(info.Name, true, existingId is null ? $"Created in '{vault}'" : $"Updated in '{vault}'", id);
    }

    private static JsonObject BuildItem(SecretInfo info, string value)
    {
        var fields = new JsonArray();
        if (info.Username is not null)
            fields.Add(new JsonObject { ["id"] = "username", ["type"] = "STRING", ["purpose"] = "USERNAME", ["label"] = "username", ["value"] = info.Username });
        fields.Add(new JsonObject { ["id"] = "password", ["type"] = "CONCEALED", ["purpose"] = "PASSWORD", ["label"] = "password", ["value"] = value });
        fields.Add(new JsonObject { ["id"] = "notesPlain", ["type"] = "STRING", ["purpose"] = "NOTES", ["label"] = "notesPlain", ["value"] = info.Notes ?? "" });

        var tags = new JsonArray("keylo");
        if (info.Category is not null) tags.Add(info.Category);

        return new JsonObject
        {
            ["title"] = info.Name,
            ["category"] = info.Username is null ? "PASSWORD" : "LOGIN",
            ["tags"] = tags,
            ["fields"] = fields,
        };
    }

    /// <summary>The id of a Keylo-tagged item with this title, if one was pushed before.</summary>
    private static async Task<string?> FindItemIdAsync(string title, string vault, string[] account, CancellationToken cancellationToken)
    {
        var (code, output, _) = await RunOpAsync(["item", "list", "--vault", vault, "--tags", "keylo", "--format", "json", .. account], null, cancellationToken);
        if (code != 0) return null;

        return JsonNode.Parse(output)?.AsArray()
            .FirstOrDefault(i => string.Equals(i?["title"]?.GetValue<string>(), title, StringComparison.Ordinal))?["id"]?.GetValue<string>();
    }

    private static string[] AccountArgs(IReadOnlyDictionary<string, string> settings) =>
        settings.TryGetValue("account", out var account) && !string.IsNullOrWhiteSpace(account) ? ["--account", account] : [];

    private static string? FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();

    /// <returns>Exit code (null if op couldn't be started), stdout, stderr.</returns>
    private static async Task<(int? Code, string Output, string Error)> RunOpAsync(string[] args, string? stdin, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo("op")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        Process process;
        try
        {
            process = Process.Start(psi)!;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (null, "", "");
        }

        using (process)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(60));

            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            if (stdin is not null) await process.StandardInput.WriteAsync(stdin.AsMemory(), timeout.Token);
            process.StandardInput.Close();

            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                throw;
            }

            return (process.ExitCode, await outputTask, await errorTask);
        }
    }
}
