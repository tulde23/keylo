using System.Text;
using Keylo.Core.Providers;

namespace Keylo.Core;

/// <summary>
/// Secrets that point at an item in another vault (1Password, or a plugin's). Keylo stores only the
/// reference (as metadata, type "link"); values are read from the vault whenever the secret is used,
/// so they're never copied and changes there apply at once. Access keys, approvals, redaction and
/// the audit log apply exactly as for Keylo's own secrets.
/// </summary>
public static class LinkedSecrets
{
    public const string TypeId = "link";

    private const string ProviderKey = "link_provider", ItemKey = "link_item", VaultKey = "link_vault", LocationKey = "link_location",
        TitleKey = "link_title", WhereKey = "link_where", FieldsKey = "link_fields", OnlyFieldKey = "link_field";

    /// <param name="Where">Where the item lives, for display ("Private · my.1password.com").</param>
    /// <param name="OnlyField">When set, the link exposes just this field of the item.</param>
    public sealed record Link(LinkTarget Target, string Title, string? Where, IReadOnlyList<LinkedField> Fields, string? OnlyField = null)
    {
        public IReadOnlyList<LinkedField> VisibleFields => OnlyField is null ? Fields : Fields.Where(f => f.Id == OnlyField).ToList();

        /// <summary>The field used when no field is named: the chosen one, else the first secret field.</summary>
        public string? MainField => OnlyField ?? VisibleFields.FirstOrDefault(f => f.Secret)?.Id ?? VisibleFields.FirstOrDefault()?.Id;
    }

    public static bool IsLinked(SecretInfo info) => info.Type == TypeId;

    /// <summary>
    /// The suggested category for an item: "1Password · Private", plus the account when items come
    /// from several (vaults of the same name in two accounts shouldn't merge).
    /// </summary>
    public static string DefaultCategory(string providerName, LinkedItemSummary item, bool severalLocations)
    {
        var category = item.VaultName is { Length: > 0 } vault ? $"{providerName} · {vault}" : providerName;
        if (severalLocations && item.Location is { Length: > 0 } location) category += $" ({ShortLocation(location)})";
        return category.Length <= SecretStore.MaxCategoryLength ? category : category[..SecretStore.MaxCategoryLength];
    }

    /// <summary>"my.1password.com" → "personal", "acme.1password.com" → "acme"; anything else as is.</summary>
    private static string ShortLocation(string location)
    {
        var host = location.Split('.')[0];
        return host.Equals("my", StringComparison.OrdinalIgnoreCase) ? "personal" : host;
    }

    public static Link? Read(SecretInfo info)
    {
        if (!IsLinked(info) || info.Fields is not { } f) return null;
        if (!f.TryGetValue(ProviderKey, out var provider) || !f.TryGetValue(ItemKey, out var item)) return null;

        return new Link(
            new LinkTarget(provider, item, f.GetValueOrDefault(VaultKey), f.GetValueOrDefault(LocationKey)),
            f.GetValueOrDefault(TitleKey) ?? info.Name,
            f.GetValueOrDefault(WhereKey),
            DecodeFields(f.GetValueOrDefault(FieldsKey)),
            f.GetValueOrDefault(OnlyFieldKey));
    }

    /// <summary>A draft that stores <paramref name="link"/> (no value: the stored value is an empty object).</summary>
    public static SecretDraft Draft(string name, Link link, string? category = null, string? notes = null, string? icon = null, string? color = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [ProviderKey] = link.Target.Provider,
            [ItemKey] = link.Target.ItemId,
            [TitleKey] = Fit(link.Title),
            [FieldsKey] = EncodeFields(link.Fields),
        };
        if (link.Target.VaultId is { Length: > 0 } vault) fields[VaultKey] = vault;
        if (link.Target.Location is { Length: > 0 } location) fields[LocationKey] = location;
        if (link.Where is { Length: > 0 } where) fields[WhereKey] = Fit(where);
        if (link.OnlyField is { Length: > 0 } only) fields[OnlyFieldKey] = only;

        return new SecretDraft(name, "{}"u8.ToArray(), category, null, notes, icon, color, TypeId, fields);
    }

    /// <summary>A type describing the link's fields, so linked secrets show and behave like typed ones.</summary>
    public static SecretTypeDefinition AsType(Link link, string providerName) => new()
    {
        Id = TypeId,
        Name = $"Linked · {providerName}",
        Icon = "Link24",
        IsBuiltIn = true,
        Fields = link.VisibleFields.Select(f => new FieldDefinition
        {
            Id = f.Id,
            Label = f.Label,
            Kind = f.Secret ? FieldKind.Password : FieldKind.Text,
        }).ToList(),
    };

    /// <summary>The linked item's current values (only the chosen field, for a single-field link), read from its vault.</summary>
    public static async Task<Dictionary<string, string>> ResolveAsync(SecretInfo info, ProviderRegistry registry, KeyloConfig config, CancellationToken cancellationToken = default)
    {
        var link = Read(info) ?? throw new KeyloException($"'{info.Name}' isn't a valid link.");
        var provider = registry.FindLinked(link.Target.Provider)
                       ?? throw new KeyloException($"'{info.Name}' is linked to '{link.Target.Provider}', which isn't installed.");
        var settings = config.Providers.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>();

        var values = await provider.ResolveAsync(link.Target, settings, cancellationToken);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in link.VisibleFields)
            if (values.TryGetValue(field.Id, out var value) && value.Length > 0) result[field.Id] = value;

        // Fields added to the item after linking still come through (unless the link is to one field).
        if (link.OnlyField is null)
            foreach (var (id, value) in values)
                if (!result.ContainsKey(id) && value.Length > 0) result[id] = value;
        return result;
    }

    // Fields are stored as "id|label|1;id|label|0" (1 = secret), trimmed to fit a 256-byte attribute.
    private static string EncodeFields(IEnumerable<LinkedField> fields)
    {
        var text = new StringBuilder();
        foreach (var f in fields)
        {
            var part = $"{Clean(f.Id)}|{Clean(f.Label)}|{(f.Secret ? 1 : 0)}";
            if (Encoding.UTF8.GetByteCount(text.ToString() + ";" + part) > 250) break;
            if (text.Length > 0) text.Append(';');
            text.Append(part);
        }
        return text.ToString();
    }

    private static List<LinkedField> DecodeFields(string? text) =>
        (text ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('|'))
            .Where(p => p.Length == 3)
            .Select(p => new LinkedField(p[0], p[1], p[2] == "1" || !LooksPublic(p[0])))
            .ToList();

    /// <summary>
    /// Fields of linked items count as secret unless they're plainly identity or address fields:
    /// vaults often keep keys in ordinary text fields, and a wrongly visible key is worse than a
    /// masked hostname.
    /// </summary>
    public static bool LooksPublic(string fieldId) =>
        fieldId is "username" or "website" ||
        fieldId.StartsWith("website_", StringComparison.Ordinal) ||
        fieldId.Contains("email", StringComparison.Ordinal) ||
        fieldId.Contains("url", StringComparison.Ordinal);

    private static string Clean(string s) => s.Replace("|", "/").Replace(";", ",");

    private static string Fit(string s)
    {
        while (Encoding.UTF8.GetByteCount(s) > 250) s = s[..^1];
        return s;
    }
}
