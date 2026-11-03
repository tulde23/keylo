namespace Keylo.Core;

public static class SecretSearch
{
    /// <summary>
    /// Case-insensitive match of every whitespace-separated term against the name, category,
    /// username or notes. A term like "cat:cloud" only matches the category. Never looks at values.
    /// </summary>
    public static bool Matches(SecretInfo secret, string? query)
    {
        if (string.IsNullOrWhiteSpace(query)) return true;

        foreach (var term in query.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (term.StartsWith("cat:", StringComparison.OrdinalIgnoreCase))
            {
                if (!Contains(secret.Category, term[4..])) return false;
                continue;
            }

            if (!Contains(secret.Name, term) && !Contains(secret.Category, term) &&
                !Contains(secret.Username, term) && !Contains(secret.Notes, term))
                return false;
        }

        return true;
    }

    public static IEnumerable<SecretInfo> Filter(IEnumerable<SecretInfo> secrets, string? query, string? category = null) =>
        secrets.Where(s =>
            (category is null || string.Equals(s.Category, category, StringComparison.OrdinalIgnoreCase)) &&
            Matches(s, query));

    private static bool Contains(string? field, string term) =>
        field is not null && field.Contains(term, StringComparison.OrdinalIgnoreCase);
}
