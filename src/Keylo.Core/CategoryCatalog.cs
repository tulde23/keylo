using System.Text.Json;

namespace Keylo.Core;

/// <summary>A category's look in the app. Both fields are optional.</summary>
public sealed class CategoryStyle
{
    public string? Icon { get; set; }
    public string? Color { get; set; }
}

public sealed record CategorySummary(string Name, int Count, string? Icon, string? Color);

/// <summary>
/// Categories live on the secrets themselves (a credential attribute). This catalog adds what a
/// secret can't hold: categories with no secrets yet, and each category's icon and colour. It's
/// display metadata, not a security setting, so it's a plain file (categories.json) that changing
/// doesn't require Windows Hello.
/// </summary>
public sealed class CategoryCatalog
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private readonly string _path;
    private readonly SecretStore _store;
    private Dictionary<string, CategoryStyle> _entries = new(StringComparer.OrdinalIgnoreCase);

    public CategoryCatalog(SecretStore store, string? dataDirectory = null)
    {
        _store = store;
        _path = Path.Combine(dataDirectory ?? KeyloPaths.DefaultDataDirectory, "categories.json");
        Load();
    }

    /// <summary>Every category: those in use plus empty ones created here, with counts and styles.</summary>
    public IReadOnlyList<CategorySummary> All(IReadOnlyList<SecretInfo>? secrets = null)
    {
        secrets ??= _store.List();
        var counts = secrets.Where(s => s.Category is not null)
            .GroupBy(s => s.Category!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        return counts.Keys.Union(_entries.Keys, StringComparer.OrdinalIgnoreCase)
            .Select(name =>
            {
                _entries.TryGetValue(name, out var style);
                return new CategorySummary(name, counts.GetValueOrDefault(name), style?.Icon, style?.Color);
            })
            .OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public CategoryStyle? StyleOf(string? category) =>
        category is not null && _entries.TryGetValue(category, out var style) ? style : null;

    /// <summary>
    /// Adds a category from a backup: created if missing; its style is applied when it has none yet,
    /// or always when <paramref name="overwriteStyle"/> is set. Returns whether the category is new.
    /// </summary>
    public bool Merge(string name, CategoryStyle? style, bool overwriteStyle)
    {
        name = Validate(name);
        var isNew = !_entries.TryGetValue(name, out var existing);
        if (isNew) _entries[name] = existing = new CategoryStyle();

        if (style is not null && (overwriteStyle || (existing!.Icon is null && existing.Color is null)))
        {
            existing!.Icon = SecretStore.NormalizeIcon(style.Icon);
            existing.Color = SecretStore.NormalizeColor(style.Color);
        }

        Save();
        return isNew;
    }

    /// <summary>Adds an empty category (no-op if it exists).</summary>
    public void Create(string name, string? icon = null, string? color = null)
    {
        name = Validate(name);
        if (!_entries.ContainsKey(name)) _entries[name] = new CategoryStyle();
        SetStyle(name, icon, color);
    }

    public void SetStyle(string name, string? icon, string? color)
    {
        name = Validate(name);
        if (!_entries.TryGetValue(name, out var style)) _entries[name] = style = new CategoryStyle();
        style.Icon = SecretStore.NormalizeIcon(icon);
        style.Color = SecretStore.NormalizeColor(color);
        Save();
    }

    /// <summary>
    /// Renames a category on every secret in it. Renaming onto an existing category merges the two
    /// (the target keeps its own style). Returns the number of secrets moved.
    /// </summary>
    public int Rename(string from, string to)
    {
        to = Validate(to);
        var moved = _store.RecategorizeAll(from, to);

        if (_entries.Remove(from, out var style) && !_entries.ContainsKey(to))
            _entries[to] = style;
        else if (!_entries.ContainsKey(to))
            _entries[to] = new CategoryStyle();

        Save();
        return moved;
    }

    /// <summary>
    /// Removes a category. Its secrets move to <paramref name="moveTo"/> (null: uncategorized), or
    /// are deleted when <paramref name="deleteSecrets"/> is set. Returns the number of secrets affected.
    /// </summary>
    public int Delete(string name, string? moveTo = null, bool deleteSecrets = false)
    {
        var affected = 0;
        if (deleteSecrets)
        {
            foreach (var secret in _store.List().Where(s => string.Equals(s.Category, name, StringComparison.OrdinalIgnoreCase)))
                if (_store.Delete(secret.Name)) affected++;
        }
        else
        {
            if (moveTo is not null)
            {
                moveTo = Validate(moveTo);
                if (!_entries.ContainsKey(moveTo)) _entries[moveTo] = new CategoryStyle();
            }
            affected = _store.RecategorizeAll(name, moveTo);
        }

        _entries.Remove(name);
        Save();
        return affected;
    }

    private static string Validate(string name)
    {
        name = name.Trim();
        if (name.Length == 0) throw new KeyloException("Category name is required.");
        if (name.Length > SecretStore.MaxCategoryLength) throw new KeyloException($"Category is longer than {SecretStore.MaxCategoryLength} characters.");
        if (name.Any(char.IsControl)) throw new KeyloException("Category cannot contain control characters.");
        return name;
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        try
        {
            var loaded = JsonSerializer.Deserialize<Dictionary<string, CategoryStyle>>(File.ReadAllText(_path), Json);
            if (loaded is not null) _entries = new Dictionary<string, CategoryStyle>(loaded, StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            // A damaged file only loses icons and empty categories; secrets keep their categories.
        }
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(_entries, Json));
    }
}
