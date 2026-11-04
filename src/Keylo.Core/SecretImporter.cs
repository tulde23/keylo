namespace Keylo.Core;

public sealed record ImportedSecret(string Name, string SourcePath, string? Category, string? Type = null);

public sealed record SkippedFile(string SourcePath, string Reason);

public sealed record ImportResult(IReadOnlyList<ImportedSecret> Imported, IReadOnlyList<SkippedFile> Skipped);

/// <summary>Imports files (e.g. the contents of a .secrets folder) as secrets, one secret per file.</summary>
public static class SecretImporter
{
    /// <summary>
    /// Plans and imports. The secret name is the file name without its extension (the full file
    /// name when two files would collide). Every file gets <paramref name="category"/> when it's
    /// given; otherwise files from a directory take their top-level subfolder as the category when
    /// <paramref name="subfolderCategories"/> is set, and none when it isn't. <paramref name="names"/>
    /// overrides the name of individual files, keyed by their full path. <paramref name="types"/> sets
    /// a file's type ("" for plain); files it doesn't list get a type guessed from their name and
    /// content (<see cref="SecretTypeInference"/>) when <paramref name="inferTypes"/> is set.
    /// </summary>
    public static ImportResult Import(
        SecretStore store,
        IEnumerable<string> paths,
        string? category = null,
        bool overwrite = false,
        bool subfolderCategories = true,
        IReadOnlyDictionary<string, string>? names = null,
        IReadOnlyDictionary<string, string>? types = null,
        bool inferTypes = true)
    {
        var catalog = new SecretTypeCatalog();
        var planned = Plan(paths, category, subfolderCategories);
        if (names is { Count: > 0 })
            planned = (planned.Items.Select(i => names.TryGetValue(i.SourcePath, out var name) && !string.IsNullOrWhiteSpace(name) ? i with { Name = name.Trim() } : i).ToList(),
                planned.Skipped);
        var imported = new List<ImportedSecret>();
        var skipped = new List<SkippedFile>(planned.Skipped);

        foreach (var item in planned.Items)
        {
            try
            {
                var value = File.ReadAllBytes(item.SourcePath);
                var existing = store.Find(item.Name);
                if (existing is not null && !overwrite)
                {
                    skipped.Add(new SkippedFile(item.SourcePath, $"'{item.Name}' already exists"));
                    continue;
                }

                var notes = existing?.Notes ?? $"Imported from {Path.GetFileName(item.SourcePath)}";
                var inferred = SecretTypeInference.Infer(item.SourcePath, value);
                var typeId = types?.GetValueOrDefault(item.SourcePath) ?? (inferTypes ? inferred?.TypeId : null);
                var type = string.IsNullOrEmpty(typeId) ? null : catalog.Find(typeId);
                var text = type is null ? null : TypedSecrets.DecodeText(value);

                SecretDraft draft;
                if (type is not null && text is not null)
                {
                    // The guessed split when the guess was kept; otherwise the whole value goes in the main field.
                    var fields = inferred?.TypeId == type.Id ? inferred.Fields
                        : new Dictionary<string, string?> { [type.Primary?.Id ?? type.Fields[0].Id] = text.Trim() };
                    draft = TypedSecrets.Draft(type, item.Name, fields, item.Category ?? existing?.Category, notes, existing?.Icon, existing?.Color);
                }
                else
                {
                    type = null;
                    draft = new SecretDraft(item.Name, value, item.Category ?? existing?.Category, existing?.Username, notes, existing?.Icon, existing?.Color);
                }

                store.Save(draft, originalName: existing?.Name);
                imported.Add(item with { Type = type?.Id });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or KeyloException)
            {
                skipped.Add(new SkippedFile(item.SourcePath, ex.Message));
            }
        }

        return new ImportResult(imported, skipped);
    }

    /// <summary>What an import would do, without touching the store (for confirming options first).</summary>
    public static (IReadOnlyList<ImportedSecret> Items, IReadOnlyList<SkippedFile> Skipped) Plan(
        IEnumerable<string> paths, string? category = null, bool subfolderCategories = true)
    {
        var files = new List<(string Path, string? Category)>();
        var skipped = new List<SkippedFile>();

        foreach (var input in paths)
        {
            var full = Path.GetFullPath(input);
            if (Directory.Exists(full))
            {
                foreach (var file in Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories).Order())
                {
                    var relative = Path.GetRelativePath(full, file);
                    var parts = relative.Split(Path.DirectorySeparatorChar);
                    files.Add((file, category ?? (subfolderCategories && parts.Length > 1 ? parts[0] : null)));
                }
            }
            else if (File.Exists(full))
            {
                files.Add((full, category));
            }
            else
            {
                skipped.Add(new SkippedFile(input, "Not found"));
            }
        }

        var items = new List<ImportedSecret>();
        var stems = files
            .GroupBy(f => Path.GetFileNameWithoutExtension(f.Path), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (path, fileCategory) in files)
        {
            var info = new FileInfo(path);
            if (info.Length > SecretStore.MaxValueBytes)
            {
                skipped.Add(new SkippedFile(path, "Larger than 4 MB"));
                continue;
            }

            var stem = Path.GetFileNameWithoutExtension(path);
            var name = stems[stem] > 1 || stem.Length == 0 ? Path.GetFileName(path) : stem;

            if (!SecretStore.IsValidName(name) || !used.Add(name))
            {
                skipped.Add(new SkippedFile(path, $"Can't derive a unique, valid name ('{name}')"));
                continue;
            }

            items.Add(new ImportedSecret(SecretStore.NormalizeName(name), path, fileCategory));
        }

        return (items, skipped);
    }
}
