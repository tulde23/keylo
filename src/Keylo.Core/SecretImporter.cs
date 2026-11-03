namespace Keylo.Core;

public sealed record ImportedSecret(string Name, string SourcePath, string? Category);

public sealed record SkippedFile(string SourcePath, string Reason);

public sealed record ImportResult(IReadOnlyList<ImportedSecret> Imported, IReadOnlyList<SkippedFile> Skipped);

/// <summary>Imports files (e.g. the contents of a .secrets folder) as secrets, one secret per file.</summary>
public static class SecretImporter
{
    /// <summary>
    /// Plans and imports. The secret name is the file name without its extension (the full file
    /// name when two files would collide). Every file gets <paramref name="category"/> when it's
    /// given; otherwise files from a directory take their top-level subfolder as the category when
    /// <paramref name="subfolderCategories"/> is set, and none when it isn't.
    /// </summary>
    public static ImportResult Import(
        SecretStore store,
        IEnumerable<string> paths,
        string? category = null,
        bool overwrite = false,
        bool subfolderCategories = true)
    {
        var planned = Plan(paths, category, subfolderCategories);
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

                store.Save(
                    new SecretDraft(item.Name, value, item.Category ?? existing?.Category, existing?.Username,
                        existing?.Notes ?? $"Imported from {Path.GetFileName(item.SourcePath)}", existing?.Icon, existing?.Color),
                    originalName: existing?.Name);
                imported.Add(item);
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
