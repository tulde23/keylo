using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Keylo.Core;
using Keylo.Core.Providers;
using Keylo.Core.Security;

namespace Keylo.Cli;

internal static class Program
{
    private const string Usage = """
        keylo - local secrets in Windows Credential Manager

        keylo                                   Open the Keylo app
        keylo list [search...] [--category C]   List secrets (search matches name, category, username, notes)
        keylo categories                        List categories with counts
        keylo get NAME [--clip] [--out FILE] [--field value|username]
                                                Print a value (or copy it; the clipboard clears itself)
        keylo set NAME [--category C] [--username U] [--notes N] [--file FILE]
                                                Add or update (value is prompted, piped, or read from FILE)
        keylo edit NAME [--rename NEW] [--category C] [--username U] [--notes N]
                                                Change details without touching the value ("" clears a field)
        keylo rm NAME [--yes]                   Delete a secret
        keylo import PATH... [--category C | --flat] [--overwrite] [--delete-originals]
                                                One secret per file. Subfolders become categories,
                                                unless --category puts everything in C or --flat sets none
        keylo run --env VAR=NAME [...] -- CMD [ARGS]
                                                Run CMD with secrets as environment variables
        keylo push PROVIDER [NAME...] [--category C] [--all]
                                                Push secrets to another vault (e.g. 1password)
        keylo provider list | status ID | set ID KEY VALUE
        keylo backup FILE [--force] [--password-stdin]
                                                Encrypted, password-protected backup of everything
        keylo restore FILE [--overwrite] [--dry-run] [--password-stdin]
                                                Restore a backup (existing secrets are skipped unless --overwrite)
        keylo trust                             Show trust groups (manage them in the app)
        keylo unlock | lock | status
        keylo config [hello session|always|never | session-minutes N | clipboard-seconds N]
        """;

    private static readonly string[] Flags = ["clip", "yes", "overwrite", "delete-originals", "flat", "all", "json", "force", "dry-run", "password-stdin", "help"];

    private static async Task<int> Main(string[] argv)
    {
        Console.OutputEncoding = new UTF8Encoding(false);

        try
        {
            if (argv.Length == 0) return LaunchApp();

            var command = argv[0].ToLowerInvariant();
            var args = new Args(argv.Skip(1), Flags);
            if (args.Flag("help") || command is "help" or "-h" or "--help" or "/?")
            {
                Console.WriteLine(Usage);
                return 0;
            }

            var context = new Context();
            var exit = command switch
            {
                "ui" or "app" => LaunchApp(),
                "list" or "ls" or "search" => await ListAsync(context, args),
                "categories" or "cats" => await CategoriesAsync(context, args),
                "get" => await GetAsync(context, args),
                "set" or "add" => await SetAsync(context, args),
                "edit" => await EditAsync(context, args),
                "rm" or "delete" or "remove" => await RemoveAsync(context, args),
                "import" => await ImportAsync(context, args),
                "run" => await RunAsync(context, args),
                "push" => await PushAsync(context, args),
                "provider" or "providers" => await ProviderAsync(context, args),
                "trust" => Trust(context, args),
                "backup" or "export" => await BackupAsync(context, args),
                "restore" => await RestoreAsync(context, args),
                "unlock" => await UnlockAsync(context, args),
                "lock" => Lock(context, args),
                "status" => Status(context, args),
                "config" => await ConfigAsync(context, args),
                "__clip-clear" => ClipClear(args),
                _ => throw new UsageException($"Unknown command '{argv[0]}'. Run 'keylo help'."),
            };
            return exit;
        }
        catch (UsageException ex)
        {
            Terminal.Info($"keylo: {ex.Message}");
            return 2;
        }
        catch (KeyloException ex)
        {
            Terminal.Info($"keylo: {ex.Message}");
            return 1;
        }
    }

    private sealed class Context
    {
        public KeyloConfig Config { get; } = KeyloConfig.Load();
        public SecretStore Store { get; } = new();
        public AccessGate Gate { get; }

        private IReadOnlyList<AncestorProcess>? _ancestry;

        public Context() => Gate = new AccessGate(Config, new WindowsHelloVerifier());

        public IReadOnlyList<AncestorProcess> Ancestry => _ancestry ??= ProcessAncestry.Current();

        /// <summary>For commands that change secrets or settings: trust groups never apply.</summary>
        public Task BrowseAsync() => Gate.EnsureAsync(IntPtr.Zero, "Unlock Keylo", valueAccess: false);

        /// <summary>
        /// Lists what this caller may see: everything once unlocked; otherwise, for a trusted caller,
        /// only the secrets its groups cover (without prompting); otherwise prompts.
        /// </summary>
        public async Task<IReadOnlyList<SecretInfo>> VisibleSecretsAsync()
        {
            if (!Gate.IsUnlocked && TrustPolicy.GroupsFor(Config, Ancestry) is { Count: > 0 } groups)
                return Store.List().Where(s => groups.Any(g => g.Covers(s))).ToList();

            await BrowseAsync();
            return Store.List();
        }

        /// <summary>Allows a value operation via a trust group (audited) or Windows Hello.</summary>
        public async Task AuthorizeAsync(SecretOperation operation, IReadOnlyCollection<SecretInfo> secrets, string what)
        {
            if (TrustPolicy.Find(Config, operation, secrets, Ancestry) is { } decision)
            {
                AuditLog.Write(operation.ToString().ToLowerInvariant(), secrets.Select(s => s.Name), decision, Ancestry);
                return;
            }

            await Gate.EnsureAsync(IntPtr.Zero, $"Keylo: {what}", valueAccess: true);
        }

        /// <summary>Settings and pushes always need Windows Hello (or hello = never).</summary>
        public Task ValueAsync(string what) => Gate.EnsureAsync(IntPtr.Zero, $"Keylo: {what}", valueAccess: true);
    }

    private static int LaunchApp()
    {
        var app = Path.Combine(AppContext.BaseDirectory, "keylow.exe");
        if (!File.Exists(app)) throw new KeyloException($"The Keylo app (keylow.exe) isn't next to keylo.exe ({AppContext.BaseDirectory}).");
        Process.Start(new ProcessStartInfo(app) { UseShellExecute = true })?.Dispose();
        return 0;
    }

    private static async Task<int> ListAsync(Context c, Args args)
    {
        var category = args.Option("category");
        var json = args.Flag("json");
        args.ThrowOnUnknown();

        var query = string.Join(' ', args.PositionalsFrom(0));
        var secrets = SecretSearch.Filter(await c.VisibleSecretsAsync(), query, category).ToList();

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(secrets, JsonOptions));
            return 0;
        }

        if (secrets.Count == 0)
        {
            Terminal.Info(query.Length > 0 || category is not null ? "No matching secrets." : "No secrets yet. Add one with 'keylo set NAME'.");
            return 0;
        }

        PrintTable(
            ["NAME", "CATEGORY", "USERNAME", "UPDATED"],
            secrets.Select(s => new[] { s.Name, s.Category ?? "", s.Username ?? "", s.UpdatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm") }));
        return 0;
    }

    private static async Task<int> CategoriesAsync(Context c, Args args)
    {
        args.ThrowOnUnknown();

        var groups = (await c.VisibleSecretsAsync())
            .GroupBy(s => s.Category ?? "(none)", StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key == "(none)").ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase);
        PrintTable(["CATEGORY", "SECRETS"], groups.Select(g => new[] { g.Key, g.Count().ToString() }));
        return 0;
    }

    private static async Task<int> GetAsync(Context c, Args args)
    {
        var name = args.Positional(0, "secret name");
        var clip = args.Flag("clip");
        var field = args.Option("field")?.ToLowerInvariant() ?? "value";
        var outFile = args.Option("out");
        args.ThrowOnUnknown(maxPositionals: 1);
        if (field is not ("value" or "username")) throw new UsageException("--field must be value or username.");
        var username = field == "username";

        var info = c.Store.Find(name) ?? throw new SecretNotFoundException(name);
        if (username)
        {
            if (info.Username is null) throw new KeyloException($"'{name}' has no username.");
            await c.AuthorizeAsync(SecretOperation.Get, [info], $"read the username of '{name}'");
            if (clip) return CopyWithTimeout(c, info.Username, "Username");
            Console.WriteLine(info.Username);
            return 0;
        }

        await c.AuthorizeAsync(SecretOperation.Get, [info], $"read '{name}'");
        var secret = c.Store.Get(name);

        if (outFile is not null)
        {
            File.WriteAllBytes(outFile, secret.Value);
            Terminal.Info($"Wrote {secret.Value.Length} bytes to {Path.GetFullPath(outFile)}");
            return 0;
        }

        if (clip)
        {
            var text = DecodeText(secret.Value) ?? throw new KeyloException($"'{name}' is binary; use --out FILE instead.");
            return CopyWithTimeout(c, text, "Value");
        }

        Terminal.WriteRaw(secret.Value);
        return 0;
    }

    private static async Task<int> SetAsync(Context c, Args args)
    {
        var name = SecretStore.NormalizeName(args.Positional(0, "secret name"));
        var category = args.Option("category");
        var username = args.Option("username");
        var notes = args.Option("notes");
        var file = args.Option("file");
        args.ThrowOnUnknown(maxPositionals: 1);
        await c.BrowseAsync();

        var existing = c.Store.Find(name);
        var value = file is not null
            ? File.ReadAllBytes(file)
            : Terminal.ReadSecret(existing is null ? $"Value for '{name}': " : $"New value for '{name}': ", confirm: true);

        c.Store.Save(
            new SecretDraft(name, value, category ?? existing?.Category, username ?? existing?.Username, notes ?? existing?.Notes,
                existing?.Icon, existing?.Color),
            originalName: existing?.Name);

        Terminal.Info(existing is null ? $"Added '{name}'." : $"Updated '{name}'.");
        return 0;
    }

    private static async Task<int> EditAsync(Context c, Args args)
    {
        var name = args.Positional(0, "secret name");
        var rename = args.Option("rename");
        var category = args.Option("category");
        var username = args.Option("username");
        var notes = args.Option("notes");
        args.ThrowOnUnknown(maxPositionals: 1);

        if (rename is null && category is null && username is null && notes is null)
            throw new UsageException("Nothing to change. Use --rename, --category, --username or --notes.");

        await c.BrowseAsync();
        var secret = c.Store.Get(name);
        var info = c.Store.Save(
            new SecretDraft(rename ?? secret.Info.Name, secret.Value, category ?? secret.Info.Category,
                username ?? secret.Info.Username, notes ?? secret.Info.Notes, secret.Info.Icon, secret.Info.Color),
            originalName: secret.Info.Name);

        Terminal.Info($"Updated '{info.Name}'.");
        return 0;
    }

    private static async Task<int> RemoveAsync(Context c, Args args)
    {
        var name = args.Positional(0, "secret name");
        var yes = args.Flag("yes");
        args.ThrowOnUnknown(maxPositionals: 1);
        await c.BrowseAsync();

        if (c.Store.Find(name) is null) throw new SecretNotFoundException(name);
        if (!yes && !Terminal.Confirm($"Delete '{name}'?"))
        {
            Terminal.Info("Not deleted.");
            return 1;
        }

        c.Store.Delete(name);
        Terminal.Info($"Deleted '{name}'.");
        return 0;
    }

    private static async Task<int> ImportAsync(Context c, Args args)
    {
        var paths = args.PositionalsFrom(0);
        var category = args.Option("category");
        var overwrite = args.Flag("overwrite");
        var deleteOriginals = args.Flag("delete-originals");
        var flat = args.Flag("flat");
        args.ThrowOnUnknown();
        if (paths.Count == 0) throw new UsageException("Give one or more files or folders to import.");
        if (flat && category is not null) throw new UsageException("Use --category or --flat, not both.");
        await c.BrowseAsync();

        var result = SecretImporter.Import(c.Store, paths, category, overwrite, subfolderCategories: !flat);

        foreach (var item in result.Imported)
            Terminal.Info($"  + {item.Name}{(item.Category is null ? "" : $"  [{item.Category}]")}");
        foreach (var skip in result.Skipped)
            Terminal.Info($"  - {skip.SourcePath}: {skip.Reason}");
        Terminal.Info($"Imported {result.Imported.Count}, skipped {result.Skipped.Count}.");

        if (deleteOriginals && result.Imported.Count > 0)
        {
            foreach (var item in result.Imported)
            {
                // Overwrite before deleting. On an SSD this isn't a guaranteed wipe, but it keeps the
                // plaintext out of the recycle bin and casual undelete tools.
                var length = new FileInfo(item.SourcePath).Length;
                File.WriteAllBytes(item.SourcePath, new byte[length]);
                File.Delete(item.SourcePath);
            }
            Terminal.Info($"Deleted {result.Imported.Count} original file(s).");
        }
        else if (result.Imported.Count > 0)
        {
            Terminal.Info("The original files are untouched. Re-run with --delete-originals once you've checked the import.");
        }

        return result.Skipped.Count > 0 ? 1 : 0;
    }

    private static async Task<int> RunAsync(Context c, Args args)
    {
        var mappings = args.Options("env");
        args.ThrowOnUnknown();
        if (mappings.Count == 0) throw new UsageException("Map at least one secret: --env VAR=NAME");
        if (args.PositionalCount > 0) throw new UsageException("Put the command after '--': keylo run --env VAR=NAME -- CMD");

        var pairs = mappings.Select(m =>
        {
            var eq = m.IndexOf('=');
            if (eq <= 0 || eq == m.Length - 1) throw new UsageException($"--env expects VAR=NAME, got '{m}'.");
            return (Variable: m[..eq], Name: m[(eq + 1)..]);
        }).ToList();

        var infos = pairs
            .Select(p => c.Store.Find(p.Name) ?? throw new SecretNotFoundException(p.Name))
            .DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        await c.AuthorizeAsync(SecretOperation.Run, infos, $"run with {string.Join(", ", infos.Select(s => s.Name))}");

        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (variable, name) in pairs)
        {
            var value = DecodeText(c.Store.Get(name).Value) ?? throw new KeyloException($"'{name}' is binary and can't be an environment variable.");
            environment[variable] = value;
        }

        return CommandRunner.Run(args.Rest, environment);
    }

    private static async Task<int> PushAsync(Context c, Args args)
    {
        var providerId = args.Positional(0, "provider (e.g. 1password)");
        var names = args.PositionalsFrom(1);
        var category = args.Option("category");
        var all = args.Flag("all");
        args.ThrowOnUnknown();

        var registry = new ProviderRegistry();
        var provider = registry.Find(providerId) ?? throw new UsageException($"No provider '{providerId}'. See 'keylo provider list'.");
        var settings = ProviderSettings(c, provider);

        var status = await provider.GetStatusAsync(settings);
        if (!status.Ready) throw new KeyloException($"{provider.DisplayName}: {status.Message}");

        await c.BrowseAsync();
        var selected = names.Count > 0
            ? names.Select(n => c.Store.Find(n) ?? throw new SecretNotFoundException(n)).ToList()
            : all || category is not null
                ? SecretSearch.Filter(c.Store.List(), null, category).ToList()
                : throw new UsageException("Name the secrets to push, or use --category C or --all.");

        if (selected.Count == 0)
        {
            Terminal.Info("Nothing to push.");
            return 0;
        }

        await c.ValueAsync($"push {selected.Count} secret(s) to {provider.DisplayName}");

        var failures = 0;
        foreach (var info in selected)
        {
            var result = await provider.PushAsync(c.Store.Get(info.Name), settings);
            Terminal.Info($"  {(result.Succeeded ? "+" : "!")} {info.Name}: {result.Message}");
            if (!result.Succeeded) failures++;
        }

        Terminal.Info($"Pushed {selected.Count - failures} of {selected.Count} to {provider.DisplayName}.");
        return failures > 0 ? 1 : 0;
    }

    private static async Task<int> ProviderAsync(Context c, Args args)
    {
        var action = args.OptionalPositional(0)?.ToLowerInvariant() ?? "list";
        args.ThrowOnUnknown();
        var registry = new ProviderRegistry();

        switch (action)
        {
            case "list":
                PrintTable(["ID", "NAME", "SETTINGS"], registry.All.Select(p => new[]
                {
                    p.Id, p.DisplayName,
                    string.Join(", ", p.SettingDescriptions.Keys.Select(k => ProviderSettings(c, p).ContainsKey(k) ? $"{k}=✓" : k)),
                }));
                foreach (var error in registry.LoadErrors)
                    Terminal.Info($"Plugin {Path.GetFileName(error.Path)} failed to load: {error.Message}");
                return 0;

            case "status":
            {
                var provider = registry.Find(args.Positional(1, "provider id")) ?? throw new UsageException("Unknown provider.");
                var status = await provider.GetStatusAsync(ProviderSettings(c, provider));
                Console.WriteLine($"{provider.DisplayName}: {status.Message}");
                return status.Ready ? 0 : 1;
            }

            case "set":
            {
                var provider = registry.Find(args.Positional(1, "provider id")) ?? throw new UsageException("Unknown provider.");
                var key = args.Positional(2, "setting name");
                var value = args.Positional(3, "setting value");
                if (!provider.SettingDescriptions.ContainsKey(key))
                    throw new UsageException($"{provider.DisplayName} settings: {string.Join(", ", provider.SettingDescriptions.Keys)}");

                if (!c.Config.Providers.TryGetValue(provider.Id, out var settings))
                    c.Config.Providers[provider.Id] = settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                settings[key] = value;
                c.Config.Save();
                Terminal.Info($"{provider.DisplayName}: {key} = {value}");
                return 0;
            }

            default:
                throw new UsageException("Usage: keylo provider list | status ID | set ID KEY VALUE");
        }
    }

    private static async Task<int> BackupAsync(Context c, Args args)
    {
        var path = Path.GetFullPath(args.Positional(0, "backup file"));
        var force = args.Flag("force");
        var passwordStdin = args.Flag("password-stdin");
        args.ThrowOnUnknown(maxPositionals: 1);

        if (!Path.HasExtension(path)) path += KeyloBackup.FileExtension;
        if (File.Exists(path) && !force) throw new UsageException($"{path} exists. Use --force to replace it.");

        // Exports every value, so it always verifies — no session or trust group shortcut.
        await c.Gate.ConfirmAsync(IntPtr.Zero, "Keylo: back up all secrets");

        var password = Terminal.ReadPassword("Backup password: ", confirm: true, passwordStdin);
        if (KeyloBackup.CheckPassword(password) is { } problem) throw new UsageException(problem);

        Terminal.Info("Encrypting…");
        var summary = KeyloBackup.Create(c.Store, new CategoryCatalog(c.Store), path, password);
        Terminal.Info($"Backed up {summary.Secrets} secrets, {summary.Categories} categories and {summary.Icons} icons to {summary.Path} ({summary.Bytes / 1024.0:0.#} KB).");
        Terminal.Info("Keep the password somewhere other than Keylo. Without it the backup can't be opened.");
        return 0;
    }

    private static async Task<int> RestoreAsync(Context c, Args args)
    {
        var path = Path.GetFullPath(args.Positional(0, "backup file"));
        var overwrite = args.Flag("overwrite");
        var dryRun = args.Flag("dry-run");
        var passwordStdin = args.Flag("password-stdin");
        args.ThrowOnUnknown(maxPositionals: 1);
        if (!File.Exists(path)) throw new UsageException($"{path} doesn't exist.");

        await c.BrowseAsync();
        var password = Terminal.ReadPassword("Backup password: ", confirm: false, passwordStdin);

        Terminal.Info("Decrypting…");
        var contents = KeyloBackup.Read(path, password);
        var existing = contents.Secrets.Count(s => c.Store.Exists(s.Name));
        Terminal.Info($"Backup from {contents.CreatedAt.LocalDateTime:yyyy-MM-dd HH:mm}: {contents.Secrets.Count} secrets " +
                      $"({existing} already here), {contents.Categories.Count} categories, {contents.Icons.Count} icons.");

        if (dryRun)
        {
            Terminal.Info(existing > 0 && !overwrite
                ? $"Would add {contents.Secrets.Count - existing} and skip {existing}. Nothing was changed (--dry-run)."
                : $"Would add {contents.Secrets.Count - existing} and replace {existing}. Nothing was changed (--dry-run).");
            return 0;
        }

        var result = KeyloBackup.Restore(c.Store, new CategoryCatalog(c.Store), contents, overwrite);
        Terminal.Info($"Restored: {result.Added} added, {result.Replaced} replaced, {result.Skipped} skipped" +
                      (result.Skipped > 0 && !overwrite ? " (use --overwrite to replace them)" : "") +
                      $"; {result.CategoriesAdded} new categories.");
        foreach (var error in result.Errors) Terminal.Info($"  ! {error}");
        return result.Errors.Count > 0 ? 1 : 0;
    }

    private static int Trust(Context c, Args args)
    {
        args.ThrowOnUnknown();
        if (c.Config.TrustGroups.Count == 0)
        {
            Console.WriteLine("No trust groups. Add them in the Keylo app (Settings → Trust groups).");
            return 0;
        }

        PrintTable(["GROUP", "CALLERS", "COVERS", "ALLOWS"], c.Config.TrustGroups.Select(g => new[]
        {
            g.Name,
            string.Join(", ", g.Callers),
            string.Join(", ", g.Categories.Select(cat => $"cat:{cat}").Concat(g.Secrets)),
            g.AllowGet ? "run, get" : "run",
        }));

        var mine = TrustPolicy.GroupsFor(c.Config, c.Ancestry);
        Console.WriteLine();
        Console.WriteLine($"This caller ({string.Join(" ← ", c.Ancestry.Take(4).Select(p => p.ExecutableName))}): " +
                          (mine.Count == 0 ? "not in any group" : $"in {string.Join(", ", mine.Select(g => g.Name))}"));
        return 0;
    }

    private static async Task<int> UnlockAsync(Context c, Args args)
    {
        args.ThrowOnUnknown();
        if (c.Gate.Mode == HelloMode.Never)
        {
            Terminal.Info("Windows Hello is off (hello = never); nothing to unlock.");
            return 0;
        }

        c.Gate.Lock();
        await c.Gate.UnlockAsync(IntPtr.Zero);
        Terminal.Info(c.Gate.SessionExpiresAt is { } until
            ? $"Unlocked until {until.LocalDateTime:HH:mm}."
            : "Verified.");
        return 0;
    }

    private static int Lock(Context c, Args args)
    {
        args.ThrowOnUnknown();
        c.Gate.Lock();
        Terminal.Info("Locked.");
        return 0;
    }

    private static int Status(Context c, Args args)
    {
        args.ThrowOnUnknown();
        var state = c.Gate.Mode switch
        {
            HelloMode.Never => "no Windows Hello prompt (hello = never)",
            HelloMode.Always => "Windows Hello on every value access (hello = always)",
            _ => c.Gate.SessionExpiresAt is { } until ? $"unlocked until {until.LocalDateTime:HH:mm}" : "locked",
        };
        Console.WriteLine($"Keylo {typeof(Program).Assembly.GetName().Version?.ToString(3)}: {state}");
        Console.WriteLine($"Data:  {KeyloPaths.DefaultDataDirectory}");
        return 0;
    }

    private static async Task<int> ConfigAsync(Context c, Args args)
    {
        var key = args.OptionalPositional(0)?.ToLowerInvariant();
        args.ThrowOnUnknown();

        if (key is null)
        {
            Console.WriteLine($"hello             {c.Config.Hello.ToString().ToLowerInvariant()}");
            Console.WriteLine($"session-minutes   {c.Config.SessionMinutes}");
            Console.WriteLine($"clipboard-seconds {c.Config.ClipboardSeconds}");
            return 0;
        }

        var value = args.Positional(1, $"value for {key}");

        // These settings decide when verification happens, so changing them always verifies.
        await c.Gate.ConfirmAsync(IntPtr.Zero, "Keylo: change settings");

        switch (key)
        {
            case "hello":
                c.Config.Hello = Enum.TryParse<HelloMode>(value, ignoreCase: true, out var mode)
                    ? mode
                    : throw new UsageException("hello must be session, always or never.");
                break;
            case "session-minutes":
                c.Config.SessionMinutes = int.TryParse(value, out var minutes) ? minutes : throw new UsageException("Expected a number of minutes.");
                break;
            case "clipboard-seconds":
                c.Config.ClipboardSeconds = int.TryParse(value, out var seconds) ? seconds : throw new UsageException("Expected a number of seconds.");
                break;
            default:
                throw new UsageException("Settings: hello, session-minutes, clipboard-seconds.");
        }

        c.Config.Save();
        c.Gate.Lock();
        Terminal.Info($"Saved. {key} = {value}");
        return 0;
    }

    private static int CopyWithTimeout(Context c, string text, string what)
    {
        var sequence = SecureClipboard.SetText(text);
        var seconds = c.Config.ClipboardSeconds;

        // A separate hidden process clears the clipboard, so this command can return immediately.
        var psi = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add("__clip-clear");
        psi.ArgumentList.Add(sequence.ToString());
        psi.ArgumentList.Add(seconds.ToString());
        Process.Start(psi)?.Dispose();

        Terminal.Info($"{what} copied. The clipboard clears in {seconds}s.");
        return 0;
    }

    private static int ClipClear(Args args)
    {
        var sequence = uint.Parse(args.Positional(0, "sequence"));
        var seconds = int.Parse(args.Positional(1, "seconds"));
        Thread.Sleep(TimeSpan.FromSeconds(seconds));
        SecureClipboard.ClearIfUnchanged(sequence);
        return 0;
    }

    private static IReadOnlyDictionary<string, string> ProviderSettings(Context c, IVaultProvider provider) =>
        c.Config.Providers.TryGetValue(provider.Id, out var settings) ? settings : new Dictionary<string, string>();

    private static string? DecodeText(byte[] value)
    {
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(value);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static void PrintTable(string[] headers, IEnumerable<string[]> rows)
    {
        var all = rows.ToList();
        var widths = headers.Select((h, i) => Math.Min(48, all.Select(r => r[i].Length).Append(h.Length).Max())).ToArray();

        string Line(string[] cells) => string.Join("  ", cells.Select((cell, i) =>
            (cell.Length > widths[i] ? cell[..(widths[i] - 1)] + "…" : cell).PadRight(widths[i]))).TrimEnd();

        Console.WriteLine(Line(headers));
        foreach (var row in all) Console.WriteLine(Line(row));
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };
}
