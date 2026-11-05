using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Keylo.Core;
using Keylo.Core.Providers;
using Keylo.Core.Security;

namespace Keylo.Cli;

internal static class Program
{
    private static string Usage => $"""
        keylo - local secrets in {Platform.StoreName}

        keylo                                   Open the Keylo app
        keylo list [search...] [--category C]   List secrets (search matches name, category, username, notes,
                                                non-secret fields; "type:login" and "cat:dev" narrow it)
        keylo categories                        List categories with counts
        keylo types                             List secret types (login, api_key, database, ...) and their fields
        keylo get NAME [--clip] [--out FILE] [--field F] [--both]
                                                Print the value (a typed secret's main field, or --field F;
                                                the clipboard clears itself). --both prints every field
        keylo set NAME [--category C] [--username U] [--notes N] [--file FILE]
                                                Add or update (value is prompted, piped, or read from FILE)
        keylo set NAME --type T [--field F=V]... [--category C] [--notes N] [--file FILE]
                                                Add a typed secret (the main secret field is prompted)
        keylo edit NAME [--rename NEW] [--category C] [--username U] [--notes N] [--field F=V]...
                                                Change details or fields ("" clears one)
        keylo rm NAME [--yes]                   Delete a secret
        keylo import PATH... [--category C | --flat] [--overwrite] [--delete-originals] [--plain]
                                                One secret per file. Subfolders become categories,
                                                unless --category puts everything in C or --flat sets none
                                                Types are guessed (SSH key, database URL, token…); --plain keeps them plain
        keylo run --env VAR=NAME [...] -- CMD [ARGS]
                                                Run CMD with secrets as environment variables
                                                (NAME:FIELD maps one field, e.g. prod-db:password or x:username;
                                                NAME@ENV picks an environment of a per-environment link, e.g. orders-db@uat)
        keylo link NAME --item ITEM [--provider 1password|aws] [--vault V] [--account A] [--field F] [--category C]
                                                Link to an item in another vault (read live, never copied)
        keylo link --search QUERY [--provider P] [--account A]   Find items to link
                                                (aws: --profile P --region R, else the provider settings)
        keylo link NAME --provider aws --item SECRET --environment ENV [--env-name ENV=OTHER-NAME]...
                                                Link per environment: NAME@dev, NAME@prod… read SECRET from
                                                each environment's account (see keylo provider env)
        keylo provider env aws [list | set ENV PROFILE REGION [--ask] | remove ENV | default ENV]
                                                Environments (dev, uat, prod…) for per-environment links
        keylo push PROVIDER [NAME...] [--category C] [--all] [--yes]
                                                Push secrets to another vault (e.g. 1password)
        keylo provider list | status ID | set ID KEY VALUE
        keylo backup FILE [--force] [--password-stdin]
                                                Encrypted, password-protected backup of everything
        keylo restore FILE [--overwrite] [--dry-run] [--password-stdin]
                                                Restore a backup (existing secrets are skipped unless --overwrite)
        keylo keys                              List access keys (let tools use secrets without {Platform.VerifierName})
        keylo keys create NAME [--all | --category C... --secret S...] [--allow-get] [--expires-days N] [--add-to-claude]
                                                Create a key (shown once; --add-to-claude registers the MCP server instead)
        keylo keys revoke NAME                  Revoke a key
        keylo mcp                               The MCP server for AI agents (started by the agent; run it
                                                yourself to see how to set it up)
        keylo unlock | lock | status | version
        keylo config [hello session|always|never | session-minutes N | clipboard-seconds N | audit-days N|forever]
        """;

    private static readonly string[] Flags = ["clip", "yes", "overwrite", "delete-originals", "flat", "plain", "all", "json", "force", "dry-run", "password-stdin", "both", "allow-get", "add-to-claude", "help", "stdio", "ask", "no-ask"];

    private static Keylo.Core.Platform.IKeyloPlatform Platform => Keylo.Core.Platform.KeyloPlatform.Current;

    /// <summary>
    /// This keylo: keylo.exe on Windows; on macOS the keylo launcher inside Keylo.app, which runs the
    /// app's own executable (one code signature, so the keychain sees one app).
    /// </summary>
    internal static string SelfPath =>
        Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "keylo.exe" : "keylo") is var path && File.Exists(path)
            ? path : Environment.ProcessPath!;

    /// <summary>The entry point; also called by the macOS app (KeyloApp --cli ARGS).</summary>
    internal static async Task<int> Main(string[] argv)
    {
        InstallPlatform();
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
                "version" or "--version" or "-v" => PrintVersion(),
                "list" or "ls" or "search" => await ListAsync(context, args),
                "categories" or "cats" => await CategoriesAsync(context, args),
                "types" => Types(context, args),
                "get" => await GetAsync(context, args),
                "set" or "add" => await SetAsync(context, args),
                "edit" => await EditAsync(context, args),
                "rm" or "delete" or "remove" => await RemoveAsync(context, args),
                "import" => await ImportAsync(context, args),
                "run" => await RunAsync(context, args),
                "push" => await PushAsync(context, args),
                "link" => await LinkAsync(context, args),
                "provider" or "providers" => await ProviderAsync(context, args),
                "keys" or "key" => await KeysAsync(context, args),
                "mcp" => args.Flag("stdio") || Console.IsInputRedirected ? await Mcp.McpServer.RunAsync() : Mcp.McpServer.Explain(context.Config, SelfPath),
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
        public SecretTypeCatalog Types { get; } = new();

        public ProviderRegistry Registry => _registry ??= new ProviderRegistry();
        private ProviderRegistry? _registry;
        public AccessGate Gate { get; }

        public Context() => Gate = new AccessGate(Config, Keylo.Core.Platform.KeyloPlatform.Current.Verifier);

        /// <summary>The access key in KEYLO_ACCESS_KEY, if it's valid and unexpired.</summary>
        public AccessKey? Key => _key ??= AccessKeys.FromEnvironment(Config);
        private AccessKey? _key;

        /// <summary>For commands that change secrets or settings: access keys never apply.</summary>
        public Task BrowseAsync() => Gate.EnsureAsync(IntPtr.Zero, "Unlock Keylo", valueAccess: false);

        /// <summary>
        /// Lists what this caller may see: everything once unlocked; otherwise, for a caller with an
        /// access key, only the secrets the key covers (without prompting); otherwise prompts.
        /// </summary>
        public async Task<IReadOnlyList<SecretInfo>> VisibleSecretsAsync()
        {
            if (!Gate.IsUnlocked && Key is { } key)
                return Store.List().Where(key.Covers).ToList();

            await BrowseAsync();
            return Store.List();
        }

        /// <summary>
        /// Allows a value operation via the access key (audited) or Windows Hello / Touch ID. With
        /// <paramref name="alwaysAsk"/> (a use in an "always ask" environment such as prod) the key doesn't count.
        /// </summary>
        public async Task AuthorizeAsync(SecretOperation operation, IReadOnlyCollection<SecretInfo> secrets, string what,
            bool alwaysAsk = false, IEnumerable<string>? logged = null)
        {
            if (!alwaysAsk && Key is { } key && key.Allows(operation, secrets))
            {
                AuditLog.Write(operation.ToString().ToLowerInvariant(), logged ?? secrets.Select(s => s.Name), key, "access key");
                return;
            }

            if (Key is null && AccessKeys.IsPresentInEnvironment)
                Terminal.Info($"keylo: {AccessKeys.EnvironmentVariable} isn't a valid, unexpired access key; asking {Platform.VerifierName} instead.");
            await Gate.EnsureAsync(IntPtr.Zero, $"Keylo: {what}", valueAccess: true);
        }

        /// <summary>Settings and pushes always need Windows Hello / Touch ID (or hello = never).</summary>
        public Task ValueAsync(string what) => Gate.EnsureAsync(IntPtr.Zero, $"Keylo: {what}", valueAccess: true);
    }

    private static int PrintVersion()
    {
        Console.WriteLine($"keylo {KeyloVersion.Of(typeof(Program).Assembly)}");
        return 0;
    }

    private static void InstallPlatform()
    {
#if WINDOWS
        Keylo.Platform.Windows.WindowsPlatform.Install();
#else
        if (!OperatingSystem.IsMacOS()) throw new PlatformNotSupportedException("Keylo runs on Windows and macOS.");
        Keylo.Platform.MacOS.MacPlatform.Install();
#endif
    }

    private static int LaunchApp()
    {
        if (!OperatingSystem.IsWindows())
        {
            // On macOS keylo lives inside Keylo.app (Contents/MacOS); open the app around it.
            var bundle = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", ".."));
            if (OperatingSystem.IsMacOS() && bundle.EndsWith(".app", StringComparison.OrdinalIgnoreCase) && Directory.Exists(bundle))
            {
                Process.Start(new ProcessStartInfo("/usr/bin/open", [bundle]) { UseShellExecute = false })?.Dispose();
                return 0;
            }
            Console.WriteLine(Usage);
            Terminal.Info("The Keylo app isn't installed next to this keylo; everything is also in the keylo command (and the MCP server).");
            return 0;
        }

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
            ["NAME", "TYPE", "CATEGORY", "USERNAME", "UPDATED"],
            secrets.Select(s => new[] { s.Name, s.Type ?? "", s.Category ?? "", s.Username ?? "", s.UpdatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm") }));
        return 0;
    }

    private static int Types(Context c, Args args)
    {
        args.ThrowOnUnknown();
        foreach (var type in c.Types.All())
        {
            Console.WriteLine($"{type.Id}  ({type.Name}{(type.IsBuiltIn ? "" : ", custom")})");
            foreach (var field in type.Fields)
                Console.WriteLine($"    {field.Id,-20} {field.Kind}{(field == type.Primary ? ", main value" : "")}" +
                                  (field.Options is { Count: > 0 } options ? $"  [{string.Join(", ", options)}]" : ""));
        }
        Console.WriteLine();
        Console.WriteLine("Add one: keylo set NAME --type login --field username=alice --field url=https://…  (the main value is prompted)");
        Console.WriteLine("Custom types are managed in the app (Settings → Secret types).");
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
        var field = args.Option("field")?.ToLowerInvariant();
        var outFile = args.Option("out");
        var both = args.Flag("both");
        args.ThrowOnUnknown(maxPositionals: 1);
        if (both && (clip || outFile is not null || field is not null))
            throw new UsageException("--both prints to the terminal; it can't be combined with --clip, --out or --field.");

        var reference = SecretReference.Parse(name, n => c.Store.Exists(n)) ?? throw new SecretNotFoundException(name);
        var info = c.Store.Find(reference.Name)!;
        field ??= reference.Field?.ToLowerInvariant();
        var env = LinkedSecrets.EnvironmentFor(info, c.Config, reference.Environment);
        if (LinkedSecrets.IsLinked(info))
        {
            var label = env is null ? info.Name : $"{info.Name}@{env.Name}";
            await c.AuthorizeAsync(SecretOperation.Get, [info], $"read '{label}'", env?.AlwaysAsk == true, [label]);
            var link = LinkedSecrets.Read(info)!;
            var values = await LinkedSecrets.ResolveAsync(info, c.Registry, c.Config, env?.Name);
            if (both)
            {
                Console.WriteLine($"type: link ({link.Target.Provider}: {link.Title}{(env is null ? "" : $", environment {env.Name}")})");
                foreach (var (id, text) in values) Console.WriteLine($"{id}: {text}");
                return 0;
            }

            var linkedField = PickLinkedField(info, link, values, field);
            if (outFile is not null)
            {
                File.WriteAllText(outFile, linkedField);
                Terminal.Info($"Wrote it to {Path.GetFullPath(outFile)}");
                return 0;
            }
            if (clip) return CopyWithTimeout(c, linkedField, "Value");
            Console.WriteLine(linkedField);
            return 0;
        }

        var type = c.Types.Find(info.Type);
        if (field is "username" or "key")
        {
            if (info.Username is null) throw new KeyloException($"'{name}' has no username.");
            await c.AuthorizeAsync(SecretOperation.Get, [info], $"read the username of '{name}'");
            if (clip) return CopyWithTimeout(c, info.Username, "Username");
            Console.WriteLine(info.Username);
            return 0;
        }
        if (type is null && field is not (null or "value"))
            throw new UsageException($"'{name}' is a plain secret; --field must be value or username.");

        await c.AuthorizeAsync(SecretOperation.Get, [info], $"read '{name}'");
        var secret = c.Store.Get(info.Name);

        if (both)
        {
            // Every field (typed) or key and value (plain), e.g. for a login an agent needs.
            if (type is null)
            {
                var value = DecodeText(secret.Value) ?? throw new KeyloException($"'{name}' is binary; use --out FILE instead.");
                if (info.Username is not null) Console.WriteLine($"key: {info.Username}");
                Console.WriteLine($"value: {value}");
                return 0;
            }

            var fields = TypedSecrets.ReadFields(type, info, secret.Value);
            Console.WriteLine($"type: {type.Id}");
            foreach (var f in type.Fields)
                if (fields.TryGetValue(f.Id, out var text)) Console.WriteLine($"{f.Id}: {text}");
            return 0;
        }

        if (type is null)
        {
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

        // Typed: one field, the main (first secret) field by default.
        var chosen = field is null or "value" ? type.Primary : type.Field(field)
            ?? throw new UsageException($"{type.Name} has no field '{field}'. Fields: {string.Join(", ", type.Fields.Select(f => f.Id))}.");
        if (chosen is null || !TypedSecrets.ReadFields(type, info, secret.Value).TryGetValue(chosen.Id, out var fieldValue))
            throw new KeyloException($"'{name}' has no {chosen?.Label ?? "value"}.");

        if (outFile is not null)
        {
            File.WriteAllText(outFile, fieldValue);
            Terminal.Info($"Wrote {chosen.Label} to {Path.GetFullPath(outFile)}");
            return 0;
        }
        if (clip) return CopyWithTimeout(c, fieldValue, chosen.Label);
        Console.WriteLine(fieldValue);
        return 0;
    }

    private static async Task<int> SetAsync(Context c, Args args)
    {
        var name = SecretStore.NormalizeName(args.Positional(0, "secret name"));
        var category = args.Option("category");
        var username = args.Option("username");
        var notes = args.Option("notes");
        var file = args.Option("file");
        var typeName = args.Option("type");
        var fieldArgs = args.Options("field");
        args.ThrowOnUnknown(maxPositionals: 1);
        await c.BrowseAsync();

        var existing = c.Store.Find(name);
        if (typeName is null && fieldArgs.Count == 0)
        {
            var value = file is not null
                ? File.ReadAllBytes(file)
                : Terminal.ReadSecret(existing is null ? $"Value for '{name}': " : $"New value for '{name}': ", confirm: true);

            c.Store.Save(
                new SecretDraft(name, value, category ?? existing?.Category, username ?? existing?.Username, notes ?? existing?.Notes,
                    existing?.Icon, existing?.Color),
                originalName: existing?.Name);
        }
        else
        {
            var type = (typeName is not null ? c.Types.Resolve(typeName) : c.Types.Find(existing?.Type))
                       ?? throw new UsageException(typeName is null
                           ? "--field needs --type (e.g. --type login). See 'keylo types'."
                           : $"No type '{typeName}'. See 'keylo types'.");

            var fields = ParseFieldArgs(type, fieldArgs);
            if (username is not null && type.UsernameField is { } userField) fields[userField.Id] = username;
            if (type.Primary is { } primary && !fields.ContainsKey(primary.Id))
            {
                fields[primary.Id] = file is not null
                    ? File.ReadAllText(file)
                    : Encoding.UTF8.GetString(Terminal.ReadSecret($"{primary.Label} for '{name}': ", confirm: true));
            }

            c.Store.Save(
                TypedSecrets.Draft(type, name, fields, category ?? existing?.Category, notes ?? existing?.Notes, existing?.Icon, existing?.Color),
                originalName: existing?.Name);
        }

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
        var fieldArgs = args.Options("field");
        args.ThrowOnUnknown(maxPositionals: 1);

        if (rename is null && category is null && username is null && notes is null && fieldArgs.Count == 0)
            throw new UsageException("Nothing to change. Use --rename, --category, --username, --notes or --field.");

        await c.BrowseAsync();
        var secret = c.Store.Get(name);
        var type = c.Types.Find(secret.Info.Type);

        SecretDraft draft;
        if (fieldArgs.Count > 0)
        {
            if (type is null) throw new UsageException($"'{name}' is a plain secret; --field only applies to typed secrets.");
            var fields = TypedSecrets.ReadFields(type, secret.Info, secret.Value, derive: false)
                .ToDictionary(p => p.Key, p => (string?)p.Value, StringComparer.OrdinalIgnoreCase);
            foreach (var (id, value) in ParseFieldArgs(type, fieldArgs)) fields[id] = value; // "" clears
            if (username is not null && type.UsernameField is { } userField) fields[userField.Id] = username;
            draft = TypedSecrets.Draft(type, rename ?? secret.Info.Name, fields, category ?? secret.Info.Category,
                notes ?? secret.Info.Notes, secret.Info.Icon, secret.Info.Color);
        }
        else
        {
            draft = SecretDraft.From(secret) with
            {
                Name = rename ?? secret.Info.Name,
                Category = category ?? secret.Info.Category,
                Username = username ?? secret.Info.Username,
                Notes = notes ?? secret.Info.Notes,
            };
        }

        var info = c.Store.Save(draft, originalName: secret.Info.Name);
        Terminal.Info($"Updated '{info.Name}'.");
        return 0;
    }

    /// <summary>"--field host=db.local" pairs, checked against the type. Secret fields given this way end up in shell history.</summary>
    private static Dictionary<string, string?> ParseFieldArgs(SecretTypeDefinition type, IReadOnlyList<string> pairs)
    {
        var fields = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in pairs)
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) throw new UsageException($"--field expects NAME=VALUE, got '{pair}'.");
            var field = type.Field(pair[..eq].Trim())
                        ?? throw new UsageException($"{type.Name} has no field '{pair[..eq]}'. Fields: {string.Join(", ", type.Fields.Select(f => f.Id))}.");
            if (field.IsSecret) Terminal.Info($"keylo: note that '{field.Id}' given on the command line is visible in your shell history.");
            fields[field.Id] = pair[(eq + 1)..];
        }
        return fields;
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
        var plain = args.Flag("plain");
        args.ThrowOnUnknown();
        if (paths.Count == 0) throw new UsageException("Give one or more files or folders to import.");
        if (flat && category is not null) throw new UsageException("Use --category or --flat, not both.");
        await c.BrowseAsync();

        var result = SecretImporter.Import(c.Store, paths, category, overwrite, subfolderCategories: !flat, inferTypes: !plain);

        foreach (var item in result.Imported)
            Terminal.Info($"  + {item.Name}{(item.Type is null ? "" : $"  ({item.Type})")}{(item.Category is null ? "" : $"  [{item.Category}]")}");
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
        // The app's "Copy CLI command" ends with this placeholder.
        if (args.Rest is ["YOUR-COMMAND", ..])
            throw new UsageException("Replace YOUR-COMMAND with the program that needs the secret, e.g. ... -- node deploy.js (it reads the variables from its environment).");

        var pairs = mappings.Select(m =>
        {
            var eq = m.IndexOf('=');
            if (eq <= 0 || eq == m.Length - 1) throw new UsageException($"--env expects VAR=NAME, got '{m}'.");
            var (info, field, env) = ResolveEnvSource(c, m[(eq + 1)..]);
            return (Variable: m[..eq], Info: info, Field: field, Env: env);
        }).ToList();

        var infos = pairs.Select(p => p.Info).DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
        var labels = pairs.Select(p => p.Env is null ? p.Info.Name : $"{p.Info.Name}@{p.Env.Name}").Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        await c.AuthorizeAsync(SecretOperation.Run, infos, $"run with {string.Join(", ", labels)}", pairs.Any(p => p.Env?.AlwaysAsk == true), labels);

        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (variable, info, field, env) in pairs)
            environment[variable] = FieldValue(c, info, field, env?.Name);

        return CommandRunner.Run(args.Rest, environment);
    }

    /// <summary>
    /// "NAME" maps the main value; "NAME:FIELD" one field ("username" works for any secret, other
    /// field ids for typed ones); "NAME@ENV[:FIELD]" an environment of a per-environment link. Names
    /// may contain ':' and '@', so an exact secret name wins.
    /// </summary>
    private static (SecretInfo Info, string? Field, VaultEnvironment? Env) ResolveEnvSource(Context c, string source)
    {
        var reference = SecretReference.Parse(source, n => c.Store.Exists(n)) ?? throw new SecretNotFoundException(source);
        var info = c.Store.Find(reference.Name)!;
        return (info, reference.Field, LinkedSecrets.EnvironmentFor(info, c.Config, reference.Environment));
    }

    /// <summary>A secret's main value, or one field, as text (a per-environment link's from <paramref name="environment"/>).</summary>
    private static string FieldValue(Context c, SecretInfo info, string? field, string? environment = null)
    {
        if (LinkedSecrets.Read(info) is { } link)
            return PickLinkedField(info, link, LinkedSecrets.ResolveAsync(info, c.Registry, c.Config, environment).GetAwaiter().GetResult(), field);

        if (field?.ToLowerInvariant() is "username" or "key")
            return info.Username ?? throw new KeyloException($"'{info.Name}' has no username.");

        var type = c.Types.Find(info.Type);
        var secret = c.Store.Get(info.Name);
        if (type is null)
        {
            if (field is not (null or "value")) throw new KeyloException($"'{info.Name}' is a plain secret; it only has value and username.");
            return DecodeText(secret.Value) ?? throw new KeyloException($"'{info.Name}' is binary and can't be an environment variable.");
        }

        var chosen = field is null or "value" ? type.Primary : type.Field(field)
            ?? throw new KeyloException($"{type.Name} '{info.Name}' has no field '{field}'. Fields: {string.Join(", ", type.Fields.Select(f => f.Id))}.");
        return chosen is not null && TypedSecrets.ReadFields(type, info, secret.Value).TryGetValue(chosen.Id, out var value)
            ? value
            : throw new KeyloException($"'{info.Name}' has no {chosen?.Label ?? "value"}.");
    }

    /// <summary>One field of a resolved link: its main field by default; "key" means username.</summary>
    private static string PickLinkedField(SecretInfo info, LinkedSecrets.Link link, Dictionary<string, string> values, string? field)
    {
        var id = field?.ToLowerInvariant() switch
        {
            null or "value" => link.MainField,
            "key" => "username",
            _ => field,
        };
        return id is not null && values.TryGetValue(id, out var value)
            ? value
            : throw new KeyloException($"'{info.Name}' has no {(field is null ? "value" : $"field '{field}'")} in {link.Title}. Fields: {string.Join(", ", values.Keys)}.");
    }

    /// <summary>
    /// keylo link NAME --item ITEM: a secret that points at an item in another vault (1Password by
    /// default, or --provider aws); values are read from there on every use. keylo link --search QUERY finds items.
    /// </summary>
    private static async Task<int> LinkAsync(Context c, Args args)
    {
        var providerId = args.Option("provider") ?? "1password";
        var search = args.Option("search");
        var item = args.Option("item");
        var account = args.Option("account");
        var profile = args.Option("profile");
        var region = args.Option("region");
        var environmentName = args.Option("environment");
        var environmentNames = args.Options("env-name");
        var vaultFilter = args.Option("vault");
        var only = args.Option("field");
        var category = args.Option("category");
        var notes = args.Option("notes");
        args.ThrowOnUnknown(maxPositionals: 1);

        var provider = c.Registry.FindLinked(providerId)
                       ?? throw new UsageException($"No linked vault '{providerId}'. Available: {string.Join(", ", c.Registry.Linked.Select(p => p.Id))}.");
        var settings = new Dictionary<string, string>(c.Config.Providers.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);
        if (account is not null) settings["account"] = account;
        if (profile is not null) settings["profile"] = profile;
        if (region is not null) settings["region"] = region;
        if (environmentName is not null)
        {
            // Search that environment's account; the link itself will name only the secret.
            if (VaultEnvironments.Find(settings, environmentName) is null)
                throw new UsageException($"No environment '{environmentName}'. Add one: keylo provider env {provider.Id} set {environmentName} PROFILE REGION");
            settings[LinkedSecrets.EnvironmentSetting] = environmentName;
        }

        if (search is not null)
        {
            var found = (await provider.SearchAsync(search, settings)).Where(i => vaultFilter is null || string.Equals(i.VaultName, vaultFilter, StringComparison.OrdinalIgnoreCase)).ToList();
            if (found.Count == 0)
            {
                Terminal.Info("Nothing matches.");
                return 1;
            }
            PrintTable(["TITLE", "VAULT", "WHERE", "CATEGORY", "ID"], found.Select(i => new[] { i.Title, i.VaultName ?? "", i.Location ?? "", i.Category ?? "", i.ItemId }));
            return 0;
        }

        var name = SecretStore.NormalizeName(args.Positional(0, "secret name"));
        if (item is null) throw new UsageException("Usage: keylo link NAME --item ITEM [--vault V] [--account A] [--field F] [--category C]   (find items with --search QUERY)");
        await c.BrowseAsync();
        if (c.Store.Exists(name)) throw new SecretExistsException(name);

        // ITEM is an id or a title; a title must match exactly one item.
        var candidates = (await provider.SearchAsync(null, settings))
            .Where(i => vaultFilter is null || string.Equals(i.VaultName, vaultFilter, StringComparison.OrdinalIgnoreCase))
            .Where(i => i.ItemId == item || string.Equals(i.Title, item, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var chosen = candidates.Count switch
        {
            1 => candidates[0],
            0 => throw new KeyloException($"No item '{item}' in {provider.DisplayName}. Try: keylo link --search \"{item}\""),
            _ => throw new KeyloException($"'{item}' matches {candidates.Count} items ({string.Join("; ", candidates.Select(i => $"{i.VaultName} · {i.Location} · {i.ItemId}"))}). Use --vault, --account or the id."),
        };

        var target = environmentName is null
            ? new LinkTarget(provider.Id, chosen.ItemId, chosen.VaultId, chosen.Location)
            : new LinkTarget(provider.Id, chosen.Title, null, LinkedSecrets.PerEnvironment);
        var fields = await provider.DescribeAsync(target, settings);
        if (only is not null && fields.All(f => !f.Id.Equals(only, StringComparison.OrdinalIgnoreCase)))
            throw new UsageException($"{chosen.Title} has no field '{only}'. Fields: {string.Join(", ", fields.Select(f => f.Id))}.");

        var overrides = environmentNames.Select(n => n.Split('=', 2)).ToList();
        if (overrides.Any(o => o.Length != 2 || o[0].Length == 0 || o[1].Length == 0))
            throw new UsageException("--env-name expects ENV=SECRET-NAME, e.g. --env-name prod=orders/db-prod");
        if (overrides.Count > 0 && environmentName is null) throw new UsageException("--env-name needs --environment (a per-environment link).");

        var where = environmentName is null
            ? string.Join(" · ", new[] { chosen.VaultName, chosen.Location }.Where(x => !string.IsNullOrEmpty(x)))
            : "per environment";
        var link = new LinkedSecrets.Link(target, chosen.Title, where, fields, only?.ToLowerInvariant(),
            overrides.Count > 0 ? overrides.ToDictionary(o => o[0], o => o[1], StringComparer.OrdinalIgnoreCase) : null);
        category ??= environmentName is not null
            ? provider.DisplayName
            : LinkedSecrets.DefaultCategory(provider.DisplayName, chosen,
                severalLocations: (await provider.SearchAsync(null, settings)).Select(i => i.Location).Distinct().Count() > 1);
        c.Store.Save(LinkedSecrets.Draft(name, link, category == "" ? null : category, notes, icon: null, color: null));
        Terminal.Info($"Linked '{name}' to {chosen.Title} in {provider.DisplayName} ({where}), category '{category}'. Fields: {string.Join(", ", link.VisibleFields.Select(f => f.Id))}.");
        if (environmentName is not null)
            Terminal.Info($"Use it as {name}@ENV ({string.Join(", ", VaultEnvironments.Read(settings).Select(e => e.Name))}); plain '{name}' uses the default environment.");
        return 0;
    }

    private static async Task<int> PushAsync(Context c, Args args)
    {
        var providerId = args.Positional(0, "provider (e.g. 1password)");
        var names = args.PositionalsFrom(1);
        var category = args.Option("category");
        var all = args.Flag("all");
        var yes = args.Flag("yes");
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

        // Show where it all goes before anything is read or sent.
        var target = (await provider.PreviewAsync(selected[0].Name, settings)).Target;
        Terminal.Info($"Pushing {selected.Count} secret(s) to {provider.DisplayName}: {target}");
        foreach (var info in selected.Take(10)) Terminal.Info($"  {info.Name}");
        if (selected.Count > 10) Terminal.Info($"  …and {selected.Count - 10} more");
        if (!yes && !Terminal.Confirm("Push them? (existing Keylo-pushed items are updated)"))
        {
            Terminal.Info("Nothing pushed.");
            return 1;
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

    /// <summary>
    /// keylo provider env aws [list | set ENV PROFILE REGION [--ask|--no-ask] | remove ENV | default ENV]:
    /// the environments per-environment links read from. Changes ask for Windows Hello / Touch ID, since
    /// "always ask" decides what agents can use without approval.
    /// </summary>
    private static async Task<int> EnvironmentsAsync(Context c, Args args, IVaultProvider provider, bool ask, bool noAsk)
    {
        if (!provider.HasEnvironments) throw new UsageException($"{provider.DisplayName} has no environments.");
        if (!c.Config.Providers.TryGetValue(provider.Id, out var settings))
            c.Config.Providers[provider.Id] = settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var environments = VaultEnvironments.Read(settings).ToList();
        var defaultName = VaultEnvironments.Default(settings);

        switch (args.OptionalPositional(2)?.ToLowerInvariant() ?? "list")
        {
            case "list":
                if (environments.Count == 0)
                {
                    Terminal.Info($"No environments yet. Add one: keylo provider env {provider.Id} set dev PROFILE REGION");
                    return 0;
                }
                PrintTable(["ENVIRONMENT", "PROFILE", "REGION", "ALWAYS ASK", "DEFAULT"], environments.Select(e => new[]
                {
                    e.Name, e.Profile ?? "(default credentials)", e.Region ?? "(profile's)", e.AlwaysAsk ? "yes" : "",
                    e.Name.Equals(defaultName, StringComparison.OrdinalIgnoreCase) ? "✓" : "",
                }));
                return 0;

            case "set":
            {
                var name = args.Positional(3, "environment name");
                var existing = environments.FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                // Production-like names start as "always ask"; --ask / --no-ask decide explicitly.
                var alwaysAsk = ask || (!noAsk && (existing?.AlwaysAsk ?? VaultEnvironments.LooksLikeProduction(name)));
                var updated = new VaultEnvironment(name, args.OptionalPositional(4), args.OptionalPositional(5), alwaysAsk);
                await c.ValueAsync($"change {provider.DisplayName} environments");
                environments.RemoveAll(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                environments.Add(updated);
                VaultEnvironments.Write(settings, environments, settings.GetValueOrDefault(VaultEnvironments.DefaultKey));
                c.Config.Save();
                Terminal.Info($"{name}: profile {updated.Profile ?? "(default credentials)"}, region {updated.Region ?? "(profile's)"}{(alwaysAsk ? ", always asks" : "")}.");
                return 0;
            }

            case "remove":
            {
                var name = args.Positional(3, "environment name");
                if (environments.RemoveAll(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) == 0) throw new KeyloException($"No environment '{name}'.");
                await c.ValueAsync($"change {provider.DisplayName} environments");
                var keepDefault = settings.GetValueOrDefault(VaultEnvironments.DefaultKey) is { } d && !d.Equals(name, StringComparison.OrdinalIgnoreCase) ? d : null;
                VaultEnvironments.Write(settings, environments, keepDefault);
                c.Config.Save();
                Terminal.Info($"Removed {name}.");
                return 0;
            }

            case "default":
            {
                var name = args.Positional(3, "environment name");
                if (environments.All(e => !e.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) throw new KeyloException($"No environment '{name}'.");
                await c.ValueAsync($"change {provider.DisplayName} environments");
                VaultEnvironments.Write(settings, environments, name);
                c.Config.Save();
                Terminal.Info($"Default environment: {name}.");
                return 0;
            }

            default:
                throw new UsageException($"Usage: keylo provider env {provider.Id} [list | set ENV PROFILE REGION [--ask|--no-ask] | remove ENV | default ENV]");
        }
    }

    private static async Task<int> ProviderAsync(Context c, Args args)
    {
        var action = args.OptionalPositional(0)?.ToLowerInvariant() ?? "list";
        var ask = args.Flag("ask");
        var noAsk = args.Flag("no-ask");
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

            case "env":
                return await EnvironmentsAsync(c, args, registry.Find(args.Positional(1, "provider id")) ?? throw new UsageException("Unknown provider."), ask, noAsk);

            default:
                throw new UsageException("Usage: keylo provider list | status ID | set ID KEY VALUE | env ID [list | set ENV PROFILE REGION [--ask] | remove ENV | default ENV]");
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

    private static async Task<int> KeysAsync(Context c, Args args)
    {
        var action = args.PositionalCount > 0 ? args.Positional(0, "action").ToLowerInvariant() : "list";
        switch (action)
        {
            case "list" or "ls":
            {
                args.ThrowOnUnknown(maxPositionals: 1);
                if (c.Config.AccessKeys.Count == 0)
                {
                    Console.WriteLine("No access keys. Create one with 'keylo keys create NAME' or in the app (Settings → Access keys).");
                    return 0;
                }

                var now = DateTimeOffset.Now;
                PrintTable(["NAME", "ID", "COVERS", "ALLOWS", "EXPIRES"], c.Config.AccessKeys.Select(k => new[]
                {
                    k.Name,
                    k.Id,
                    k.Scope == KeyScope.All ? "everything"
                        : string.Join(", ", k.Categories.Select(cat => $"cat:{cat}").Concat(k.Secrets)) is { Length: > 0 } covers ? covers : "nothing (asks each time)",
                    k.AllowGet ? "run, get" : "run",
                    k.Expires is { } e ? (k.IsExpired(now) ? "expired" : e.LocalDateTime.ToString("yyyy-MM-dd")) : "never",
                }));

                Console.WriteLine();
                Console.WriteLine(c.Key is { } mine
                    ? $"This process has the key '{mine.Name}' ({AccessKeys.EnvironmentVariable})."
                    : AccessKeys.IsPresentInEnvironment
                        ? $"{AccessKeys.EnvironmentVariable} is set but isn't a valid, unexpired key."
                        : $"This process has no access key ({AccessKeys.EnvironmentVariable} isn't set).");
                return 0;
            }

            case "create" or "new" or "add":
            {
                var name = args.Positional(1, "key name").Trim();
                var categories = args.Options("category");
                var secrets = args.Options("secret");
                var allowGet = args.Flag("allow-get");
                var everything = args.Flag("all");
                var expiresDays = args.Option("expires-days");
                var addToClaude = args.Flag("add-to-claude");
                args.ThrowOnUnknown(maxPositionals: 2);

                if (name.Length == 0) throw new UsageException("Give the key a name, e.g. 'Claude Code'.");
                if (c.Config.AccessKeys.Any(k => k.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                    throw new UsageException($"There's already a key called '{name}'. Revoke it first, or pick another name.");
                DateTimeOffset? expires = expiresDays is null ? null
                    : int.TryParse(expiresDays, out var days) && days > 0 ? DateTimeOffset.Now.AddDays(days)
                    : throw new UsageException("--expires-days must be a positive number.");

                await c.Gate.ConfirmAsync(IntPtr.Zero, $"Keylo: create access key '{name}'");

                var (key, token) = AccessKeys.Create(name, expires);
                key.Categories = categories.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                key.Secrets = secrets.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                key.AllowGet = allowGet;
                key.Scope = everything ? KeyScope.All : KeyScope.Selected;
                c.Config.AccessKeys.Add(key);
                c.Config.Save();

                if (addToClaude)
                {
                    await ClaudeCode.RegisterAsync(SelfPath, token);
                    Terminal.Info($"Created '{name}' and added Keylo to Claude Code (user scope) with it. Restart Claude Code, or run /mcp, to load it.");
                    return 0;
                }

                Terminal.Info($"Created '{name}'. This is the only time the key is shown:");
                Console.WriteLine(token);
                Terminal.Info("Register it with Claude Code (user scope; never put it in a project's .mcp.json):");
                Terminal.Info($"  claude mcp add {ClaudeCode.ServerName} --scope user --env {AccessKeys.EnvironmentVariable}={token} -- \"{SelfPath}\" mcp");
                return 0;
            }

            case "revoke" or "rm" or "delete":
            {
                var which = args.Positional(1, "key name or id");
                args.ThrowOnUnknown(maxPositionals: 2);
                var key = c.Config.AccessKeys.FirstOrDefault(k => k.Id == which || k.Name.Equals(which, StringComparison.OrdinalIgnoreCase))
                          ?? throw new KeyloException($"No access key '{which}'. See 'keylo keys'.");

                await c.Gate.ConfirmAsync(IntPtr.Zero, $"Keylo: revoke access key '{key.Name}'");
                c.Config.AccessKeys.Remove(key);
                c.Config.Save();
                Terminal.Info($"Revoked '{key.Name}'. Anything still using it now gets {Platform.VerifierName} prompts or approval requests.");
                return 0;
            }

            default:
                throw new UsageException("Usage: keylo keys [list | create NAME ... | revoke NAME]");
        }
    }

    private static async Task<int> UnlockAsync(Context c, Args args)
    {
        args.ThrowOnUnknown();
        if (c.Gate.Mode == HelloMode.Never)
        {
            Terminal.Info($"{Platform.VerifierName} is off (hello = never); nothing to unlock.");
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
            HelloMode.Never => $"no {Platform.VerifierName} prompt (hello = never)",
            HelloMode.Always => $"{Platform.VerifierName} on every value access (hello = always)",
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
            Console.WriteLine($"audit-days        {(c.Config.AuditRetentionDays == 0 ? "forever" : c.Config.AuditRetentionDays)}");
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
            case "audit-days":
                c.Config.AuditRetentionDays = value.Equals("forever", StringComparison.OrdinalIgnoreCase) ? 0
                    : int.TryParse(value, out var days) && days >= 0 ? days : throw new UsageException("Expected a number of days, or forever.");
                break;
            default:
                throw new UsageException("Settings: hello, session-minutes, clipboard-seconds, audit-days.");
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
        var psi = new ProcessStartInfo(SelfPath) { UseShellExecute = false, CreateNoWindow = true };
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
