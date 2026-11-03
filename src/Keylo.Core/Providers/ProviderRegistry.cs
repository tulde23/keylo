using System.Reflection;
using System.Runtime.Loader;

namespace Keylo.Core.Providers;

public sealed record ProviderLoadError(string Path, string Message);

/// <summary>Built-in providers plus any found in the plugins folder.</summary>
public sealed class ProviderRegistry
{
    private readonly Dictionary<string, IVaultProvider> _providers = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<ProviderLoadError> LoadErrors { get; }

    public ProviderRegistry(string? dataDirectory = null)
    {
        Add(new OnePasswordProvider());

        var errors = new List<ProviderLoadError>();
        var pluginDirectory = Path.Combine(dataDirectory ?? KeyloPaths.DefaultDataDirectory, "plugins");
        if (Directory.Exists(pluginDirectory))
        {
            foreach (var dll in Directory.EnumerateFiles(pluginDirectory, "*.dll"))
            {
                try
                {
                    var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(dll);
                    foreach (var type in assembly.GetExportedTypes()
                                 .Where(t => t is { IsClass: true, IsAbstract: false } &&
                                             typeof(IVaultProvider).IsAssignableFrom(t) &&
                                             t.GetConstructor(Type.EmptyTypes) is not null))
                    {
                        var provider = (IVaultProvider)Activator.CreateInstance(type)!;
                        if (_providers.ContainsKey(provider.Id))
                            errors.Add(new ProviderLoadError(dll, $"Provider id '{provider.Id}' is already registered."));
                        else
                            Add(provider);
                    }
                }
                catch (Exception ex) when (ex is BadImageFormatException or FileLoadException or ReflectionTypeLoadException
                                               or TargetInvocationException or MissingMethodException)
                {
                    errors.Add(new ProviderLoadError(dll, ex.Message));
                }
            }
        }

        LoadErrors = errors;
    }

    public IReadOnlyList<IVaultProvider> All => _providers.Values.OrderBy(p => p.DisplayName).ToList();

    public IVaultProvider? Find(string id) => _providers.GetValueOrDefault(id);

    private void Add(IVaultProvider provider) => _providers[provider.Id] = provider;
}
