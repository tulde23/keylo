using System.Reflection;
using System.Runtime.Loader;

namespace Keylo.Core.Providers;

public sealed record ProviderLoadError(string Path, string Message);

/// <summary>
/// Built-in providers plus any found in the plugins folder: push providers (<see cref="IVaultProvider"/>)
/// and linked vaults (<see cref="ILinkedVaultProvider"/>). One class may be both.
/// </summary>
public sealed class ProviderRegistry
{
    private readonly Dictionary<string, IVaultProvider> _providers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ILinkedVaultProvider> _linked = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<ProviderLoadError> LoadErrors { get; }

    public ProviderRegistry(string? dataDirectory = null)
    {
        Add(new OnePasswordProvider());
        Add(new AwsSecretsManagerProvider());

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
                                             (typeof(IVaultProvider).IsAssignableFrom(t) || typeof(ILinkedVaultProvider).IsAssignableFrom(t)) &&
                                             t.GetConstructor(Type.EmptyTypes) is not null))
                    {
                        var instance = Activator.CreateInstance(type)!;
                        var id = (instance as IVaultProvider)?.Id ?? ((ILinkedVaultProvider)instance).Id;
                        if (_providers.ContainsKey(id) || _linked.ContainsKey(id))
                            errors.Add(new ProviderLoadError(dll, $"Provider id '{id}' is already registered."));
                        else
                            Add(instance);
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

    /// <summary>Vaults secrets can be linked to.</summary>
    public IReadOnlyList<ILinkedVaultProvider> Linked => _linked.Values.OrderBy(p => p.DisplayName).ToList();

    public ILinkedVaultProvider? FindLinked(string id) => _linked.GetValueOrDefault(id);

    /// <summary>Adds a provider object (push, linked, or both) — for hosts that bring their own, and tests.</summary>
    public void Register(object provider) => Add(provider);

    private void Add(object provider)
    {
        if (provider is IVaultProvider push) _providers[push.Id] = push;
        if (provider is ILinkedVaultProvider linked) _linked[linked.Id] = linked;
    }
}
