using System.Runtime.CompilerServices;

namespace Keylo.Core.Tests;

/// <summary>The tests run against the real Windows platform (Credential Manager under a test prefix, DPAPI).</summary>
internal static class PlatformSetup
{
    [ModuleInitializer]
    internal static void Install() => Keylo.Platform.Windows.WindowsPlatform.Install();
}
