namespace Keylo.Core;

public static class KeyloPaths
{
    /// <summary>
    /// %LOCALAPPDATA%\Keylo, or KEYLO_HOME when set. Local (not Roaming) because DPAPI-encrypted
    /// files are only readable on the machine that wrote them.
    /// </summary>
    public static string DefaultDataDirectory =>
        Environment.GetEnvironmentVariable("KEYLO_HOME") is { Length: > 0 } home
            ? home
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Keylo");

    /// <summary>Uploaded icon images (icons\{hash}.png), referenced from secrets and categories as "img{hash}".</summary>
    public static string IconDirectory => Path.Combine(DefaultDataDirectory, "icons");

    /// <summary>Credential Manager target prefix: "Keylo:", or KEYLO_PREFIX when set (tests use a separate one).</summary>
    public static string CredentialPrefix =>
        Environment.GetEnvironmentVariable("KEYLO_PREFIX") is { Length: > 0 } prefix ? prefix : SecretStore.DefaultPrefix;
}
