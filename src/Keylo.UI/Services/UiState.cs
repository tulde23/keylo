using System.IO;
using System.Text.Json;
using Keylo.Core;

namespace Keylo.App.Services;

/// <summary>Window layout and appearance remembered between runs (ui.json). Purely cosmetic, so failures are ignored.</summary>
public sealed class UiState
{
    private static readonly string FilePath = Path.Combine(KeyloPaths.DefaultDataDirectory, "ui.json");

    public double SidebarWidth { get; set; } = 232;
    public double ListWidth { get; set; } = 340;

    /// <summary>A <see cref="ThemeName"/> and <see cref="ThemeMode"/>, by name.</summary>
    public string Theme { get; set; } = Themes.DefaultTheme.ToString();
    public string Mode { get; set; } = nameof(ThemeMode.System);

    private static UiState? _current;

    /// <summary>The one instance for this process (the window and Settings share it, so neither saves over the other).</summary>
    public static UiState Load() => _current ??= Read();

    private static UiState Read()
    {
        try
        {
            return File.Exists(FilePath) ? JsonSerializer.Deserialize<UiState>(File.ReadAllText(FilePath)) ?? new UiState() : new UiState();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new UiState();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
