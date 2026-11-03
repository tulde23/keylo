using System.IO;
using System.Text.Json;
using Keylo.Core;

namespace Keylo.App.Services;

/// <summary>Window layout remembered between runs (ui.json). Purely cosmetic, so failures are ignored.</summary>
public sealed class UiState
{
    private static readonly string FilePath = Path.Combine(KeyloPaths.DefaultDataDirectory, "ui.json");

    public double SidebarWidth { get; set; } = 232;
    public double ListWidth { get; set; } = 340;

    public static UiState Load()
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
