#if DEBUG
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Keylo.App.ViewModels;

namespace Keylo.Desktop;

/// <summary>
/// Debug builds only: KEYLO_SNAPSHOTS="home=a.png;select:NAME=b.png;settings=c.png" drives the window
/// through those states, renders each to a PNG, then quits. For checking the UI where no screen
/// capture is available (e.g. over SSH on a Mac). Use it with a throwaway KEYLO_HOME / KEYLO_PREFIX.
/// </summary>
internal static class Snapshots
{
    public static async Task RunAsync(Window window, MainViewModel vm, string spec)
    {
        foreach (var part in spec.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var at = part.LastIndexOf('=');
            if (at <= 0) continue;
            var (action, file) = (part[..at], part[(at + 1)..]);
            await ApplyAsync(vm, action);
            await Task.Delay(500);
            Render(window, file);
        }
        window.Close();
    }

    private static async Task ApplyAsync(MainViewModel vm, string action)
    {
        var (verb, arg) = action.IndexOf(':') is var i and > 0 ? (action[..i], action[(i + 1)..]) : (action, "");
        switch (verb)
        {
            case "home":
                vm.CloseSettingsCommand.Execute(null);
                vm.SelectedCategory = vm.Categories[0];
                break;
            case "all":
                vm.CloseSettingsCommand.Execute(null);
                vm.SelectedCategory = vm.Categories.First(c => c.Key is null);
                break;
            case "search":
                vm.SearchText = arg;
                break;
            case "select" or "edit" or "reveal":
                vm.CloseSettingsCommand.Execute(null);
                vm.SelectedCategory = vm.Categories.First(c => c.Key is null);
                vm.SelectedSecret = vm.VisibleSecrets.First(s => s.Name.Equals(arg, StringComparison.OrdinalIgnoreCase));
                if (verb == "edit") await vm.Detail!.EditCommand.ExecuteAsync(null);
                if (verb == "reveal") await vm.Detail!.ToggleValueCommand.ExecuteAsync(null);
                break;
            case "new":
                vm.NewSecretCommand.Execute(null);
                break;
            case "settings":
                vm.OpenSettingsCommand.Execute(null);
                break;
            case "categories":
                vm.OpenCategoryManagerCommand.Execute(null);
                break;
            case "lock":
                vm.LockCommand.Execute(null);
                break;
            case "light" or "dark":
                Application.Current!.RequestedThemeVariant = verb == "light" ? Avalonia.Styling.ThemeVariant.Light : Avalonia.Styling.ThemeVariant.Dark;
                break;
        }
    }

    private static void Render(Window window, string file)
    {
        var scale = window.RenderScaling;
        var size = new PixelSize((int)(window.Bounds.Width * scale), (int)(window.Bounds.Height * scale));
        using var bitmap = new RenderTargetBitmap(size, new Vector(96 * scale, 96 * scale));
        bitmap.Render(window);
        bitmap.Save(file);
    }
}
#endif
