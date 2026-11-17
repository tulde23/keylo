#if DEBUG
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Avalonia.VisualTree;
using Keylo.App.ViewModels;

namespace Keylo.Desktop;

/// <summary>
/// Debug builds only: KEYLO_SNAPSHOTS="home=a.png;select:NAME=b.png;settings=c.png;tab:4=d.png;scroll:1200=e.png" drives the window
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
            await ApplyAsync(window, vm, action);
            await Task.Delay(500);
            Render(window, file);
        }
        window.Close();
    }

    private static async Task ApplyAsync(Window window, MainViewModel vm, string action)
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
            case "settings": // settings, or settings:TAB to open on a tab
                vm.OpenSettingsCommand.Execute(null);
                if (arg.Length > 0)
                {
                    await Task.Delay(300);
                    if (window.GetVisualDescendants().OfType<TabControl>().FirstOrDefault() is { } settingsTabs)
                        settingsTabs.SelectedIndex = int.Parse(arg, System.Globalization.CultureInfo.InvariantCulture);
                }
                break;
            case "tab": // tab:INDEX, a settings tab (0 General, 1 Themes, … 4 Vault providers)
                if (window.GetVisualDescendants().OfType<TabControl>().FirstOrDefault() is { } tabs)
                    tabs.SelectedIndex = int.Parse(arg, System.Globalization.CultureInfo.InvariantCulture);
                break;
            case "scroll": // scroll:PIXELS, the open settings page
                if (window.GetVisualDescendants().OfType<Views.SettingsView>().SelectMany(v => v.GetVisualDescendants().OfType<ScrollViewer>()).FirstOrDefault() is { } viewer)
                    viewer.Offset = new Vector(0, double.Parse(arg, System.Globalization.CultureInfo.InvariantCulture));
                break;
            case "categories":
                vm.OpenCategoryManagerCommand.Execute(null);
                break;
            case "lock":
                vm.LockCommand.Execute(null);
                break;
            case "theme": // theme:twilight | quietviolet | aurora, keeping the current light/dark
                Keylo.App.Services.Ui.Host.ApplyTheme(Keylo.App.Services.Themes.ParseName(arg),
                    Application.Current!.ActualThemeVariant == Avalonia.Styling.ThemeVariant.Light ? Keylo.App.Services.ThemeMode.Light : Keylo.App.Services.ThemeMode.Dark);
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
