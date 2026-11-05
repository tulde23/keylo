using System.Globalization;
using Avalonia.Data.Converters;
using Keylo.App.Services;

namespace Keylo.Desktop.Views;

/// <summary>Text that names the platform's verifier ("Touch ID", "Windows Hello"), for x:Static in XAML.</summary>
public static class Labels
{
    public static string AskFor => $"Ask for {Ui.Verifier}";
    public static string AuditHeading => $"AUDIT LOG — ACCESS WITHOUT {Ui.Verifier.ToUpperInvariant()}";
    public static string AuditEmpty => $"No access without {Ui.Verifier} yet.";
    public static string AuditRetention => $"Older entries are removed as new ones are added. The log records every use that skipped {Ui.Verifier}.";
    public static string AccessKeysIntro =>
        $"One key per agent or tool (Keylo's MCP server, or KEYLO_ACCESS_KEY for the CLI): what it can use without {Ui.Verifier}. " +
        "Secrets outside a key's scope ask you first. By default a key can only pass secrets to commands, so values don't end up in an AI conversation.";
    public static string KeysShownOnce =>
        $"New key creates a key right away (after {Ui.Verifier}) and shows it once, with the command to add it to Claude Code. " +
        "Then choose what it can use without asking and Save settings. Keylo keeps only a hash; delete a key to revoke it.";
    public static string BackupIntro =>
        "One .keylo file with every secret, category and icon, encrypted with AES-256-GCM under your password. " +
        (OperatingSystem.IsMacOS() ? "It works on any Mac or PC, unlike the keychain." : "It works on any PC or Windows account, unlike Keylo's normal storage.");

    /// <summary>The settings footer: what saving asks for, or that there are unsaved changes.</summary>
    public static readonly IValueConverter SaveHint = new FuncValueConverter<bool, string>(dirty => dirty
        ? $"Unsaved changes — Save settings to apply them (asks for {Ui.Verifier})."
        : $"Saving asks for {Ui.Verifier}, because these settings decide what can skip it.");
}

/// <summary>double ↔ decimal, for NumericUpDown.</summary>
public sealed class DecimalConverter : IValueConverter
{
    public static readonly DecimalConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is double d ? (decimal)d : null;

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is decimal m ? (double)m : 0d;
}
