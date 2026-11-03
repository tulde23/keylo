using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Keylo.App;

/// <summary>Visible when the value is true / non-null / non-empty; "Invert" flips it.</summary>
public sealed class VisibleWhenConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var truthy = value switch
        {
            bool b => b,
            string s => s.Length > 0,
            int i => i > 0,
            null => false,
            _ => true,
        };
        return truthy ^ Invert ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}

/// <summary>Shows HelloMode values as friendly text in the settings combo box.</summary>
public sealed class HelloModeTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        Core.HelloMode.Session => "Once per session",
        Core.HelloMode.Always => "Every time a value is revealed or used",
        Core.HelloMode.Never => "Never (Windows sign-in only)",
        _ => value?.ToString() ?? "",
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
