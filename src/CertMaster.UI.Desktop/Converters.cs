using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using CertMaster.Models;

namespace CertMaster.UI.Desktop;

public class HealthToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        ManagedCertificateHealth.OK => new SolidColorBrush(Color.FromRgb(0x2E, 0x7D, 0x32)),
        ManagedCertificateHealth.Warning => new SolidColorBrush(Color.FromRgb(0xEF, 0x6C, 0x00)),
        ManagedCertificateHealth.Error => new SolidColorBrush(Color.FromRgb(0xC6, 0x28, 0x28)),
        _ => Brushes.Gray,
    };
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class HealthToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        ManagedCertificateHealth.OK => "OK",
        ManagedCertificateHealth.Warning => "Expiring / attention",
        ManagedCertificateHealth.Error => "Error",
        ManagedCertificateHealth.AwaitingUser => "Not yet requested",
        _ => "Unknown",
    };
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b ? !b : true;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => value is bool b ? !b : false;
}

/// <summary>Visible when the bound value equals the converter parameter (string compare).</summary>
public class EqualsToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.OrdinalIgnoreCase) ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>True when the bound value equals the parameter; used for section highlighting.</summary>
public class EqualsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.OrdinalIgnoreCase);
    // Checking a radio button selects its parameter; unchecking leaves the value as is.
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? parameter : Binding.DoNothing;
}

public class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value == null || (value is string s && s.Length == 0) || (value is System.Collections.ICollection c && c.Count == 0) ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public class RequestStateToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        RequestState.Success => new SolidColorBrush(Color.FromRgb(0x2E, 0x7D, 0x32)),
        RequestState.Error => new SolidColorBrush(Color.FromRgb(0xC6, 0x28, 0x28)),
        RequestState.Warning => new SolidColorBrush(Color.FromRgb(0xEF, 0x6C, 0x00)),
        _ => new SolidColorBrush(Color.FromRgb(0x15, 0x65, 0xC0)),
    };
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
