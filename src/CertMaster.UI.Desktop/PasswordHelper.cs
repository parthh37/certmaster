using System.Windows;
using System.Windows.Controls;

namespace CertMaster.UI.Desktop;

/// <summary>Allows binding a PasswordBox's password (PasswordBox.Password is not a dependency property).</summary>
public static class PasswordHelper
{
    public static readonly DependencyProperty BoundPasswordProperty = DependencyProperty.RegisterAttached(
        "BoundPassword", typeof(string), typeof(PasswordHelper),
        new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.BindsTwoWayByDefault, OnBoundPasswordChanged));

    private static readonly DependencyProperty IsUpdatingProperty =
        DependencyProperty.RegisterAttached("IsUpdating", typeof(bool), typeof(PasswordHelper));

    public static string GetBoundPassword(DependencyObject d) => (string)d.GetValue(BoundPasswordProperty);
    public static void SetBoundPassword(DependencyObject d, string value) => d.SetValue(BoundPasswordProperty, value);

    private static void OnBoundPasswordChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not PasswordBox box) return;
        box.PasswordChanged -= OnPasswordChanged;
        if (!(bool)box.GetValue(IsUpdatingProperty)) box.Password = (string?)e.NewValue ?? "";
        box.PasswordChanged += OnPasswordChanged;
    }

    private static void OnPasswordChanged(object sender, RoutedEventArgs e)
    {
        var box = (PasswordBox)sender;
        box.SetValue(IsUpdatingProperty, true);
        SetBoundPassword(box, box.Password);
        box.SetValue(IsUpdatingProperty, false);
    }
}
