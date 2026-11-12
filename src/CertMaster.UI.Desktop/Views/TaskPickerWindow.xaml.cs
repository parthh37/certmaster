using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CertMaster.Models;
using MahApps.Metro.Controls;

namespace CertMaster.UI.Desktop.Views;

public partial class TaskPickerWindow : MetroWindow
{
    private readonly List<DeploymentProviderDefinition> _all;
    public DeploymentProviderDefinition? Selected { get; private set; }

    public TaskPickerWindow(List<DeploymentProviderDefinition> providers)
    {
        InitializeComponent();
        _all = providers.OrderBy(p => p.Title, StringComparer.OrdinalIgnoreCase).ToList();
        List.ItemsSource = _all;
        FilterBox.Focus();
    }

    private void OnFilter(object sender, TextChangedEventArgs e)
    {
        var f = FilterBox.Text.Trim();
        List.ItemsSource = f.Length == 0 ? _all
            : _all.Where(p => p.Title.Contains(f, StringComparison.OrdinalIgnoreCase) || (p.Description ?? "").Contains(f, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void OnSelect(object sender, RoutedEventArgs e)
    {
        Selected = (DeploymentProviderDefinition)((Button)sender).Tag;
        DialogResult = true;
    }

    private void OnDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (List.SelectedItem is DeploymentProviderDefinition d) { Selected = d; DialogResult = true; }
    }
}
