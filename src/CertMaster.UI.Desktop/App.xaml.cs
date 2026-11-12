using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using CertMaster.Client;
using CertMaster.Models;
using CertMaster.UI.Desktop.ViewModels;

namespace CertMaster.UI.Desktop;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        AgentClient client;
        try
        {
            client = AgentClient.CreateLocal();
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("CertMaster must be run as Administrator to connect to the local CertMaster Agent service.", "CertMaster", MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(1); return;
        }
        catch (Exception ex)
        {
            MessageBox.Show("Could not connect to the CertMaster Agent service.\n\n" + ex.Message, "CertMaster", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1); return;
        }

        var vm = new MainViewModel(client);
        var window = new MainWindow { DataContext = vm };
        MainWindow = window;
        window.Show();
        await vm.InitializeAsync();
    }
}

public class HealthToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        ManagedCertificateHealth.OK => Brushes.SeaGreen,
        ManagedCertificateHealth.Warning => Brushes.DarkOrange,
        ManagedCertificateHealth.Error => Brushes.Firebrick,
        _ => Brushes.Gray,
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
