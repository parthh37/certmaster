using System.Windows;
using System.Windows.Threading;
using CertMaster.Client;
using CertMaster.UI.Desktop.ViewModels;

namespace CertMaster.UI.Desktop;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;

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
            MessageBox.Show("Could not connect to the CertMaster Agent service.\n\n" + ex.Message +
                            "\n\nCheck that the 'CertMaster Agent' Windows service is installed and running.", "CertMaster", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1); return;
        }

        var vm = new MainViewModel(client);
        var window = new MainWindow { DataContext = vm };
        MainWindow = window;
        window.Show();
        await vm.InitializeAsync();
    }

    /// <summary>Keep the app alive on unexpected UI errors (e.g. agent restarted mid-call) and tell the user.</summary>
    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.GetBaseException().Message, "CertMaster", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
