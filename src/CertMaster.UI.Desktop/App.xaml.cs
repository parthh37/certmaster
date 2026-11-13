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
        ThemeService.Initialize();
        // The start-up progress window must not end the app when it closes; the real main window takes over below.
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        AgentClient client;
        Window? progress = null;
        try
        {
            await AgentServiceStarter.EnsureRunningAsync(message => progress = ShowProgress(progress, message));
            client = AgentClient.CreateLocal();
        }
        catch (UnauthorizedAccessException)
        {
            progress?.Close();
            MessageBox.Show("CertMaster must be run as Administrator to connect to the local CertMaster Agent service.", "CertMaster", MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(1); return;
        }
        catch (AgentUnavailableException ex)
        {
            progress?.Close();
            MessageBox.Show("Could not connect to the CertMaster Agent service.\n\n" + ex.Message, "CertMaster", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1); return;
        }
        catch (Exception ex)
        {
            progress?.Close();
            MessageBox.Show("Could not connect to the CertMaster Agent service.\n\n" + ex.Message +
                            "\n\nCheck that the 'CertMaster Agent' Windows service is installed and running.", "CertMaster", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1); return;
        }

        var vm = new MainViewModel(client);
        var window = new MainWindow { DataContext = vm };
        MainWindow = window;
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        window.Show();
        progress?.Close();
        await vm.InitializeAsync();
    }

    /// <summary>A small status window shown only while the app starts or waits for the agent service.</summary>
    private static Window ShowProgress(Window? existing, string message)
    {
        if (existing?.Tag is System.Windows.Controls.TextBlock current) { current.Text = message; return existing; }
        var text = new System.Windows.Controls.TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
        var ring = new MahApps.Metro.Controls.ProgressRing { IsActive = true, Width = 28, Height = 28, Margin = new Thickness(0, 0, 16, 0) };
        var panel = new System.Windows.Controls.DockPanel { Margin = new Thickness(24, 16, 24, 24) };
        System.Windows.Controls.DockPanel.SetDock(ring, System.Windows.Controls.Dock.Left);
        panel.Children.Add(ring);
        panel.Children.Add(text);
        var window = new MahApps.Metro.Controls.MetroWindow
        {
            Title = "CertMaster",
            Width = 440,
            SizeToContent = SizeToContent.Height,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/certmaster.ico")),
            ShowMinButton = false,
            ShowMaxRestoreButton = false,
            Content = panel,
            Tag = text,
        };
        window.SetResourceReference(FrameworkElement.StyleProperty, "Cm.Window");
        window.Show();
        return window;
    }

    /// <summary>Keep the app alive on unexpected UI errors (e.g. agent restarted mid-call) and tell the user.</summary>
    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.GetBaseException().Message, "CertMaster", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
