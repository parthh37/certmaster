using System.Diagnostics;
using System.Windows.Navigation;
using MahApps.Metro.Controls;

namespace CertMaster.UI.Desktop;

public partial class MainWindow : MetroWindow
{
    public MainWindow() => InitializeComponent();

    private void OnNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }
}
