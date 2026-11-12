using System.Windows;
using System.Windows.Controls;
using CertMaster.UI.Desktop.ViewModels;

namespace CertMaster.UI.Desktop.Views;

public partial class CertificateEditorView : UserControl
{
    public CertificateEditorView() => InitializeComponent();

    /// <summary>When the user picks a website, load its binding hostnames as domain options.</summary>
    private void OnSiteChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.AddedItems.Count == 0 || !((ComboBox)sender).IsDropDownOpen && !((ComboBox)sender).IsKeyboardFocusWithin) return;
        if (Window.GetWindow(this)?.DataContext is MainViewModel vm) vm.SiteSelectedCommand.Execute(null);
    }
}
