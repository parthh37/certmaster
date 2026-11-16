using System.Windows;
using CertMaster.Models;
using CertMaster.UI.Desktop.ViewModels;
using MahApps.Metro.Controls;

namespace CertMaster.UI.Desktop.Views;

/// <summary>Adds a stored credential of one fixed type, opened from a credential picker in the certificate editor.</summary>
public partial class CredentialEditorWindow : MetroWindow
{
    private readonly CredentialTypeDefinition _type;
    private readonly List<ParameterViewModel> _fields;

    public string CredentialTitle { get; private set; } = "";
    public Dictionary<string, string> Values { get; private set; } = new();

    public CredentialEditorWindow(CredentialTypeDefinition type)
    {
        InitializeComponent();
        _type = type;
        Heading.Text = "New " + type.Title + " credential";
        TitleBox.Text = type.Title;
        _fields = ParameterViewModel.Build(type.Fields, Array.Empty<ProviderParameterSetting>(), true);
        Fields.ItemsSource = _fields;
        Loaded += (_, _) => { TitleBox.Focus(); TitleBox.SelectAll(); };
    }

    /// <summary>Non-empty field values, or an error message when the input is incomplete.</summary>
    public static (Dictionary<string, string> Values, string? Error) Validate(CredentialTypeDefinition type, IEnumerable<ParameterViewModel> fields)
    {
        var values = fields.Where(f => !string.IsNullOrWhiteSpace(f.Value)).ToDictionary(f => f.Key, f => f.Value!.Trim());
        var missing = type.Fields.Where(f => f.IsRequired && !values.ContainsKey(f.Key)).Select(f => f.Name).ToList();
        if (missing.Count > 0) return (values, "Fill in: " + string.Join(", ", missing) + ".");
        if (values.Count == 0) return (values, "Enter at least one value.");
        return (values, null);
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        var (values, error) = Validate(_type, _fields);
        if (error != null)
        {
            Error.Text = error;
            Error.Visibility = Visibility.Visible;
            return;
        }
        CredentialTitle = string.IsNullOrWhiteSpace(TitleBox.Text) ? _type.Title : TitleBox.Text.Trim();
        Values = values;
        DialogResult = true;
    }
}
