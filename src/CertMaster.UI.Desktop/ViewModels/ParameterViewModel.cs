using CertMaster.Models;
using CommunityToolkit.Mvvm.ComponentModel;

namespace CertMaster.UI.Desktop.ViewModels;

/// <summary>One dynamic provider field (text, password, checkbox, select, multiline).</summary>
public partial class ParameterViewModel : ObservableObject
{
    public ParameterViewModel(ProviderParameter def, string? value)
    {
        Definition = def;
        _value = value ?? def.Value;
        Options = def.GetOptions().ToList();
    }

    public ProviderParameter Definition { get; }
    public string Key => Definition.Key;
    public string Name => Definition.Name + (Definition.IsRequired ? " *" : "");
    public string? Description => Definition.Description;
    public OptionType Type => Definition.Type;
    public List<KeyValuePair<string, string>> Options { get; }

    [ObservableProperty] private string? _value;

    public bool BoolValue
    {
        get => Value == "true";
        set { Value = value ? "true" : "false"; OnPropertyChanged(); }
    }

    public static List<ParameterViewModel> Build(IEnumerable<ProviderParameter> defs, IEnumerable<ProviderParameterSetting> settings, bool includeCredentialFields = false) =>
        defs.Where(d => includeCredentialFields || !d.IsCredential)
            .Select(d => new ParameterViewModel(d, settings.FirstOrDefault(s => s.Key == d.Key)?.Value))
            .ToList();

    public static List<ProviderParameterSetting> ToSettings(IEnumerable<ParameterViewModel> vms) =>
        vms.Select(v => new ProviderParameterSetting(v.Key, v.Value)).ToList();
}
