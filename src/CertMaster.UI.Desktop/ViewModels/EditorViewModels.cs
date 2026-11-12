using System.Collections.ObjectModel;
using CertMaster.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CertMaster.UI.Desktop.ViewModels;

/// <summary>Shared lookup data used by the editors.</summary>
public class Catalog
{
    public List<ChallengeProviderDefinition> ChallengeProviders { get; set; } = new();
    public List<DeploymentProviderDefinition> DeploymentProviders { get; set; } = new();
    public List<StoredCredential> Credentials { get; set; } = new();
    public List<CertificateAuthority> Authorities { get; set; } = new();
    public List<SiteInfo> Sites { get; set; } = new();
    public ServerStatus ServerStatus { get; set; } = new();
}

public record Choice<T>(T Value, string Title);

public static class Choices
{
    public static readonly List<Choice<DeploymentOption>> DeploymentModes = new()
    {
        new(DeploymentOption.Auto, "Auto"),
        new(DeploymentOption.SingleSite, "Single Site (selected on the Certificate tab)"),
        new(DeploymentOption.AllSites, "All Sites"),
        new(DeploymentOption.CertificateStoreOnly, "Certificate Store Only"),
        new(DeploymentOption.NoDeployment, "No Deployment"),
    };

    public static readonly List<Choice<DeploymentBindingOption>> BindingOptions = new()
    {
        new(DeploymentBindingOption.AddOrUpdate, "Add or update https bindings as required"),
        new(DeploymentBindingOption.UpdateOnly, "Update existing https bindings only"),
    };

    public static readonly List<Choice<TaskTriggerType>> Triggers = new()
    {
        new(TaskTriggerType.ON_SUCCESS, "Run on success"),
        new(TaskTriggerType.ON_ERROR, "Run on error"),
        new(TaskTriggerType.ANY_STATUS, "Run always"),
        new(TaskTriggerType.MANUAL, "Manual only"),
        new(TaskTriggerType.NOT_ENABLED, "Disabled"),
    };

    public static readonly Dictionary<DeploymentContextType, string> TargetTitles = new()
    {
        [DeploymentContextType.LocalAsService] = "Local (as the CertMaster service)",
        [DeploymentContextType.LocalAsUser] = "Local (as a specific Windows user)",
        [DeploymentContextType.WindowsNetwork] = "Windows network share (UNC)",
        [DeploymentContextType.SSH] = "Remote host via SSH / SFTP",
    };

    public static readonly List<Choice<string>> KeyTypes = new()
    {
        new("RS256", "RSA 2048"), new("RS256-3072", "RSA 3072"), new("RS256-4096", "RSA 4096"),
        new("ES256", "ECDSA P-256"), new("ES384", "ECDSA P-384"),
    };

    /// <summary>Key types for a certificate: blank follows the instance default from Settings.</summary>
    public static readonly List<Choice<string>> ItemKeyTypes = new[] { new Choice<string>("", "Instance default (Settings)") }.Concat(KeyTypes).ToList();

    public static readonly List<Choice<string>> RenewalModes = new()
    {
        new(RenewalIntervalModes.DaysBeforeExpiry, "A number of days before expiry"),
        new(RenewalIntervalModes.PercentageOfLifetime, "A percentage of the certificate lifetime"),
    };
}

public partial class DomainOptionViewModel : ObservableObject
{
    [ObservableProperty] private string _domain = "";
    [ObservableProperty] private bool _isSelected = true;
    [ObservableProperty] private bool _isPrimary;
    public string? Comment { get; init; }
}

public partial class ChallengeConfigViewModel : ObservableObject
{
    private readonly Catalog _catalog;
    public CertRequestChallengeConfig Model { get; }

    public ChallengeConfigViewModel(CertRequestChallengeConfig model, Catalog catalog)
    {
        Model = model; _catalog = catalog;
        _challengeType = model.ChallengeType;
        _providerId = model.ChallengeProvider ?? (model.ChallengeType == ChallengeTypes.Http01 ? "HTTP01.BuiltIn" : null);
        _credentialKey = model.ChallengeCredentialKey;
        _domainMatch = model.DomainMatch;
        _delegationRule = model.ChallengeDelegationRule;
        _propagationDelay = model.PropagationDelaySeconds?.ToString();
        _zoneId = model.ZoneId;
        RebuildParameters(model.Parameters);
    }

    public string[] ChallengeTypeOptions { get; } = { ChallengeTypes.Http01, ChallengeTypes.Dns01 };

    [ObservableProperty] private string _challengeType;
    [ObservableProperty] private string? _providerId;
    [ObservableProperty] private string? _credentialKey;
    [ObservableProperty] private string? _domainMatch;
    [ObservableProperty] private string? _delegationRule;
    [ObservableProperty] private string? _propagationDelay;
    [ObservableProperty] private string? _zoneId;
    [ObservableProperty] private List<ParameterViewModel> _parameters = new();

    public List<ChallengeProviderDefinition> Providers => _catalog.ChallengeProviders.Where(p => p.ChallengeType == ChallengeType).ToList();
    private ChallengeProviderDefinition? Provider => _catalog.ChallengeProviders.FirstOrDefault(p => p.Id == ProviderId);
    public string? ProviderDescription => Provider?.Description;
    public List<StoredCredential> Credentials => _catalog.Credentials.Where(c => c.ProviderType == Provider?.CredentialType).ToList();
    public bool NeedsCredential => Provider?.CredentialType != null;
    public bool IsDns => ChallengeType == ChallengeTypes.Dns01;

    partial void OnChallengeTypeChanged(string value)
    {
        ProviderId = value == ChallengeTypes.Http01 ? "HTTP01.BuiltIn" : Providers.FirstOrDefault()?.Id;
        OnPropertyChanged(nameof(Providers));
        OnPropertyChanged(nameof(IsDns));
    }

    partial void OnProviderIdChanged(string? value)
    {
        RebuildParameters(Model.Parameters);
        OnPropertyChanged(nameof(Credentials));
        OnPropertyChanged(nameof(NeedsCredential));
        OnPropertyChanged(nameof(ProviderDescription));
    }

    private void RebuildParameters(IEnumerable<ProviderParameterSetting> current) =>
        Parameters = Provider == null ? new() : ParameterViewModel.Build(Provider.ProviderParameters, current);

    public CertRequestChallengeConfig ToModel()
    {
        Model.ChallengeType = ChallengeType;
        Model.ChallengeProvider = ProviderId;
        Model.ChallengeCredentialKey = NeedsCredential ? CredentialKey : null;
        Model.DomainMatch = DomainMatch;
        Model.ChallengeDelegationRule = DelegationRule;
        Model.ZoneId = string.IsNullOrWhiteSpace(ZoneId) ? null : ZoneId;
        Model.PropagationDelaySeconds = int.TryParse(PropagationDelay, out var d) ? d : null;
        Model.Parameters = ParameterViewModel.ToSettings(Parameters);
        return Model;
    }
}

public partial class DeploymentTaskViewModel : ObservableObject
{
    private readonly Catalog _catalog;
    public DeploymentTaskConfig Model { get; }

    public DeploymentTaskViewModel(DeploymentTaskConfig model, Catalog catalog)
    {
        Model = model; _catalog = catalog;
        _taskName = model.TaskName;
        _trigger = model.TaskTrigger;
        _credentialKey = model.ChallengeCredentialKey;
        _isFatalOnError = model.IsFatalOnError;
        _runIfLastStepFailed = model.RunIfLastStepFailed;
        _retriesAllowed = model.RetriesAllowed;
        _targetType = model.TargetType;
        _targetHost = model.TargetHost;
        Parameters = Definition == null ? new() : ParameterViewModel.Build(Definition.ProviderParameters, model.Parameters);
    }

    public DeploymentProviderDefinition? Definition => _catalog.DeploymentProviders.FirstOrDefault(p => p.Id == Model.TaskTypeId);
    public string TypeTitle => Definition?.Title ?? Model.TaskTypeId;
    public string? LastResult => Model.LastResult == null ? null : $"Last run {Model.DateLastExecuted?.ToLocalTime():g}: {Model.LastRunStatus} - {Model.LastResult}";
    public List<ParameterViewModel> Parameters { get; }
    public List<Choice<TaskTriggerType>> TriggerOptions => Choices.Triggers;
    public List<Choice<DeploymentContextType>> TargetOptions =>
        (Definition?.SupportedTargets ?? new() { DeploymentContextType.LocalAsService })
        .Select(t => new Choice<DeploymentContextType>(t, Choices.TargetTitles[t])).ToList();
    public bool HasTargetChoice => TargetOptions.Count > 1;
    public bool IsSsh => TargetType == DeploymentContextType.SSH;

    /// <summary>Credentials applicable to the selected target, or to the provider for API based tasks.</summary>
    public List<StoredCredential> Credentials => _catalog.Credentials.Where(c => c.ProviderType == RequiredCredentialType).ToList();
    private string? RequiredCredentialType => TargetType switch
    {
        DeploymentContextType.SSH => "SSH",
        DeploymentContextType.WindowsNetwork or DeploymentContextType.LocalAsUser => "Windows",
        _ => Definition?.CredentialType,
    };
    public bool NeedsCredential => RequiredCredentialType != null;

    [ObservableProperty] private string _taskName;
    [ObservableProperty] private TaskTriggerType _trigger;
    [ObservableProperty] private string? _credentialKey;
    [ObservableProperty] private bool _isFatalOnError;
    [ObservableProperty] private bool _runIfLastStepFailed;
    [ObservableProperty] private int _retriesAllowed;
    [ObservableProperty] private DeploymentContextType _targetType;
    [ObservableProperty] private string? _targetHost;

    partial void OnTargetTypeChanged(DeploymentContextType value)
    {
        OnPropertyChanged(nameof(Credentials));
        OnPropertyChanged(nameof(NeedsCredential));
        OnPropertyChanged(nameof(IsSsh));
    }

    public DeploymentTaskConfig ToModel()
    {
        Model.TaskName = string.IsNullOrWhiteSpace(TaskName) ? (Definition?.DefaultTitle ?? "Task") : TaskName;
        Model.TaskTrigger = Trigger;
        Model.ChallengeCredentialKey = NeedsCredential ? CredentialKey : null;
        Model.IsFatalOnError = IsFatalOnError;
        Model.RunIfLastStepFailed = RunIfLastStepFailed;
        Model.RetriesAllowed = RetriesAllowed;
        Model.TargetType = TargetType;
        Model.TargetHost = IsSsh ? TargetHost : null;
        Model.Parameters = ParameterViewModel.ToSettings(Parameters);
        return Model;
    }
}

/// <summary>Editable copy of a managed certificate.</summary>
public partial class CertificateEditorViewModel : ObservableObject
{
    private readonly Catalog _catalog;

    public CertificateEditorViewModel(ManagedCertificate item, Catalog catalog)
    {
        Item = item; _catalog = catalog;
        _name = item.Name;
        _selectedSiteId = item.ServerSiteId;
        Domains = new(item.GetAllDomains().Select((d, i) => new DomainOptionViewModel { Domain = d, IsSelected = true, IsPrimary = i == 0 }));
        Challenges = new(item.RequestConfig.Challenges.Select(c => new ChallengeConfigViewModel(c, catalog)));
        Tasks = new(item.PostRequestTasks.Select(t => new DeploymentTaskViewModel(t, catalog)));
        PreRequestTasks = new(item.PreRequestTasks.Select(t => new DeploymentTaskViewModel(t, catalog)));
        _useSpecificBinding = item.RequestConfig.UseSpecificBindingIPPort;
        _ipText = string.Join(Environment.NewLine, item.RequestConfig.SubjectIPAddresses);
    }

    public ManagedCertificate Item { get; }
    public CertRequestConfig Config => Item.RequestConfig;
    public bool IsNew => Item.DateLastRenewalAttempt == null && Item.DateExpiry == null;
    public string Heading => string.IsNullOrWhiteSpace(Name) ? "New Managed Certificate" : Name;

    public List<CertificateAuthority> Authorities => _catalog.Authorities;
    public List<SiteInfo> Sites => _catalog.Sites;
    public bool IsIisAvailable => _catalog.ServerStatus.IsIisAvailable;
    public string ServerStatusText => _catalog.ServerStatus.IsIisAvailable
        ? $"IIS {_catalog.ServerStatus.IisVersion} detected"
        : _catalog.ServerStatus.Message ?? "IIS not detected: automatic binding deployment is unavailable, use deployment tasks.";
    public List<DeploymentProviderDefinition> DeploymentProviders => _catalog.DeploymentProviders;
    public List<Choice<DeploymentOption>> DeploymentModes => Choices.DeploymentModes;
    public List<Choice<DeploymentBindingOption>> BindingOptions => Choices.BindingOptions;
    public List<Choice<string>> KeyTypes => Choices.ItemKeyTypes;

    public ObservableCollection<DomainOptionViewModel> Domains { get; }
    public ObservableCollection<ChallengeConfigViewModel> Challenges { get; }
    public ObservableCollection<DeploymentTaskViewModel> Tasks { get; }
    public ObservableCollection<DeploymentTaskViewModel> PreRequestTasks { get; }
    public ObservableCollection<ActionStep> PreviewSteps { get; } = new();

    [ObservableProperty] private string _name;
    [ObservableProperty] private string? _selectedSiteId;
    [ObservableProperty] private string _addDomainsText = "";
    [ObservableProperty] private string _ipText;
    [ObservableProperty] private bool _useSpecificBinding;
    [ObservableProperty] private string _section = "Certificate";

    partial void OnNameChanged(string value) => OnPropertyChanged(nameof(Heading));

    public string Summary => Item.DateExpiry == null
        ? "No certificate has been issued yet."
        : $"Certificate valid {Item.DateStart?.ToLocalTime():d} to {Item.DateExpiry?.ToLocalTime():d}  ·  {Item.CertificateIssuer}  ·  {Item.CertificateKeyType}  ·  {Item.CertificateThumbprintHash}";

    [RelayCommand] private void ShowSection(string section) => Section = section;

    /// <summary>Merges hostnames from the selected site's bindings into the domain list.</summary>
    public void MergeSiteDomains(IEnumerable<DomainOption> options)
    {
        foreach (var o in options)
        {
            if (Domains.Any(d => d.Domain.Equals(o.Domain, StringComparison.OrdinalIgnoreCase))) continue;
            Domains.Add(new DomainOptionViewModel { Domain = o.Domain, IsSelected = o.IsSelected, Comment = o.Comment });
        }
        if (Domains.Count > 0 && !Domains.Any(d => d.IsPrimary)) Domains.First(d => d.IsSelected).IsPrimary = true;
        if (string.IsNullOrWhiteSpace(Name)) Name = Domains.FirstOrDefault(d => d.IsPrimary)?.Domain ?? "";
    }

    [RelayCommand]
    private void AddDomains()
    {
        foreach (var d in AddDomainsText.Split(new[] { '\r', '\n', ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim().ToLowerInvariant()))
        {
            if (Domains.Any(x => x.Domain == d)) continue;
            Domains.Add(new DomainOptionViewModel { Domain = d, IsSelected = true, IsPrimary = Domains.Count == 0 });
        }
        AddDomainsText = "";
        if (string.IsNullOrWhiteSpace(Name)) Name = Domains.FirstOrDefault(d => d.IsPrimary)?.Domain ?? "";
    }

    [RelayCommand]
    private void RemoveDomain(DomainOptionViewModel d)
    {
        Domains.Remove(d);
        if (d.IsPrimary && Domains.FirstOrDefault(x => x.IsSelected) is { } next) next.IsPrimary = true;
    }

    [RelayCommand]
    private void SetPrimary(DomainOptionViewModel d)
    {
        foreach (var x in Domains) x.IsPrimary = x == d;
        d.IsSelected = true;
    }

    [RelayCommand] private void AddChallenge() => Challenges.Add(new ChallengeConfigViewModel(new CertRequestChallengeConfig { ChallengeProvider = "HTTP01.BuiltIn" }, _catalog));
    [RelayCommand] private void RemoveChallenge(ChallengeConfigViewModel c) { if (Challenges.Count > 1) Challenges.Remove(c); }
    [RelayCommand] private void RemoveTask(DeploymentTaskViewModel t) { Tasks.Remove(t); PreRequestTasks.Remove(t); }

    public void AddTask(DeploymentProviderDefinition def, bool preRequest)
    {
        var vm = new DeploymentTaskViewModel(new DeploymentTaskConfig
        {
            TaskTypeId = def.Id, TaskName = def.DefaultTitle,
            TaskTrigger = preRequest ? TaskTriggerType.ANY_STATUS : TaskTriggerType.ON_SUCCESS,
        }, _catalog);
        (preRequest ? PreRequestTasks : Tasks).Add(vm);
    }

    public ManagedCertificate ToModel()
    {
        var selected = Domains.Where(d => d.IsSelected).ToList();
        var primary = selected.FirstOrDefault(d => d.IsPrimary) ?? selected.FirstOrDefault();
        Item.Name = Name?.Trim() ?? "";
        Item.ServerSiteId = string.IsNullOrEmpty(SelectedSiteId) ? null : SelectedSiteId;
        Item.RequestConfig.PrimaryDomain = primary?.Domain ?? "";
        Item.RequestConfig.SubjectAlternativeNames = selected.Where(d => d != primary).Select(d => d.Domain).ToList();
        Item.RequestConfig.SubjectIPAddresses = IpText.Split(new[] { '\r', '\n', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList();
        Item.RequestConfig.UseSpecificBindingIPPort = UseSpecificBinding;
        Item.RequestConfig.Challenges = Challenges.Select(c => c.ToModel()).ToList();
        Item.PostRequestTasks = Tasks.Select(t => t.ToModel()).ToList();
        Item.PreRequestTasks = PreRequestTasks.Select(t => t.ToModel()).ToList();
        return Item;
    }
}
