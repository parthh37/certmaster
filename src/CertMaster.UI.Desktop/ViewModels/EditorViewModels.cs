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
        RebuildParameters(model.Parameters);
    }

    public string[] ChallengeTypeOptions { get; } = { ChallengeTypes.Http01, ChallengeTypes.Dns01 };

    [ObservableProperty] private string _challengeType;
    [ObservableProperty] private string? _providerId;
    [ObservableProperty] private string? _credentialKey;
    [ObservableProperty] private string? _domainMatch;
    [ObservableProperty] private string? _delegationRule;
    [ObservableProperty] private string? _propagationDelay;
    [ObservableProperty] private List<ParameterViewModel> _parameters = new();

    public List<ChallengeProviderDefinition> Providers => _catalog.ChallengeProviders.Where(p => p.ChallengeType == ChallengeType).ToList();
    private ChallengeProviderDefinition? Provider => _catalog.ChallengeProviders.FirstOrDefault(p => p.Id == ProviderId);
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
        Parameters = Definition == null ? new() : ParameterViewModel.Build(Definition.ProviderParameters, model.Parameters);
    }

    public DeploymentProviderDefinition? Definition => _catalog.DeploymentProviders.FirstOrDefault(p => p.Id == Model.TaskTypeId);
    public string TypeTitle => Definition?.Title ?? Model.TaskTypeId;
    public string? LastResult => Model.LastResult == null ? null : $"Last run {Model.DateLastExecuted?.ToLocalTime():g}: {Model.LastRunStatus} - {Model.LastResult}";
    public List<ParameterViewModel> Parameters { get; }
    public List<StoredCredential> Credentials => _catalog.Credentials.Where(c => c.ProviderType == Definition?.CredentialType).ToList();
    public bool NeedsCredential => Definition?.CredentialType != null;
    public TaskTriggerType[] TriggerOptions { get; } = Enum.GetValues<TaskTriggerType>();

    [ObservableProperty] private string _taskName;
    [ObservableProperty] private TaskTriggerType _trigger;
    [ObservableProperty] private string? _credentialKey;
    [ObservableProperty] private bool _isFatalOnError;

    public DeploymentTaskConfig ToModel()
    {
        Model.TaskName = TaskName;
        Model.TaskTrigger = Trigger;
        Model.ChallengeCredentialKey = CredentialKey;
        Model.IsFatalOnError = IsFatalOnError;
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
        _domainsText = string.Join(Environment.NewLine, item.GetAllDomains());
        Challenges = new(item.RequestConfig.Challenges.Select(c => new ChallengeConfigViewModel(c, catalog)));
        Tasks = new(item.PostRequestTasks.Select(t => new DeploymentTaskViewModel(t, catalog)));
    }

    public ManagedCertificate Item { get; }
    public bool IsNew => Item.DateLastRenewalAttempt == null && Item.DateExpiry == null;
    public List<CertificateAuthority> Authorities => _catalog.Authorities;
    public List<DeploymentProviderDefinition> DeploymentProviders => _catalog.DeploymentProviders;
    public ObservableCollection<ChallengeConfigViewModel> Challenges { get; }
    public ObservableCollection<DeploymentTaskViewModel> Tasks { get; }
    public string[] KeyTypes { get; } = { "RS256", "RS256-3072", "RS256-4096", "ES256", "ES384" };

    [ObservableProperty] private string _domainsText;
    [ObservableProperty] private DeploymentProviderDefinition? _newTaskType;

    public string Summary => Item.DateExpiry == null
        ? "No certificate has been issued yet."
        : $"Valid {Item.DateStart?.ToLocalTime():d} to {Item.DateExpiry?.ToLocalTime():d}  |  {Item.CertificateIssuer}  |  {Item.CertificateThumbprintHash}";

    [RelayCommand]
    private void AddChallenge() => Challenges.Add(new ChallengeConfigViewModel(new CertRequestChallengeConfig { ChallengeProvider = "HTTP01.BuiltIn" }, _catalog));

    [RelayCommand]
    private void RemoveChallenge(ChallengeConfigViewModel c) { if (Challenges.Count > 1) Challenges.Remove(c); }

    [RelayCommand]
    private void AddTask()
    {
        if (NewTaskType == null) return;
        Tasks.Add(new DeploymentTaskViewModel(new DeploymentTaskConfig { TaskTypeId = NewTaskType.Id, TaskName = NewTaskType.DefaultTitle }, _catalog));
        NewTaskType = null;
    }

    [RelayCommand]
    private void RemoveTask(DeploymentTaskViewModel t) => Tasks.Remove(t);

    public ManagedCertificate ToModel()
    {
        var domains = DomainsText.Split(new[] { '\r', '\n', ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries).Select(d => d.Trim()).ToList();
        Item.RequestConfig.PrimaryDomain = domains.FirstOrDefault() ?? "";
        Item.RequestConfig.SubjectAlternativeNames = domains.Skip(1).ToList();
        Item.RequestConfig.Challenges = Challenges.Select(c => c.ToModel()).ToList();
        Item.PostRequestTasks = Tasks.Select(t => t.ToModel()).ToList();
        return Item;
    }
}
