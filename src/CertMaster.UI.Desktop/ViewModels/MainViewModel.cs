using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using CertMaster.Client;
using CertMaster.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace CertMaster.UI.Desktop.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly AgentClient _client;
    public Catalog Catalog { get; } = new();
    public AgentClient Client => _client;

    public MainViewModel(AgentClient client)
    {
        _client = client;
        _client.ProgressReceived += s => Ui(() => OnProgress(s));
        _client.ManagedCertificateUpdated += i => Ui(() => OnItemUpdated(i));
        _client.ConnectionStateChanged += s => Ui(() => ConnectionState = s);
    }

    private static void Ui(Action a) => Application.Current?.Dispatcher.Invoke(a);

    public ObservableCollection<ManagedCertificate> Items { get; } = new();
    public ObservableCollection<string> Progress { get; } = new();
    public ObservableCollection<ActionStep> TestResults { get; } = new();
    public ObservableCollection<LogEntry> Log { get; } = new();

    [ObservableProperty] private ManagedCertificate? _selectedItem;
    [ObservableProperty] private CertificateEditorViewModel? _editor;
    [ObservableProperty] private string _statusText = "Connecting...";
    [ObservableProperty] private string _connectionState = "Connecting";
    [ObservableProperty] private string? _search;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _version = "";

    public async Task InitializeAsync()
    {
        try
        {
            var v = await _client.GetVersionAsync();
            Version = $"CertMaster {v.Version} on {v.Hostname}";
            await _client.ConnectStatusAsync();
            await ReloadCatalogAsync();
            await RefreshAsync();
            if (Catalog.Authorities.Count > 0 && (await _client.GetAccountsAsync()).Count == 0)
                StatusText = "No ACME account yet: open Settings > Certificate Authorities to register one.";
        }
        catch (Exception ex) { StatusText = "Agent connection failed: " + ex.Message; }
    }

    public async Task ReloadCatalogAsync()
    {
        Catalog.ChallengeProviders = await _client.GetChallengeProvidersAsync();
        Catalog.DeploymentProviders = await _client.GetDeploymentProvidersAsync();
        Catalog.Credentials = await _client.GetCredentialsAsync();
        Catalog.Authorities = await _client.GetCertificateAuthoritiesAsync();
    }

    partial void OnSelectedItemChanged(ManagedCertificate? value)
    {
        TestResults.Clear();
        Editor = value == null ? null : new CertificateEditorViewModel(JsonDefaults.Clone(value), Catalog);
        _ = LoadLogAsync();
    }

    partial void OnSearchChanged(string? value) => _ = RefreshAsync();

    [RelayCommand]
    private async Task RefreshAsync()
    {
        try
        {
            var selectedId = SelectedItem?.Id;
            var items = await _client.GetManagedCertificatesAsync(Search);
            Items.Clear();
            foreach (var i in items) Items.Add(i);
            if (selectedId != null) SelectedItem = Items.FirstOrDefault(i => i.Id == selectedId);
            StatusText = $"{Items.Count} managed certificate(s)";
        }
        catch (Exception ex) { StatusText = ex.Message; }
    }

    [RelayCommand]
    private void New()
    {
        var item = new ManagedCertificate { Name = "", CertificateAuthorityId = Catalog.Authorities.FirstOrDefault()?.Id };
        SelectedItem = null;
        Editor = new CertificateEditorViewModel(item, Catalog);
        Log.Clear();
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        if (Editor == null) return;
        IsBusy = true;
        try
        {
            var r = await _client.UpdateManagedCertificateAsync(Editor.ToModel());
            StatusText = r.Message ?? "";
            if (!r.IsSuccess) { MessageBox.Show(r.Message, "Save", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
            await RefreshAsync();
            SelectedItem = Items.FirstOrDefault(i => i.Id == r.Result!.Id);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error); }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task TestAsync()
    {
        if (Editor == null) return;
        IsBusy = true; TestResults.Clear(); StatusText = "Testing configuration...";
        try
        {
            foreach (var s in await _client.TestConfigurationAsync(Editor.ToModel())) TestResults.Add(s);
            StatusText = TestResults.Any(t => t.HasError) ? "Test found problems" : "Test passed";
        }
        catch (Exception ex) { StatusText = ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RequestAsync()
    {
        if (SelectedItem == null) { MessageBox.Show("Save the certificate first."); return; }
        Progress.Clear();
        try
        {
            var r = await _client.BeginCertificateRequestAsync(SelectedItem.Id);
            StatusText = r.Message ?? "";
        }
        catch (Exception ex) { StatusText = ex.Message; }
    }

    [RelayCommand]
    private async Task DeleteAsync()
    {
        if (SelectedItem == null) return;
        if (MessageBox.Show($"Delete '{SelectedItem.Name}'?", "Delete", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await _client.DeleteManagedCertificateAsync(SelectedItem.Id);
        SelectedItem = null; Editor = null;
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task RevokeAsync()
    {
        if (SelectedItem == null) return;
        if (MessageBox.Show("Revoke this certificate with the CA? This cannot be undone.", "Revoke", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var r = await _client.RevokeCertificateAsync(SelectedItem.Id);
        MessageBox.Show(r.Message, "Revoke");
        await RefreshAsync();
    }

    [RelayCommand]
    private async Task RenewAllAsync()
    {
        var r = await _client.RenewAllAsync();
        StatusText = r.Message ?? "";
    }

    [RelayCommand]
    private async Task ExportAsync()
    {
        if (SelectedItem == null) return;
        var dlg = new SaveFileDialog { FileName = SelectedItem.Name.Replace("*", "_") + ".pfx", Filter = "PFX (*.pfx)|*.pfx|PEM full chain + key (*.pem)|*.pem" };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var format = dlg.FilterIndex == 2 ? CertificateDownloadFormat.pem_full : CertificateDownloadFormat.pfx;
            await File.WriteAllBytesAsync(dlg.FileName, await _client.DownloadCertificateAsync(SelectedItem.Id, format));
            StatusText = "Exported to " + dlg.FileName;
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Export failed"); }
    }

    [RelayCommand]
    private async Task RunTaskAsync(DeploymentTaskViewModel task)
    {
        if (SelectedItem == null) return;
        var r = await _client.PerformDeploymentTaskAsync(SelectedItem.Id, task.Model.Id, false);
        MessageBox.Show(r.Message, task.TaskName, MessageBoxButton.OK, r.IsSuccess ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    [RelayCommand]
    private async Task OpenSettingsAsync()
    {
        var win = new Views.SettingsWindow { Owner = Application.Current.MainWindow, DataContext = new SettingsViewModel(_client) };
        await ((SettingsViewModel)win.DataContext).LoadAsync();
        win.ShowDialog();
        await ReloadCatalogAsync();
        if (SelectedItem != null) Editor = new CertificateEditorViewModel(JsonDefaults.Clone(SelectedItem), Catalog);
    }

    private async Task LoadLogAsync()
    {
        Log.Clear();
        if (SelectedItem == null) return;
        try { foreach (var l in (await _client.GetItemLogAsync(SelectedItem.Id, 300)).AsEnumerable().Reverse()) Log.Add(l); } catch { /* ignore */ }
    }

    private void OnProgress(RequestProgressState s)
    {
        var name = Items.FirstOrDefault(i => i.Id == s.ManagedCertificateId)?.Name ?? s.ManagedCertificateId;
        Progress.Insert(0, $"{s.MessageCreated.ToLocalTime():HH:mm:ss}  {name}: {s.Message}");
        StatusText = $"{name}: {s.Message}";
        if (s.IsFinal && SelectedItem?.Id == s.ManagedCertificateId) _ = LoadLogAsync();
    }

    private void OnItemUpdated(ManagedCertificate item)
    {
        var idx = Items.ToList().FindIndex(i => i.Id == item.Id);
        if (idx < 0) return;
        var wasSelected = SelectedItem?.Id == item.Id;
        Items[idx] = item;
        if (wasSelected) SelectedItem = item;
    }
}

public partial class SettingsViewModel : ObservableObject
{
    private readonly AgentClient _client;
    public SettingsViewModel(AgentClient client) => _client = client;

    public ObservableCollection<AccountDetails> Accounts { get; } = new();
    public ObservableCollection<StoredCredential> Credentials { get; } = new();
    public List<CertificateAuthority> Authorities { get; private set; } = new();
    public List<CredentialTypeDefinition> CredentialTypes { get; private set; } = new();

    [ObservableProperty] private Preferences _preferences = new();
    [ObservableProperty] private CertificateAuthority? _selectedAuthority;
    [ObservableProperty] private string _accountEmail = "";
    [ObservableProperty] private bool _accountStaging;
    [ObservableProperty] private bool _accountAgree;
    [ObservableProperty] private string? _eabKeyId;
    [ObservableProperty] private string? _eabKey;
    [ObservableProperty] private CredentialTypeDefinition? _selectedCredentialType;
    [ObservableProperty] private string _credentialTitle = "";
    [ObservableProperty] private List<ParameterViewModel> _credentialFields = new();
    [ObservableProperty] private string? _hubUrl;
    [ObservableProperty] private string? _joiningKey;
    [ObservableProperty] private string _hubStatus = "";
    [ObservableProperty] private string _message = "";

    public async Task LoadAsync()
    {
        Authorities = await _client.GetCertificateAuthoritiesAsync();
        CredentialTypes = await _client.GetCredentialTypesAsync();
        OnPropertyChanged(nameof(Authorities)); OnPropertyChanged(nameof(CredentialTypes));
        SelectedAuthority = Authorities.FirstOrDefault();
        Preferences = await _client.GetPreferencesAsync();
        await ReloadListsAsync();
        await RefreshHubAsync();
    }

    private async Task ReloadListsAsync()
    {
        Accounts.Clear(); foreach (var a in await _client.GetAccountsAsync()) Accounts.Add(a);
        Credentials.Clear(); foreach (var c in await _client.GetCredentialsAsync()) Credentials.Add(c);
    }

    partial void OnSelectedCredentialTypeChanged(CredentialTypeDefinition? value) =>
        CredentialFields = value == null ? new() : ParameterViewModel.Build(value.Fields, Array.Empty<ProviderParameterSetting>(), true);

    [RelayCommand]
    private async Task AddAccountAsync()
    {
        if (SelectedAuthority == null) return;
        Message = "Registering account...";
        var r = await _client.AddAccountAsync(new NewAccountRequest
        {
            CertificateAuthorityId = SelectedAuthority.Id, Email = AccountEmail, IsStaging = AccountStaging,
            AgreedToTermsAndConditions = AccountAgree, EabKeyId = EabKeyId, EabKey = EabKey,
        });
        Message = r.Message ?? "";
        if (r.IsSuccess) { AccountEmail = ""; EabKey = null; EabKeyId = null; await ReloadListsAsync(); }
    }

    [RelayCommand]
    private async Task RemoveAccountAsync(AccountDetails a)
    {
        if (MessageBox.Show($"Remove account {a.Email}?", "Remove", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        await _client.RemoveAccountAsync(a.StorageKey);
        await ReloadListsAsync();
    }

    [RelayCommand]
    private async Task AddCredentialAsync()
    {
        if (SelectedCredentialType == null) return;
        var values = CredentialFields.Where(f => !string.IsNullOrEmpty(f.Value)).ToDictionary(f => f.Key, f => f.Value!);
        if (SelectedCredentialType.Fields.Any(f => f.IsRequired && !values.ContainsKey(f.Key))) { Message = "Fill in all required fields."; return; }
        await _client.UpdateCredentialAsync(new StoredCredential
        {
            ProviderType = SelectedCredentialType.ProviderType,
            Title = string.IsNullOrWhiteSpace(CredentialTitle) ? SelectedCredentialType.Title : CredentialTitle,
            Secret = JsonDefaults.Serialize(values),
        });
        Message = "Credential saved.";
        CredentialTitle = ""; OnSelectedCredentialTypeChanged(SelectedCredentialType);
        await ReloadListsAsync();
    }

    [RelayCommand]
    private async Task DeleteCredentialAsync(StoredCredential c)
    {
        if (MessageBox.Show($"Delete credential '{c.Title}'?", "Delete", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
        await _client.DeleteCredentialAsync(c.StorageKey);
        await ReloadListsAsync();
    }

    [RelayCommand]
    private async Task SavePreferencesAsync()
    {
        var r = await _client.SetPreferencesAsync(Preferences);
        Message = r.Message ?? "";
    }

    [RelayCommand]
    private async Task JoinHubAsync()
    {
        if (string.IsNullOrWhiteSpace(HubUrl) || string.IsNullOrWhiteSpace(JoiningKey)) { Message = "Enter the hub URL and joining key."; return; }
        var r = await _client.JoinHubAsync(new JoinHubRequest { HubUrl = HubUrl, JoiningKey = JoiningKey });
        Message = r.Message ?? "";
        JoiningKey = null;
        await Task.Delay(2500);
        await RefreshHubAsync();
    }

    [RelayCommand]
    private async Task LeaveHubAsync()
    {
        await _client.LeaveHubAsync();
        await RefreshHubAsync();
    }

    [RelayCommand]
    private async Task RefreshHubAsync()
    {
        var s = await _client.GetHubStatusAsync();
        HubUrl ??= s.HubUrl;
        HubStatus = s.HubUrl == null ? "Not joined to a management hub."
            : s.IsConnected ? $"Connected to {s.HubUrl}"
            : $"Not connected to {s.HubUrl}. {s.LastError}";
    }
}
