using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using CertMaster.Client;
using CertMaster.Models;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CertMaster.UI.Desktop.ViewModels;

/// <summary>
/// Update status and settings for this server. The agent service does the checking and installing (it runs as SYSTEM,
/// so no elevation prompt is needed); this view model only shows its state and sends commands.
/// </summary>
public partial class UpdatesViewModel : ObservableObject
{
    private readonly AgentClient _client;
    private readonly DispatcherTimer _timer;

    public UpdatesViewModel(AgentClient client)
    {
        _client = client;
        // Poll quickly while downloading/installing, otherwise pick up the agent's scheduled checks now and then.
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(10) };
        _timer.Tick += async (_, _) => await RefreshAsync();
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasUpdate), nameof(IsWorking), nameof(Summary), nameof(LastCheckedText), nameof(BannerText))]
    [NotifyCanExecuteChangedFor(nameof(InstallCommand), nameof(CheckCommand))]
    private UpdateStatus _status = new();

    [ObservableProperty] private UpdateSettings _settings = new();
    [ObservableProperty] private string? _message;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(InstallCommand), nameof(CheckCommand))]
    private bool _isBusy;

    public bool HasUpdate => Status.IsUpdateAvailable;
    public bool IsWorking => Status.State is UpdateState.Checking or UpdateState.Downloading or UpdateState.Installing;
    public string Summary => Status.IsUpdateAvailable
        ? $"CertMaster {Status.LatestVersion} is available. This server runs {Status.CurrentVersion}."
        : Status.LastChecked == null ? $"This server runs CertMaster {Status.CurrentVersion}." : $"CertMaster {Status.CurrentVersion} is up to date.";
    public string LastCheckedText => Status.LastChecked == null ? "Not checked yet" : $"Last checked {Status.LastChecked.Value.ToLocalTime():g}";
    public string BannerText => Status.State switch
    {
        UpdateState.Downloading or UpdateState.Installing => Status.Message ?? "Installing update...",
        _ => $"CertMaster {Status.LatestVersion} is available (you have {Status.CurrentVersion}).",
    };

    public async Task InitializeAsync()
    {
        await RefreshAsync();
        try { Settings = await _client.GetUpdateSettingsAsync(); } catch (Exception ex) { Message = ex.Message; }
        _timer.Start();
    }

    public async Task RefreshAsync()
    {
        try
        {
            Status = await _client.GetUpdateStatusAsync();
            _timer.Interval = IsWorking ? TimeSpan.FromSeconds(3) : TimeSpan.FromMinutes(10);
        }
        catch (Exception ex) when (Status.State == UpdateState.Installing)
        {
            // Expected while setup restarts the service.
            Message = "The agent is restarting to finish the update... (" + ex.Message + ")";
        }
        catch (Exception ex) { Message = ex.Message; }
    }

    private bool CanAct => !IsBusy && !IsWorking;

    [RelayCommand(CanExecute = nameof(CanAct))]
    private async Task CheckAsync()
    {
        IsBusy = true;
        try
        {
            Status = await _client.CheckForUpdatesAsync();
            Message = Status.Message;
        }
        catch (Exception ex) { Message = ex.Message; }
        finally { IsBusy = false; }
    }

    private bool CanInstall => CanAct && Status.IsUpdateAvailable && Status.CanInstall;

    [RelayCommand(CanExecute = nameof(CanInstall))]
    private async Task InstallAsync()
    {
        if (MessageBox.Show(
                $"Download and install CertMaster {Status.LatestVersion}?\n\n" +
                "The agent service restarts during setup (after any running certificate requests finish) and this window closes. " +
                "Open CertMaster again when setup has finished, usually within a minute or two.",
                "Install update", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        IsBusy = true;
        try
        {
            var r = await _client.InstallUpdateAsync();
            Message = r.Message;
            await RefreshAsync();
        }
        catch (Exception ex) { Message = ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task SaveSettingsAsync()
    {
        try
        {
            Settings = await _client.SetUpdateSettingsAsync(Settings);
            Message = "Update settings saved.";
        }
        catch (Exception ex) { Message = ex.Message; }
    }

    [RelayCommand]
    private void OpenReleaseNotes()
    {
        var url = Status.ReleaseUrl ?? "https://github.com/parthh37/certmaster/releases";
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch (Exception ex) { Message = ex.Message; }
    }
}
