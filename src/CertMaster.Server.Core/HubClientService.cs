using CertMaster.Core;
using CertMaster.Core.Storage;
using CertMaster.Models;
using CertMaster.Models.Hub;
using Microsoft.AspNetCore.SignalR.Client;

namespace CertMaster.Server.Core;

/// <summary>
/// Maintains the outbound SignalR connection from this agent to a Management Hub. The hub sends commands
/// (client results) and receives progress and summary reports. Agents connect out, so no inbound port is needed.
/// </summary>
public class HubClientService : BackgroundService
{
    public const string HubPath = "/api/internal/instances";
    private const string SettingsKey = "hubconnection";

    private readonly DocumentStore _store;
    private readonly AgentIdentity _identity;
    private readonly IServiceProvider _services;
    private readonly ILogger<HubClientService> _logger;
    private readonly SemaphoreSlim _changed = new(0, 1);
    private HubConnection? _connection;
    private bool _registered;

    public string? LastError { get; private set; }
    public bool IsConnected => _connection?.State == HubConnectionState.Connected && _registered;

    public HubClientService(DocumentStore store, AgentIdentity identity, IServiceProvider services, ILogger<HubClientService> logger)
    {
        _store = store; _identity = identity; _services = services; _logger = logger;
    }

    public Task<HubConnectionSettings> GetSettingsAsync() => _store.GetSettingAsync<HubConnectionSettings>(SettingsKey);

    public async Task JoinAsync(JoinHubRequest req)
    {
        var url = req.HubUrl.Trim().TrimEnd('/');
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http"))
            throw new ArgumentException("Hub URL must be an absolute http(s) URL.");
        await _store.SetSettingAsync(SettingsKey, new HubConnectionSettings { HubUrl = url, JoiningKey = req.JoiningKey.Trim() });
        LastError = null;
        Signal();
    }

    public async Task LeaveAsync()
    {
        await _store.SetSettingAsync(SettingsKey, new HubConnectionSettings());
        Signal();
    }

    private void Signal() { if (_changed.CurrentCount == 0) _changed.Release(); }

    public async Task ForwardProgressAsync(RequestProgressState state)
    {
        if (IsConnected) try { await _connection!.SendAsync("ReportProgress", state); } catch { /* best effort */ }
    }

    public async Task ForwardItemUpdatedAsync(ManagedCertificate item)
    {
        if (IsConnected) try { await SendSummaryAsync(); } catch { /* best effort */ }
    }

    private async Task SendSummaryAsync()
    {
        var manager = _services.GetRequiredService<CertManager>();
        var summary = ManagedInstanceSummary.From(await manager.GetManagedCertificatesAsync());
        await _connection!.SendAsync("ReportSummary", summary);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var settings = await GetSettingsAsync();
            if (string.IsNullOrEmpty(settings.HubUrl))
            {
                await WaitForChange(TimeSpan.FromMinutes(5), stoppingToken);
                continue;
            }

            try
            {
                await ConnectAsync(settings, stoppingToken);
                // stay connected; send summary every 5 minutes until settings change or connection closes
                while (!stoppingToken.IsCancellationRequested && _connection?.State != HubConnectionState.Disconnected)
                {
                    if (await WaitForChange(TimeSpan.FromMinutes(5), stoppingToken)) break; // settings changed
                    if (IsConnected) await SendSummaryAsync();
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                LastError = ex.Message;
                _logger.LogWarning("Management hub connection failed: {Error}", ex.Message);
                await WaitForChange(TimeSpan.FromSeconds(60), stoppingToken);
            }
            finally
            {
                _registered = false;
                if (_connection != null) { try { await _connection.DisposeAsync(); } catch { /* ignore */ } _connection = null; }
            }
        }
    }

    private async Task<bool> WaitForChange(TimeSpan timeout, CancellationToken ct)
    {
        try { return await _changed.WaitAsync(timeout, ct); }
        catch (OperationCanceledException) { return false; }
    }

    private async Task ConnectAsync(HubConnectionSettings settings, CancellationToken ct)
    {
        var handler = _services.GetRequiredService<InstanceCommandHandler>();
        _connection = new HubConnectionBuilder()
            .WithUrl(settings.HubUrl + HubPath, o => o.Headers["X-Instance-Id"] = _identity.InstanceId)
            .AddJsonProtocol(o => JsonDefaults.Apply(o.PayloadSerializerOptions))
            .WithAutomaticReconnect()
            .Build();

        _connection.On<InstanceCommand, InstanceCommandResult>("PerformCommand", cmd =>
            _registered ? handler.HandleAsync(cmd) : Task.FromResult(new InstanceCommandResult { CommandId = cmd.CommandId, Message = "Not registered" }));
        _connection.Reconnected += async _ => { await RegisterAsync(); };
        _connection.Closed += ex => { _registered = false; LastError = ex?.Message; Signal(); return Task.CompletedTask; };

        await _connection.StartAsync(ct);
        await RegisterAsync();
    }

    private async Task RegisterAsync()
    {
        var settings = await GetSettingsAsync();
        var reg = new InstanceRegistration
        {
            InstanceId = _identity.InstanceId, Title = _identity.Title, ClientVersion = _identity.Version,
            OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            JoiningKey = settings.InstanceSecret == null ? settings.JoiningKey : null,
            InstanceSecret = settings.InstanceSecret,
        };
        var result = await _connection!.InvokeAsync<InstanceRegistrationResult>("Register", reg);
        if (!result.IsAccepted)
        {
            LastError = result.Message ?? "Registration rejected by hub";
            _registered = false;
            throw new InvalidOperationException(LastError);
        }
        if (!string.IsNullOrEmpty(result.InstanceSecret))
        {
            settings.InstanceSecret = result.InstanceSecret;
            settings.JoiningKey = null; // single use
        }
        settings.IsJoined = true;
        await _store.SetSettingAsync(SettingsKey, settings);
        _registered = true;
        LastError = null;
        _logger.LogInformation("Connected to management hub {Url}", settings.HubUrl);
        await SendSummaryAsync();
    }
}
