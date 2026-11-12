using CertMaster.Core;
using CertMaster.Core.Storage;
using CertMaster.Hosting;
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

    private void Signal()
    {
        try { _changed.Release(); }
        catch (SemaphoreFullException) { /* a change is already pending */ }
    }

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
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = await GetSettingsAsync();
                if (string.IsNullOrEmpty(settings.HubUrl))
                {
                    failures = 0;
                    await WaitForChange(TimeSpan.FromMinutes(5), stoppingToken);
                    continue;
                }

                await ConnectAsync(settings, stoppingToken);
                failures = 0;
                // stay connected; send summary every 5 minutes until settings change or connection closes
                while (!stoppingToken.IsCancellationRequested && _connection?.State != HubConnectionState.Disconnected)
                {
                    if (await WaitForChange(TimeSpan.FromMinutes(5), stoppingToken)) break; // settings changed or connection closed
                    if (IsConnected) await SendSummaryAsync();
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                // Includes timeouts (TaskCanceledException) during negotiate/handshake and hub restarts mid-registration:
                // the agent must keep trying, never give up until the service stops.
                failures++;
                LastError = ex.Message;
                var delay = TimeSpan.FromSeconds(Math.Max(15, ForeverRetryPolicy.Delay(failures + 4).TotalSeconds)); // ~15 s ... 2 min
                _logger.LogWarning("Management hub connection failed: {Error}. Retrying in {Delay:0}s", ex.Message, delay.TotalSeconds);
                await WaitForChange(delay, stoppingToken);
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
            .WithAutomaticReconnect(new ForeverRetryPolicy())
            .Build();

        _connection.On<InstanceCommand, InstanceCommandResult>("PerformCommand", cmd =>
            _registered ? handler.HandleAsync(cmd) : Task.FromResult(new InstanceCommandResult { CommandId = cmd.CommandId, Message = "Not registered" }));
        var connection = _connection;
        _connection.Reconnecting += _ => { _registered = false; return Task.CompletedTask; };
        _connection.Reconnected += async _ =>
        {
            try { await RegisterAsync(); }
            catch (Exception ex)
            {
                // Connected but not registered is useless (the hub shows the instance offline): drop the connection so the
                // main loop rebuilds it with back-off.
                LastError = ex.Message;
                _logger.LogWarning("Re-registration with the management hub failed: {Error}", ex.Message);
                try { await connection.StopAsync(); } catch { /* Closed handler signals the loop */ }
                Signal();
            }
        };
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
