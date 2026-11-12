using System.Net.Http.Json;
using CertMaster.Models;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;

namespace CertMaster.Client;

public record HubStatus(string? HubUrl, bool IsJoined, bool IsConnected, string? LastError);

/// <summary>Typed client for the local CertMaster Agent API and its SignalR status stream.</summary>
public class AgentClient : IAsyncDisposable
{
    public const string DefaultUrl = "http://127.0.0.1:9696";
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly string _apiKey;
    private HubConnection? _status;

    public event Action<RequestProgressState>? ProgressReceived;
    public event Action<ManagedCertificate>? ManagedCertificateUpdated;
    public event Action<string>? ConnectionStateChanged;

    public AgentClient(string baseUrl, string apiKey)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;
        _http = new HttpClient { BaseAddress = new Uri(_baseUrl + "/"), Timeout = TimeSpan.FromMinutes(10) };
        _http.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
    }

    /// <summary>The local agent's data folder (CERTMASTER_DATA, else %ProgramData%\CertMaster).</summary>
    public static string LocalDataPath(string? dataPath = null) =>
        dataPath ?? Environment.GetEnvironmentVariable("CERTMASTER_DATA")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CertMaster");

    /// <summary>The API key file the local agent writes when it starts.</summary>
    public static string LocalKeyFile(string? dataPath = null) => Path.Combine(LocalDataPath(dataPath), "agent-api.key");

    /// <summary>The local agent's URL (CERTMASTER_AGENT_URL, else <see cref="DefaultUrl"/>).</summary>
    public static string LocalUrl(string? url = null) => url ?? Environment.GetEnvironmentVariable("CERTMASTER_AGENT_URL") ?? DefaultUrl;

    /// <summary>Creates a client using the API key file written by the local agent (requires administrator rights).</summary>
    public static AgentClient CreateLocal(string? url = null, string? dataPath = null)
    {
        var keyFile = LocalKeyFile(dataPath);
        if (!File.Exists(keyFile)) throw new FileNotFoundException("Agent API key not found. Is the CertMaster Agent service installed and running?", keyFile);
        return new AgentClient(LocalUrl(url), File.ReadAllText(keyFile).Trim());
    }

    /// <summary>True when the agent at <paramref name="url"/> answers its unauthenticated health check.</summary>
    public static async Task<bool> IsAgentRespondingAsync(string? url = null, CancellationToken ct = default)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            using var resp = await http.GetAsync(LocalUrl(url).TrimEnd('/') + "/api/system/health", ct);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { return false; }
    }

    // ---------- status stream ----------

    public async Task ConnectStatusAsync()
    {
        _status = new HubConnectionBuilder()
            .WithUrl(_baseUrl + "/api/status", o => o.Headers["X-Api-Key"] = _apiKey)
            .AddJsonProtocol(o => JsonDefaults.Apply(o.PayloadSerializerOptions))
            .WithAutomaticReconnect(new CertMaster.Hosting.ForeverRetryPolicy())
            .Build();
        _status.On<RequestProgressState>("RequestProgressStateUpdated", s => ProgressReceived?.Invoke(s));
        _status.On<ManagedCertificate>("ManagedCertificateUpdated", i => ManagedCertificateUpdated?.Invoke(i));
        _status.Reconnecting += _ => { ConnectionStateChanged?.Invoke("Reconnecting"); return Task.CompletedTask; };
        _status.Reconnected += _ => { ConnectionStateChanged?.Invoke("Connected"); return Task.CompletedTask; };
        _status.Closed += _ => { ConnectionStateChanged?.Invoke("Disconnected"); return Task.CompletedTask; };
        await _status.StartAsync();
        ConnectionStateChanged?.Invoke("Connected");
    }

    // ---------- helpers ----------

    private async Task<T> Get<T>(string path) =>
        (await _http.GetFromJsonAsync<T>(path, JsonDefaults.Options))!;

    private async Task<T> Post<T>(string path, object? body = null)
    {
        using var resp = await _http.PostAsJsonAsync(path, body, JsonDefaults.Options);
        if (!resp.IsSuccessStatusCode && resp.StatusCode != System.Net.HttpStatusCode.Conflict)
            throw new HttpRequestException($"{(int)resp.StatusCode} {resp.ReasonPhrase}: {await resp.Content.ReadAsStringAsync()}");
        return (await resp.Content.ReadFromJsonAsync<T>(JsonDefaults.Options))!;
    }

    private async Task<T> Delete<T>(string path)
    {
        using var resp = await _http.DeleteAsync(path);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"{(int)resp.StatusCode} {resp.ReasonPhrase}: {await resp.Content.ReadAsStringAsync()}", null, resp.StatusCode);
        return (await resp.Content.ReadFromJsonAsync<T>(JsonDefaults.Options))!;
    }

    private static string E(string s) => Uri.EscapeDataString(s);

    // ---------- system ----------
    public Task<SystemVersion> GetVersionAsync() => Get<SystemVersion>("api/system/version");
    public Task<Preferences> GetPreferencesAsync() => Get<Preferences>("api/preferences");
    public Task<ActionResult> SetPreferencesAsync(Preferences p) => Post<ActionResult>("api/preferences", p);
    public Task<ActionResult> SendTestNotificationAsync(string? url) =>
        Post<ActionResult>("api/preferences/notifications/test", new TestNotificationRequest { Url = url });
    public Task<List<string>> GetServiceLogAsync(int lines = 500) => Get<List<string>>($"api/system/log?lines={lines}");

    // ---------- updates ----------
    public Task<UpdateStatus> GetUpdateStatusAsync() => Get<UpdateStatus>("api/system/updates");
    public Task<UpdateStatus> CheckForUpdatesAsync() => Post<UpdateStatus>("api/system/updates/check");
    public Task<ActionResult> InstallUpdateAsync() => Post<ActionResult>("api/system/updates/install");
    public Task<UpdateSettings> GetUpdateSettingsAsync() => Get<UpdateSettings>("api/system/updates/settings");
    public Task<UpdateSettings> SetUpdateSettingsAsync(UpdateSettings s) => Post<UpdateSettings>("api/system/updates/settings", s);

    // ---------- managed certificates ----------
    public Task<List<ManagedCertificate>> GetManagedCertificatesAsync(string? search = null) =>
        Get<List<ManagedCertificate>>("api/managedcertificates" + (string.IsNullOrEmpty(search) ? "" : "?search=" + E(search)));
    public Task<ManagedCertificate> GetManagedCertificateAsync(string id) => Get<ManagedCertificate>($"api/managedcertificates/{E(id)}");
    public Task<ActionResult<ManagedCertificate>> UpdateManagedCertificateAsync(ManagedCertificate item) => Post<ActionResult<ManagedCertificate>>("api/managedcertificates", item);
    public Task<ActionResult> DeleteManagedCertificateAsync(string id) => Delete<ActionResult>($"api/managedcertificates/{E(id)}");
    public Task<List<ActionStep>> TestConfigurationAsync(ManagedCertificate item) => Post<List<ActionStep>>("api/managedcertificates/test", item);
    public Task<List<ActionStep>> GeneratePreviewAsync(ManagedCertificate item) => Post<List<ActionStep>>("api/managedcertificates/preview", item);
    public Task<ServerStatus> GetServerStatusAsync() => Get<ServerStatus>("api/server/status");
    public Task<List<SiteInfo>> GetSitesAsync() => Get<List<SiteInfo>>("api/server/sites");
    public Task<List<DomainOption>> GetDomainOptionsFromSiteAsync(string siteId) => Get<List<DomainOption>>($"api/server/sites/{E(siteId)}/domains");
    public Task<ActionResult> BeginCertificateRequestAsync(string id) => Post<ActionResult>($"api/managedcertificates/{E(id)}/request");
    public Task<ActionResult> CancelRequestAsync(string id) => Post<ActionResult>($"api/managedcertificates/{E(id)}/cancel");
    public Task<ActionResult> RevokeCertificateAsync(string id) => Post<ActionResult>($"api/managedcertificates/{E(id)}/revoke");
    public Task<List<LogEntry>> GetItemLogAsync(string id, int limit = 1000) => Get<List<LogEntry>>($"api/managedcertificates/{E(id)}/log?limit={limit}");
    public Task<ActionResult> PerformDeploymentTaskAsync(string id, string taskId, bool preview) =>
        Post<ActionResult>($"api/managedcertificates/{E(id)}/tasks/{E(taskId)}/execute?preview={preview.ToString().ToLowerInvariant()}");
    public Task<ActionResult> RenewAllAsync(bool force = false) => Post<ActionResult>($"api/managedcertificates/renewall?force={force.ToString().ToLowerInvariant()}");
    public async Task<byte[]> DownloadCertificateAsync(string id, CertificateDownloadFormat format) =>
        await _http.GetByteArrayAsync($"api/managedcertificates/{E(id)}/download?format={format}");

    // ---------- accounts / CAs ----------
    public Task<List<AccountDetails>> GetAccountsAsync() => Get<List<AccountDetails>>("api/accounts");
    public Task<ActionResult<AccountDetails>> AddAccountAsync(NewAccountRequest r) => Post<ActionResult<AccountDetails>>("api/accounts", r);
    public Task<ActionResult> RemoveAccountAsync(string key) => Delete<ActionResult>($"api/accounts/{E(key)}");
    public Task<List<CertificateAuthority>> GetCertificateAuthoritiesAsync() => Get<List<CertificateAuthority>>("api/accounts/authorities");
    public Task<ActionResult> UpdateCertificateAuthorityAsync(CertificateAuthority ca) => Post<ActionResult>("api/accounts/authorities", ca);

    // ---------- credentials ----------
    public Task<List<StoredCredential>> GetCredentialsAsync() => Get<List<StoredCredential>>("api/credentials");
    public Task<List<CredentialTypeDefinition>> GetCredentialTypesAsync() => Get<List<CredentialTypeDefinition>>("api/credentials/types");
    public Task<StoredCredential> UpdateCredentialAsync(StoredCredential c) => Post<StoredCredential>("api/credentials", c);
    public Task<ActionResult> DeleteCredentialAsync(string key) => Delete<ActionResult>($"api/credentials/{E(key)}");

    // ---------- providers ----------
    public Task<List<ChallengeProviderDefinition>> GetChallengeProvidersAsync() => Get<List<ChallengeProviderDefinition>>("api/providers/challenges");
    public Task<List<DeploymentProviderDefinition>> GetDeploymentProvidersAsync() => Get<List<DeploymentProviderDefinition>>("api/providers/deployment");

    // ---------- hub ----------
    public Task<HubStatus> GetHubStatusAsync() => Get<HubStatus>("api/hubsettings");
    public Task<ActionResult> JoinHubAsync(JoinHubRequest r) => Post<ActionResult>("api/hubsettings/join", r);
    public Task<ActionResult> LeaveHubAsync() => Post<ActionResult>("api/hubsettings/leave");

    public async ValueTask DisposeAsync()
    {
        if (_status != null) await _status.DisposeAsync();
        _http.Dispose();
    }
}
