using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using CertMaster.Models;
using CertMaster.Models.Hub;
using Microsoft.AspNetCore.Components;

namespace CertMaster.UI.Blazor.Services;

public class HubApiException(string message, HttpStatusCode status) : Exception(message)
{
    public HttpStatusCode Status { get; } = status;
}

/// <summary>Typed client for the Management Hub API. Attaches the bearer token and refreshes it on 401.</summary>
public class HubClient
{
    private readonly HttpClient _http;
    private readonly HubSession _session;
    private readonly NavigationManager _nav;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public HubClient(HttpClient http, HubSession session, NavigationManager nav)
    {
        _http = http; _session = session; _nav = nav;
    }

    // ---------- core ----------

    private async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> build, bool retry = true)
    {
        await _session.EnsureLoadedAsync();
        var req = build();
        var tokenUsed = _session.Current?.AccessToken;
        if (tokenUsed != null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenUsed);
        var resp = await _http.SendAsync(req);
        if (resp.StatusCode == HttpStatusCode.Unauthorized && retry && tokenUsed != null)
        {
            resp.Dispose();
            if (await TryRefreshAsync(tokenUsed)) return await SendAsync(build, false);
            await _session.SetAsync(null);
            _nav.NavigateTo("/login");
            throw new HubApiException("Your session has expired. Please sign in again.", HttpStatusCode.Unauthorized);
        }
        return resp;
    }

    private async Task<bool> TryRefreshAsync(string tokenUsed)
    {
        await _refreshLock.WaitAsync();
        try
        {
            var current = _session.Current;
            if (current == null) return false;
            if (current.AccessToken != tokenUsed) return true; // another call already refreshed
            using var resp = await _http.PostAsJsonAsync("api/v1/auth/refresh", new RefreshRequest { RefreshToken = current.RefreshToken }, JsonDefaults.Options);
            if (!resp.IsSuccessStatusCode) return false;
            await _session.SetAsync(await resp.Content.ReadFromJsonAsync<AuthResponse>(JsonDefaults.Options));
            return true;
        }
        finally { _refreshLock.Release(); }
    }

    private static async Task<T> Read<T>(HttpResponseMessage resp)
    {
        using (resp)
        {
            if (!resp.IsSuccessStatusCode) throw await ErrorAsync(resp);
            if (resp.StatusCode == HttpStatusCode.NoContent) return default!;
            return (await resp.Content.ReadFromJsonAsync<T>(JsonDefaults.Options))!;
        }
    }

    private static async Task<HubApiException> ErrorAsync(HttpResponseMessage resp)
    {
        var text = await resp.Content.ReadAsStringAsync();
        string message = $"{(int)resp.StatusCode} {resp.ReasonPhrase}";
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("detail", out var d)) message = d.GetString() ?? message;
            else if (doc.RootElement.TryGetProperty("message", out var m)) message = m.GetString() ?? message;
        }
        catch { if (!string.IsNullOrWhiteSpace(text) && text.Length < 300) message = text; }
        return new HubApiException(message, resp.StatusCode);
    }

    public async Task<T> GetAsync<T>(string path) => await Read<T>(await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, path)));

    public async Task<T> PostAsync<T>(string path, object? body = null) =>
        await Read<T>(await SendAsync(() => new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body, options: JsonDefaults.Options) }));

    public async Task<T> DeleteAsync<T>(string path) => await Read<T>(await SendAsync(() => new HttpRequestMessage(HttpMethod.Delete, path)));

    public async Task<(byte[] data, string fileName)> DownloadAsync(string path)
    {
        var resp = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, path));
        using (resp)
        {
            if (!resp.IsSuccessStatusCode) throw await ErrorAsync(resp);
            var name = resp.Content.Headers.ContentDisposition?.FileNameStar ?? resp.Content.Headers.ContentDisposition?.FileName ?? "certificate";
            return (await resp.Content.ReadAsByteArrayAsync(), name.Trim('"'));
        }
    }

    private static string E(string s) => Uri.EscapeDataString(s);

    // ---------- auth ----------

    public async Task<AuthResponse> LoginAsync(string username, string password)
    {
        using var resp = await _http.PostAsJsonAsync("api/v1/auth/login", new LoginRequest { Username = username, Password = password }, JsonDefaults.Options);
        if (!resp.IsSuccessStatusCode) throw await ErrorAsync(resp);
        var auth = (await resp.Content.ReadFromJsonAsync<AuthResponse>(JsonDefaults.Options))!;
        await _session.SetAsync(auth);
        return auth;
    }

    public async Task LogoutAsync()
    {
        if (_session.Current != null)
            try { await _http.PostAsJsonAsync("api/v1/auth/logout", new RefreshRequest { RefreshToken = _session.Current.RefreshToken }, JsonDefaults.Options); } catch { /* ignore */ }
        await _session.SetAsync(null);
    }

    // ---------- hub ----------
    public Task<HubSummary> GetSummaryAsync() => GetAsync<HubSummary>("api/v1/hub/summary");
    public Task<List<ManagedInstanceInfo>> GetInstancesAsync() => GetAsync<List<ManagedInstanceInfo>>("api/v1/hub/instances");
    public Task<ActionResult> RemoveInstanceAsync(string id) => DeleteAsync<ActionResult>($"api/v1/hub/instances/{E(id)}");
    public Task<ActionResult> SetInstanceTitleAsync(string id, string title) => PostAsync<ActionResult>($"api/v1/hub/instances/{E(id)}/title", new { title });
    public Task<List<JoiningKey>> GetJoiningKeysAsync() => GetAsync<List<JoiningKey>>("api/v1/hub/joiningkeys");
    public Task<JoiningKey> CreateJoiningKeyAsync(string title, int? expiryDays) => PostAsync<JoiningKey>("api/v1/hub/joiningkeys", new { title, expiryDays });
    public Task<ActionResult> RevokeJoiningKeyAsync(string id) => DeleteAsync<ActionResult>($"api/v1/hub/joiningkeys/{E(id)}");
    public Task<List<ManagedCertificate>> GetAllItemsAsync(string? search = null) =>
        GetAsync<List<ManagedCertificate>>("api/v1/hub/items" + (string.IsNullOrWhiteSpace(search) ? "" : "?search=" + E(search)));

    // ---------- instance: certificates ----------
    // hub self-update
    public Task<UpdateStatus> GetHubUpdateStatusAsync() => GetAsync<UpdateStatus>("api/v1/hub/updates");
    public Task<UpdateStatus> CheckHubUpdatesAsync() => PostAsync<UpdateStatus>("api/v1/hub/updates/check");
    public Task<ActionResult> InstallHubUpdateAsync() => PostAsync<ActionResult>("api/v1/hub/updates/install");
    public Task<UpdateSettings> GetHubUpdateSettingsAsync() => GetAsync<UpdateSettings>("api/v1/hub/updates/settings");
    public Task<UpdateSettings> SaveHubUpdateSettingsAsync(UpdateSettings s) => PostAsync<UpdateSettings>("api/v1/hub/updates/settings", s);

    private static string I(string iid) => $"api/v1/instances/{E(iid)}";

    // agent updates (proxied to the instance)
    public Task<UpdateStatus> GetInstanceUpdateStatusAsync(string iid) => GetAsync<UpdateStatus>($"{I(iid)}/system/updates");
    public Task<UpdateStatus> CheckInstanceUpdatesAsync(string iid) => PostAsync<UpdateStatus>($"{I(iid)}/system/updates/check");
    public Task<ActionResult> InstallInstanceUpdateAsync(string iid) => PostAsync<ActionResult>($"{I(iid)}/system/updates/install");
    public Task<UpdateSettings> GetInstanceUpdateSettingsAsync(string iid) => GetAsync<UpdateSettings>($"{I(iid)}/system/updates/settings");
    public Task<UpdateSettings> SaveInstanceUpdateSettingsAsync(string iid, UpdateSettings s) => PostAsync<UpdateSettings>($"{I(iid)}/system/updates/settings", s);
    public Task<ManagedCertificate> GetItemAsync(string iid, string id) => GetAsync<ManagedCertificate>($"{I(iid)}/certificates/{E(id)}");
    public Task<ActionResult<ManagedCertificate>> SaveItemAsync(string iid, ManagedCertificate item) => PostAsync<ActionResult<ManagedCertificate>>($"{I(iid)}/certificates", item);
    public Task<bool> DeleteItemAsync(string iid, string id) => DeleteAsync<bool>($"{I(iid)}/certificates/{E(id)}");
    public Task<List<ActionStep>> TestItemAsync(string iid, ManagedCertificate item) => PostAsync<List<ActionStep>>($"{I(iid)}/certificates/test", item);
    public Task<ActionResult> RequestItemAsync(string iid, string id) => PostAsync<ActionResult>($"{I(iid)}/certificates/{E(id)}/request");
    public Task<ActionResult> RevokeItemAsync(string iid, string id) => PostAsync<ActionResult>($"{I(iid)}/certificates/{E(id)}/revoke");
    public Task<List<LogEntry>> GetItemLogAsync(string iid, string id) => GetAsync<List<LogEntry>>($"{I(iid)}/certificates/{E(id)}/log");
    public Task<RequestProgressState?> GetItemProgressAsync(string iid, string id) => GetAsync<RequestProgressState?>($"{I(iid)}/certificates/{E(id)}/progress");
    public Task<(byte[] data, string fileName)> DownloadItemAsync(string iid, string id, CertificateDownloadFormat format) => DownloadAsync($"{I(iid)}/certificates/{E(id)}/download?format={format}");
    public Task<ActionResult> RenewAllAsync(string iid) => PostAsync<ActionResult>($"{I(iid)}/renewall");
    public Task<List<ActionStep>> PreviewItemAsync(string iid, ManagedCertificate item) => PostAsync<List<ActionStep>>($"{I(iid)}/certificates/preview", item);
    public Task<ActionResult> RunTaskAsync(string iid, string id, string taskId) => PostAsync<ActionResult>($"{I(iid)}/certificates/{E(id)}/tasks/{E(taskId)}/execute");
    public Task<ServerStatus> GetServerStatusAsync(string iid) => GetAsync<ServerStatus>($"{I(iid)}/server/status");
    public Task<List<SiteInfo>> GetSitesAsync(string iid) => GetAsync<List<SiteInfo>>($"{I(iid)}/server/sites");
    public Task<List<DomainOption>> GetSiteDomainsAsync(string iid, string siteId) => GetAsync<List<DomainOption>>($"{I(iid)}/server/sites/{E(siteId)}/domains");

    // ---------- instance: providers, credentials, accounts ----------
    public Task<List<ChallengeProviderDefinition>> GetChallengeProvidersAsync(string iid) => GetAsync<List<ChallengeProviderDefinition>>($"{I(iid)}/providers/challenges");
    public Task<List<DeploymentProviderDefinition>> GetDeploymentProvidersAsync(string iid) => GetAsync<List<DeploymentProviderDefinition>>($"{I(iid)}/providers/deployment");
    public Task<List<StoredCredential>> GetCredentialsAsync(string iid) => GetAsync<List<StoredCredential>>($"{I(iid)}/credentials");
    public Task<List<CredentialTypeDefinition>> GetCredentialTypesAsync(string iid) => GetAsync<List<CredentialTypeDefinition>>($"{I(iid)}/credentials/types");
    public Task<StoredCredential> SaveCredentialAsync(string iid, StoredCredential c) => PostAsync<StoredCredential>($"{I(iid)}/credentials", c);
    public Task<bool> DeleteCredentialAsync(string iid, string key) => DeleteAsync<bool>($"{I(iid)}/credentials/{E(key)}");
    public Task<List<AccountDetails>> GetAccountsAsync(string iid) => GetAsync<List<AccountDetails>>($"{I(iid)}/accounts");
    public Task<List<CertificateAuthority>> GetAuthoritiesAsync(string iid) => GetAsync<List<CertificateAuthority>>($"{I(iid)}/accounts/authorities");
    public Task<ActionResult<AccountDetails>> AddAccountAsync(string iid, NewAccountRequest r) => PostAsync<ActionResult<AccountDetails>>($"{I(iid)}/accounts", r);
    public Task<bool> RemoveAccountAsync(string iid, string key) => DeleteAsync<bool>($"{I(iid)}/accounts/{E(key)}");

    // ---------- access ----------
    public Task<List<HubUser>> GetUsersAsync() => GetAsync<List<HubUser>>("api/v1/access/users");
    public Task<ActionResult> SaveUserAsync(HubUser u) => PostAsync<ActionResult>("api/v1/access/users", u);
    public Task<ActionResult> DeleteUserAsync(string id) => DeleteAsync<ActionResult>($"api/v1/access/users/{E(id)}");
    public Task<ActionResult> ChangePasswordAsync(ChangePasswordRequest r) => PostAsync<ActionResult>("api/v1/access/changepassword", r);
}
