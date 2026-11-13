using CertMaster.Core;
using CertMaster.Core.Providers.Dns;
using CertMaster.Core.Updates;
using CertMaster.Models;

namespace CertMaster.Server.Core;

/// <summary>Local agent REST API (consumed by the desktop UI via CertMaster.Client).</summary>
public static class AgentApi
{
    private static readonly HttpClient ZoneHttp = new() { Timeout = TimeSpan.FromSeconds(30) };

    public static void MapAgentApi(this WebApplication app)
    {
        var api = app.MapGroup("/api");

        // ---- system ----
        api.MapGet("/system/health", () => Results.Ok(new { status = "ok" }));
        api.MapGet("/system/version", (AgentIdentity id) => id.GetVersion());
        // Read-only health snapshot for the tray monitor; loopback callers need no API key (AgentIdentity.AllowsAnonymous).
        api.MapGet("/system/summary", async (CertManager m, AgentIdentity id) =>
            AgentStatusSummary.From(await m.GetManagedCertificatesAsync(), id.Version, m.RequestsInProgressCount, DateTimeOffset.UtcNow));
        api.MapGet("/system/log", (CertManager m, int? lines) =>
        {
            var dir = m.Paths.Logs;
            var latest = new DirectoryInfo(dir).GetFiles("service*.log").OrderByDescending(f => f.LastWriteTimeUtc).FirstOrDefault();
            if (latest == null) return Results.Ok(Array.Empty<string>());
            using var fs = new FileStream(latest.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var all = sr.ReadToEnd().Split('\n');
            return Results.Ok(all.TakeLast(lines ?? 500));
        });
        api.MapGet("/system/updates", (UpdateManager u) => u.GetStatus());
        api.MapPost("/system/updates/check", (UpdateManager u, CancellationToken ct) => u.CheckAsync(ct));
        api.MapPost("/system/updates/install", (UpdateManager u, IHostApplicationLifetime life) => u.BeginInstallAsync(life.ApplicationStopping));
        api.MapGet("/system/updates/settings", (UpdateManager u) => u.GetSettingsAsync());
        api.MapPost("/system/updates/settings", (UpdateManager u, UpdateSettings s) => u.SetSettingsAsync(s));
        api.MapGet("/preferences", (CertManager m) => m.GetPreferencesAsync());
        api.MapPost("/preferences", async (CertManager m, Preferences p) => { await m.SetPreferencesAsync(p); return ActionResult.Ok("Preferences saved"); });
        api.MapPost("/preferences/notifications/test", (CertManager m, TestNotificationRequest r) => m.SendTestNotificationAsync(r.Url));

        // ---- managed certificates ----
        var mc = api.MapGroup("/managedcertificates");
        mc.MapGet("/", (CertManager m, string? search) => m.GetManagedCertificatesAsync(search));
        mc.MapGet("/{id}", async (CertManager m, string id) => await m.GetManagedCertificateAsync(id) is { } i ? Results.Ok(i) : Results.NotFound());
        mc.MapPost("/", (CertManager m, ManagedCertificate item) => m.UpdateManagedCertificateAsync(item));
        mc.MapDelete("/{id}", async (CertManager m, string id) => new ActionResult(await m.DeleteManagedCertificateAsync(id), "Deleted"));
        mc.MapPost("/test", (CertManager m, ManagedCertificate item) => m.TestConfigurationAsync(item));
        mc.MapPost("/preview", (CertManager m, ManagedCertificate item) => m.GeneratePreviewAsync(item));

        // ---- local web server (IIS) ----
        api.MapGet("/server/status", (CertManager m) => m.GetServerStatusAsync());
        api.MapGet("/server/sites", (CertManager m) => m.GetSitesAsync());
        api.MapGet("/server/sites/{id}/domains", (CertManager m, string id) => m.GetDomainOptionsFromSiteAsync(id));
        mc.MapPost("/{id}/request", async (CertManager m, IHostApplicationLifetime life, string id, bool? wait) =>
        {
            if (m.IsRequestInProgress(id)) return Results.Conflict(ActionResult.Fail("A request is already in progress"));
            if (wait == true) return Results.Ok(await m.PerformCertificateRequestAsync(id, life.ApplicationStopping));
            _ = Task.Run(() => m.PerformCertificateRequestAsync(id, life.ApplicationStopping));
            return Results.Accepted(value: ActionResult.Ok("Request started"));
        });
        mc.MapPost("/{id}/cancel", (CertManager m, string id) => new ActionResult(m.CancelRequest(id), "Cancel requested"));
        mc.MapPost("/{id}/revoke", (CertManager m, string id) => m.RevokeCertificateAsync(id));
        mc.MapGet("/{id}/log", (CertManager m, string id, int? limit) => m.GetItemLog(id, limit ?? 1000));
        mc.MapGet("/{id}/download", async (CertManager m, string id, CertificateDownloadFormat? format) =>
        {
            var f = await m.GetCertificateFileAsync(id, format ?? CertificateDownloadFormat.pfx);
            return f == null ? Results.NotFound() : Results.File(f.Value.data, f.Value.contentType, f.Value.fileName);
        });
        mc.MapPost("/{id}/tasks/{taskId}/execute", (CertManager m, string id, string taskId, bool? preview) =>
            m.PerformDeploymentTaskAsync(id, taskId, preview ?? false));
        mc.MapPost("/renewall", (CertManager m, IHostApplicationLifetime life, bool? force) =>
        {
            _ = Task.Run(() => m.PerformRenewAllAsync(force ?? false, life.ApplicationStopping));
            return ActionResult.Ok("Renewal started");
        });

        // ---- ACME accounts and certificate authorities ----
        api.MapGet("/accounts", (CertManager m) => m.Acme.GetAccountsAsync());
        api.MapPost("/accounts", (CertManager m, NewAccountRequest r) => m.Acme.AddAccountAsync(r));
        api.MapDelete("/accounts/{key}", async (CertManager m, string key) => new ActionResult(await m.Acme.RemoveAccountAsync(key), "Account removed"));
        api.MapGet("/accounts/authorities", (CertManager m) => m.Acme.GetCertificateAuthoritiesAsync());
        api.MapPost("/accounts/authorities", (CertManager m, CertificateAuthority ca) => m.Acme.UpdateCertificateAuthorityAsync(ca));
        api.MapDelete("/accounts/authorities/{id}", async (CertManager m, string id) => new ActionResult(await m.Acme.RemoveCertificateAuthorityAsync(id), "Removed"));

        // ---- stored credentials ----
        api.MapGet("/credentials", (CertManager m) => m.Credentials.GetCredentialsAsync());
        api.MapGet("/credentials/types", (CertManager m) => m.Providers.GetCredentialTypes());
        api.MapPost("/credentials", (CertManager m, StoredCredential c) => m.Credentials.UpdateAsync(c));
        api.MapDelete("/credentials/{key}", async (CertManager m, string key) => new ActionResult(await m.Credentials.DeleteAsync(key), "Credential deleted"));

        // ---- providers ----
        api.MapGet("/providers/challenges", (CertManager m) => m.Providers.GetChallengeProviders());
        api.MapGet("/providers/deployment", (CertManager m) => m.Providers.GetDeploymentProviders());
        api.MapPost("/providers/challenges/zones", async (CertManager m, CertRequestChallengeConfig cfg) =>
        {
            var p = m.Providers.GetDnsProvider(cfg.ChallengeProvider);
            if (p == null) return Results.NotFound();
            var ctx = new DnsProviderContext
            {
                Credentials = await m.Credentials.GetUnlockedCredentialsDictionaryAsync(cfg.ChallengeCredentialKey),
                Parameters = cfg.Parameters.Where(x => x.Value != null).ToDictionary(x => x.Key, x => x.Value!),
                Http = ZoneHttp, Paths = m.Paths,
            };
            return Results.Ok(await p.GetZonesAsync(ctx));
        });

        // ---- management hub connection ----
        api.MapGet("/hubsettings", async (HubClientService hub) =>
        {
            var s = await hub.GetSettingsAsync();
            return new { s.HubUrl, s.IsJoined, hub.IsConnected, hub.LastError };
        });
        api.MapPost("/hubsettings/join", async (HubClientService hub, JoinHubRequest req) =>
        {
            try { await hub.JoinAsync(req); return ActionResult.Ok("Joining management hub..."); }
            catch (Exception ex) { return ActionResult.Fail(ex.Message); }
        });
        api.MapPost("/hubsettings/leave", async (HubClientService hub) => { await hub.LeaveAsync(); return ActionResult.Ok("Left management hub"); });
    }
}
