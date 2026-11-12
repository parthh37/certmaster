using System.Security.Claims;
using CertMaster.Models;
using CertMaster.Models.Hub;
using CertMaster.Server.Hub.Services;

namespace CertMaster.Server.Hub;

public static class HubPolicies
{
    public const string Admin = "admin";
    public const string Manage = "manage";
}

/// <summary>Management Hub REST API (consumed by the Blazor UI). Instance operations are proxied to agents over SignalR.</summary>
public static class HubApi
{
    private record JoiningKeyRequest(string Title, int? ExpiryDays);
    private record TitleRequest(string Title);

    public static void MapHubApi(this WebApplication app)
    {
        var v1 = app.MapGroup("/api/v1");

        // ---- auth (anonymous, rate limited) ----
        var auth = v1.MapGroup("/auth").AllowAnonymous();
        auth.MapPost("/login", async (AuthService a, LoginRequest r) =>
            await a.LoginAsync(r) is { } t ? Results.Ok(t) : Results.Problem("Invalid username or password", statusCode: 401)).RequireRateLimiting("auth");
        auth.MapPost("/refresh", async (AuthService a, RefreshRequest r) =>
            await a.RefreshAsync(r.RefreshToken) is { } t ? Results.Ok(t) : Results.Problem("Session expired", statusCode: 401)).RequireRateLimiting("refresh");
        auth.MapPost("/logout", async (AuthService a, RefreshRequest r) => { await a.LogoutAsync(r.RefreshToken); return Results.Ok(); }).RequireRateLimiting("refresh");

        v1.MapGet("/hub/info", () => new HubInfo { Version = typeof(HubApi).Assembly.GetName().Version?.ToString(3) ?? "1.0.0" }).AllowAnonymous();

        // ---- authenticated ----
        var api = v1.MapGroup("").RequireAuthorization();

        // account
        api.MapPost("/access/changepassword", (AuthService a, ClaimsPrincipal u, ChangePasswordRequest r) => a.ChangePasswordAsync(UserId(u), r));

        // users (admin)
        var users = api.MapGroup("/access/users").RequireAuthorization(HubPolicies.Admin);
        users.MapGet("/", (AuthService a) => a.GetUsersAsync());
        users.MapPost("/", (AuthService a, HubUser user) => a.UpdateUserAsync(user));
        users.MapDelete("/{id}", (AuthService a, ClaimsPrincipal u, string id) => a.DeleteUserAsync(id, UserId(u)));
        api.MapGet("/access/roles", () => HubRoles.All);

        // instances
        api.MapGet("/hub/instances", (InstanceRegistry r) => r.GetInstancesAsync());
        api.MapPost("/hub/instances/{id}/title", async (InstanceRegistry r, string id, TitleRequest t) => new ActionResult(await r.UpdateTitleAsync(id, t.Title), "Saved"))
            .RequireAuthorization(HubPolicies.Manage);
        api.MapDelete("/hub/instances/{id}", async (InstanceRegistry r, string id) => new ActionResult(await r.RemoveInstanceAsync(id), "Instance removed"))
            .RequireAuthorization(HubPolicies.Admin);

        // joining keys (admin)
        var keys = api.MapGroup("/hub/joiningkeys").RequireAuthorization(HubPolicies.Admin);
        keys.MapGet("/", (InstanceRegistry r) => r.GetJoiningKeysAsync());
        keys.MapPost("/", (InstanceRegistry r, JoiningKeyRequest k) => r.CreateJoiningKeyAsync(k.Title, k.ExpiryDays));
        keys.MapDelete("/{id}", async (InstanceRegistry r, string id) => new ActionResult(await r.RevokeJoiningKeyAsync(id), "Joining key revoked"));

        // aggregated certificates + dashboard
        api.MapGet("/hub/items", (InstanceGateway g, string? search) => g.GetAllManagedCertificatesAsync(search));
        api.MapGet("/hub/summary", async (InstanceGateway g, InstanceRegistry r) =>
        {
            var instances = await r.GetInstancesAsync();
            var items = await g.GetAllManagedCertificatesAsync(null);
            var now = DateTimeOffset.UtcNow;
            return new HubSummary
            {
                Instances = instances.Count,
                InstancesConnected = instances.Count(i => i.IsConnected),
                Certificates = ManagedInstanceSummary.From(items),
                UpcomingRenewals = items.Where(i => i.DateExpiry != null).OrderBy(i => i.DateExpiry).Take(10).ToList(),
                AttentionItems = items.Where(i => i.Health is ManagedCertificateHealth.Error or ManagedCertificateHealth.Warning).Take(20).ToList(),
            };
        });

        // per-instance operations (proxied)
        var inst = api.MapGroup("/instances/{iid}");
        inst.MapGet("/certificates/{id}", (InstanceGateway g, string iid, string id) => Proxy(g, iid, InstanceCommands.GetManagedCertificate, new { id }));
        inst.MapPost("/certificates", (InstanceGateway g, string iid, ManagedCertificate item) => Proxy(g, iid, InstanceCommands.UpdateManagedCertificate, item)).RequireAuthorization(HubPolicies.Manage);
        inst.MapDelete("/certificates/{id}", (InstanceGateway g, string iid, string id) => Proxy(g, iid, InstanceCommands.DeleteManagedCertificate, new { id })).RequireAuthorization(HubPolicies.Manage);
        inst.MapPost("/certificates/test", (InstanceGateway g, string iid, ManagedCertificate item) => Proxy(g, iid, InstanceCommands.TestConfiguration, item, 180)).RequireAuthorization(HubPolicies.Manage);
        inst.MapPost("/certificates/{id}/request", (InstanceGateway g, string iid, string id) => Proxy(g, iid, InstanceCommands.PerformRequest, new { id })).RequireAuthorization(HubPolicies.Manage);
        inst.MapPost("/certificates/{id}/revoke", (InstanceGateway g, string iid, string id) => Proxy(g, iid, InstanceCommands.RevokeCertificate, new { id })).RequireAuthorization(HubPolicies.Manage);
        inst.MapGet("/certificates/{id}/log", (InstanceGateway g, string iid, string id) => Proxy(g, iid, InstanceCommands.GetItemLog, new { id }));
        inst.MapGet("/certificates/{id}/progress", (InstanceRegistry r, string iid, string id) => r.GetProgress(iid, id) is { } p ? Results.Ok(p) : Results.NoContent());
        inst.MapGet("/certificates/{id}/download", async (InstanceGateway g, string iid, string id, CertificateDownloadFormat? format) =>
        {
            try
            {
                var f = await g.SendAsync<DownloadResult>(iid, InstanceCommands.DownloadCertificate, new { id, format = format ?? CertificateDownloadFormat.pfx });
                return f == null ? Results.NotFound() : Results.File(Convert.FromBase64String(f.Base64), f.ContentType, f.FileName);
            }
            catch (InstanceUnavailableException ex) { return Results.Problem(ex.Message, statusCode: 503); }
            catch (Exception ex) { return Results.Problem(ex.Message, statusCode: 400); }
        }).RequireAuthorization(HubPolicies.Manage);
        inst.MapPost("/renewall", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.PerformRenewAll, null)).RequireAuthorization(HubPolicies.Manage);
        inst.MapGet("/providers/challenges", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetChallengeProviders, null));
        inst.MapGet("/providers/deployment", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetDeploymentProviders, null));
        inst.MapGet("/credentials", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetCredentials, null));
        inst.MapGet("/credentials/types", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetCredentialTypes, null));
        inst.MapPost("/credentials", (InstanceGateway g, string iid, StoredCredential c) => Proxy(g, iid, InstanceCommands.UpdateCredential, c)).RequireAuthorization(HubPolicies.Manage);
        inst.MapDelete("/credentials/{key}", (InstanceGateway g, string iid, string key) => Proxy(g, iid, InstanceCommands.DeleteCredential, new { id = key })).RequireAuthorization(HubPolicies.Manage);
        inst.MapGet("/accounts", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetAccounts, null));
        inst.MapGet("/accounts/authorities", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetCertificateAuthorities, null));
        inst.MapPost("/accounts", (InstanceGateway g, string iid, NewAccountRequest r) => Proxy(g, iid, InstanceCommands.AddAccount, r, 120)).RequireAuthorization(HubPolicies.Manage);
        inst.MapDelete("/accounts/{key}", (InstanceGateway g, string iid, string key) => Proxy(g, iid, InstanceCommands.RemoveAccount, new { id = key })).RequireAuthorization(HubPolicies.Manage);
        inst.MapGet("/system/version", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetSystemVersion, null));
        inst.MapPost("/certificates/preview", (InstanceGateway g, string iid, ManagedCertificate item) => Proxy(g, iid, InstanceCommands.GeneratePreview, item, 120)).RequireAuthorization(HubPolicies.Manage);
        inst.MapPost("/certificates/{id}/tasks/{taskId}/execute", (InstanceGateway g, string iid, string id, string taskId, bool? preview) =>
            Proxy(g, iid, InstanceCommands.PerformDeploymentTask, new { id, taskId, preview = preview ?? false }, 300)).RequireAuthorization(HubPolicies.Manage);
        inst.MapGet("/server/status", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetServerStatus, null));
        inst.MapGet("/server/sites", (InstanceGateway g, string iid) => Proxy(g, iid, InstanceCommands.GetSites, null));
        inst.MapGet("/server/sites/{siteId}/domains", (InstanceGateway g, string iid, string siteId) => Proxy(g, iid, InstanceCommands.GetSiteDomains, new { id = siteId }));
    }

    private record DownloadResult(string FileName, string ContentType, string Base64);

    private static string UserId(ClaimsPrincipal u) => u.FindFirstValue("sub") ?? "";

    /// <summary>Forward a command to an instance and return its JSON result verbatim.</summary>
    private static async Task<IResult> Proxy(InstanceGateway g, string instanceId, string command, object? payload, int timeoutSeconds = 60)
    {
        try
        {
            var r = await g.SendAsync(instanceId, command, payload, TimeSpan.FromSeconds(timeoutSeconds));
            if (!r.IsSuccess) return Results.Problem(r.Message ?? "Command failed", statusCode: 400);
            return Results.Content(r.Result ?? "null", "application/json");
        }
        catch (InstanceUnavailableException ex) { return Results.Problem(ex.Message, statusCode: 503); }
    }
}
