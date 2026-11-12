using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Simple DNS Plus HTTP API (v2). Records are added/removed with PATCH /zones/{zone}/records.</summary>
public class SimpleDnsPlusDnsProvider : DnsProviderBase
{
    private const string Name = "Simple DNS Plus";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.SimpleDnsPlus",
        Title = "Simple DNS Plus HTTP API",
        Description = "Validates via a Simple DNS Plus server's HTTP API (enable it under Options > HTTP API). Only primary zones can be updated.",
        HelpUrl = "https://simpledns.plus/help/http-api",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "SimpleDnsPlus",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_url", Name = "HTTP API URL", IsRequired = true, Description = "e.g. http://dns.example.com:8053 (the /v2 path is added automatically)." },
            new ProviderParameter { Key = "username", Name = "Username (optional)", IsCredential = true },
            new ProviderParameter { Key = "password", Name = "Password (optional)", Type = OptionType.Password, IsCredential = true },
            new ProviderParameter { Key = "ignore_tls_errors", Name = "Ignore TLS certificate errors", Type = OptionType.Boolean, Value = "false", Description = "Only for servers using a self-signed HTTPS certificate." },
        }
    };

    public static string ApiRoot(string url)
    {
        var u = url.Trim().TrimEnd('/');
        if (!u.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) u = "http://" + u;
        return u.EndsWith("/v2", StringComparison.OrdinalIgnoreCase) ? u : u + "/v2";
    }

    private static async Task<T> WithClientAsync<T>(DnsProviderContext ctx, Func<HttpClient, Task<T>> f)
    {
        if (!ctx.Flag("ignore_tls_errors")) return await f(ctx.Http);
        using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
        return await f(http);
    }

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var r = new HttpRequestMessage(m, ApiRoot(ctx.Require("api_url", "HTTP API URL", Name)) + path);
        if (ctx.Cred("username") is { } user)
            r.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{ctx.Cred("password")}")));
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    private static Task<string> SendAsync(DnsProviderContext ctx, HttpRequestMessage req) =>
        WithClientAsync(ctx, http => DnsHttp.SendAsync(http, req, Name));

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var doc = DnsHttp.ParseJson(await SendAsync(ctx, Req(ctx, HttpMethod.Get, "/zones")), Name);
        return doc.Items()
            .Where(z => string.Equals(z.Str("Type"), "primary", StringComparison.OrdinalIgnoreCase))
            .Select(z => z.Str("Name")!).Select(n => new DnsZone(n, n)).ToList();
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string recordName)
    {
        var doc = DnsHttp.ParseJson(await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"/zones/{Uri.EscapeDataString(zone.Name)}/records")), Name);
        var fqdn = DnsNames.Normalize(recordName);
        return doc.Items().Where(r => r.Str("Type") == "TXT" && DnsNames.Normalize(r.Str("Name")) == fqdn).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        if ((await GetTxtAsync(ctx, zone, recordName)).Any(r => TxtValues.Matches(r.Str("Data"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, Req(ctx, HttpMethod.Patch, $"/zones/{Uri.EscapeDataString(zone.Name)}/records",
            new[] { new { Name = DnsNames.Normalize(recordName), Type = "TXT", TTL = 60, Data = value } }));
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var ours = (await GetTxtAsync(ctx, zone, recordName)).Where(r => TxtValues.Matches(r.Str("Data"), value)).ToList();
        if (ours.Count == 0) return ActionResult.Ok($"TXT {recordName} with this value was already absent");
        await SendAsync(ctx, Req(ctx, HttpMethod.Patch, $"/zones/{Uri.EscapeDataString(zone.Name)}/records",
            ours.Select(r => new { Name = r.Str("Name"), Type = "TXT", Data = value, Remove = true }).ToArray()));
        return ActionResult.Ok($"Deleted {ours.Count} TXT record(s) {recordName}");
    });
}
