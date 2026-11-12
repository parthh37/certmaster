using System.Net.Http.Headers;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>DigitalOcean Domains API. Each TXT value is its own record, so add/remove are independent.</summary>
public class DigitalOceanDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.digitalocean.com/v2/";
    private const string Name = "DigitalOcean";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.DigitalOcean",
        Title = "DigitalOcean DNS API",
        Description = "Validates via DigitalOcean DNS using a personal access token with read and write scope (domain:read, domain:create, domain:delete).",
        HelpUrl = "https://docs.digitalocean.com/reference/api/create-personal-access-token/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "DigitalOcean",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_token", Name = "API Token", Type = OptionType.Password, IsRequired = true, IsCredential = true },
        }
    };

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var r = new HttpRequestMessage(m, Api + path);
        r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.Require("api_token", "API Token", Name));
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    private static Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpRequestMessage req) => DnsHttp.SendJsonAsync(ctx.Http, req, Name);

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 1; page < 100; page++)
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"domains?per_page=200&page={page}"));
            foreach (var d in doc.Prop("domains").Items())
                if (d.Str("name") is { } n) zones.Add(new DnsZone(n, n));
            if (doc.Prop("links").Prop("pages").Str("next") == null) break;
        }
        return zones;
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string recordName)
    {
        var fqdn = DnsNames.Normalize(recordName);
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"domains/{zone.Name}/records?type=TXT&per_page=200&name={Uri.EscapeDataString(fqdn)}"));
        return doc.Prop("domain_records").Items().ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        if ((await GetTxtAsync(ctx, zone, recordName)).Any(r => TxtValues.Matches(r.Str("data"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"domains/{zone.Name}/records",
            new { type = "TXT", name = RelativeName(recordName, zone.Name), data = value, ttl = 30 }));
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var deleted = 0;
        foreach (var r in await GetTxtAsync(ctx, zone, recordName))
        {
            if (!TxtValues.Matches(r.Str("data"), value)) continue;
            await DnsHttp.SendAsync(ctx.Http, Req(ctx, HttpMethod.Delete, $"domains/{zone.Name}/records/{r.Str("id")}"), Name);
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
