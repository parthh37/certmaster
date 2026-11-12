using System.Net.Http.Headers;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Linode (Akamai Cloud) Domains API v4. Each TXT value is a separate record.</summary>
public class LinodeDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.linode.com/v4/";
    private const string Name = "Linode";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Linode",
        Title = "Linode DNS API",
        Description = "Validates via Linode (Akamai Cloud) DNS Manager using a personal access token with Domains Read/Write scope. Linode applies record changes every few minutes.",
        HelpUrl = "https://www.linode.com/docs/products/tools/api/guides/manage-api-tokens/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 120,
        CredentialType = "Linode",
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

    private static async Task<List<JsonElement>> GetAllAsync(DnsProviderContext ctx, string path)
    {
        var items = new List<JsonElement>();
        for (var page = 1; page < 100; page++)
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"{path}{(path.Contains('?') ? '&' : '?')}page={page}&page_size=500"));
            items.AddRange(doc.Prop("data").Items());
            if (!int.TryParse(doc.Str("pages"), out var pages) || page >= pages) break;
        }
        return items;
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx) =>
        (await GetAllAsync(ctx, "domains"))
            .Where(d => d.Str("type") != "slave") // secondary zones cannot be edited
            .Select(d => new DnsZone(d.Str("id")!, d.Str("domain")!)).ToList();

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string rel) =>
        (await GetAllAsync(ctx, $"domains/{zone.ZoneId}/records"))
            .Where(r => r.Str("type") == "TXT" && string.Equals(r.Str("name") ?? "", rel, StringComparison.OrdinalIgnoreCase))
            .ToList();

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = DnsNames.RelativeName(recordName, zone.Name, apex: "");
        if ((await GetTxtAsync(ctx, zone, rel)).Any(r => TxtValues.Matches(r.Str("target"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"domains/{zone.ZoneId}/records",
            new { type = "TXT", name = rel, target = value, ttl_sec = 300 }));
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = DnsNames.RelativeName(recordName, zone.Name, apex: "");
        var deleted = 0;
        foreach (var r in await GetTxtAsync(ctx, zone, rel))
        {
            if (!TxtValues.Matches(r.Str("target"), value)) continue;
            await SendAsync(ctx, Req(ctx, HttpMethod.Delete, $"domains/{zone.ZoneId}/records/{r.Str("id")}"));
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
