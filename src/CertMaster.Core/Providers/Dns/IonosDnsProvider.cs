using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>IONOS Hosting DNS API (api.hosting.ionos.com). Each TXT value is a separate record.</summary>
public class IonosDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.hosting.ionos.com/dns/v1/";
    private const string Name = "IONOS";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.IONOS",
        Title = "IONOS DNS API",
        Description = "Validates via IONOS DNS using an API key (public prefix and secret) from the IONOS developer portal.",
        HelpUrl = "https://developer.hosting.ionos.com/docs/getstarted",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 60,
        CredentialType = "IONOS",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_prefix", Name = "API Key Public Prefix", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "api_secret", Name = "API Key Secret", Type = OptionType.Password, IsRequired = true, IsCredential = true },
        }
    };

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var prefix = ctx.Require("api_prefix", "API Key Public Prefix", Name);
        var secret = ctx.Require("api_secret", "API Key Secret", Name);
        var r = new HttpRequestMessage(m, Api + path);
        r.Headers.TryAddWithoutValidation("X-API-Key", $"{prefix}.{secret}");
        r.Headers.TryAddWithoutValidation("Accept", "application/json");
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    private static Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpRequestMessage req) => DnsHttp.SendJsonAsync(ctx.Http, req, Name);

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, "zones"));
        return doc.Items().Select(z => new DnsZone(z.Str("id")!, z.Str("name")!)).ToList();
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string recordName)
    {
        var fqdn = DnsNames.Normalize(recordName);
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones/{zone.ZoneId}?recordType=TXT&recordName={Uri.EscapeDataString(fqdn)}"));
        return doc.Prop("records").Items()
            .Where(r => r.Str("type") == "TXT" && DnsNames.Normalize(r.Str("name")) == fqdn).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        if ((await GetTxtAsync(ctx, zone, recordName)).Any(r => TxtValues.Matches(r.Str("content"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"zones/{zone.ZoneId}/records",
            new[] { new { name = DnsNames.Normalize(recordName), type = "TXT", content = value, ttl = 60, prio = 0, disabled = false } }));
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var deleted = 0;
        foreach (var r in await GetTxtAsync(ctx, zone, recordName))
        {
            if (!TxtValues.Matches(r.Str("content"), value)) continue;
            await DnsHttp.SendAsync(ctx.Http, Req(ctx, HttpMethod.Delete, $"zones/{zone.ZoneId}/records/{r.Str("id")}"), Name);
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
