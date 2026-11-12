using System.Net.Http.Headers;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>
/// Hetzner DNS. Supports the Hetzner Cloud DNS API (api.hetzner.cloud, RRSets with add/remove record actions) and the
/// legacy DNS Console API (dns.hetzner.com, one record per value).
/// </summary>
public class HetznerDnsProvider : DnsProviderBase
{
    private const string CloudApi = "https://api.hetzner.cloud/v1/";
    private const string LegacyApi = "https://dns.hetzner.com/api/v1/";
    private const string Name = "Hetzner DNS";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Hetzner",
        Title = "Hetzner DNS API",
        Description = "Validates via Hetzner DNS using an API token: a Hetzner Cloud project token (read & write) for zones in the Hetzner Console, or a legacy DNS Console token.",
        HelpUrl = "https://docs.hetzner.cloud/reference/cloud#zones",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 60,
        CredentialType = "Hetzner",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_token", Name = "API Token", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "api", Name = "API", Type = OptionType.Select, Value = "cloud", OptionsList = "cloud=Hetzner Cloud DNS API (api.hetzner.cloud);legacy=Legacy DNS Console API (dns.hetzner.com)" },
        }
    };

    private static bool Legacy(DnsProviderContext ctx) => string.Equals(ctx.Param("api"), "legacy", StringComparison.OrdinalIgnoreCase);

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var token = ctx.Require("api_token", "API Token", Name);
        HttpRequestMessage r;
        if (Legacy(ctx))
        {
            r = new HttpRequestMessage(m, LegacyApi + path);
            r.Headers.TryAddWithoutValidation("Auth-API-Token", token);
        }
        else
        {
            r = new HttpRequestMessage(m, CloudApi + path);
            r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    private static Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpRequestMessage req) => DnsHttp.SendJsonAsync(ctx.Http, req, Name);

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 1; page < 100; page++)
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones?per_page=100&page={page}"));
            foreach (var z in doc.Prop("zones").Items())
                zones.Add(new DnsZone(z.Str("id")!, z.Str("name")!));
            var pagination = doc.Prop("meta").Prop("pagination");
            if (Legacy(ctx))
            {
                if (!int.TryParse(pagination.Str("last_page"), out var last) || page >= last) break;
            }
            else if (pagination.Str("next_page") == null) break;
        }
        return zones;
    }

    // ---------- Cloud API (RRSets) ----------

    private static async Task<JsonElement?> GetRrsetAsync(DnsProviderContext ctx, DnsZone zone, string rel)
    {
        try
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones/{zone.ZoneId}/rrsets/{Uri.EscapeDataString(rel)}/TXT"));
            var set = doc.Prop("rrset");
            return set.ValueKind == JsonValueKind.Object ? set : null;
        }
        catch (DnsProviderException ex) when (ex.Message.Contains(" 404 ")) { return null; }
    }

    private static List<string> RrsetValues(JsonElement? set) =>
        set?.Prop("records").Items().Select(r => r.Str("value") ?? "").ToList() ?? new List<string>();

    private static async Task<ActionResult> CloudCreateAsync(DnsProviderContext ctx, DnsZone zone, string recordName, string value)
    {
        var rel = RelativeName(recordName, zone.Name);
        var set = await GetRrsetAsync(ctx, zone, rel);
        if (TxtValues.Contains(RrsetValues(set), value)) return ActionResult.Ok($"TXT {recordName} already has this value");
        var record = new { value = TxtValues.Quote(value), comment = "ACME challenge (CertMaster)" };
        if (set == null)
            await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"zones/{zone.ZoneId}/rrsets", new { name = rel, type = "TXT", ttl = 60, records = new[] { record } }));
        else
            await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"zones/{zone.ZoneId}/rrsets/{Uri.EscapeDataString(rel)}/TXT/actions/add_records", new { records = new[] { record } }));
        return ActionResult.Ok($"Added TXT value to {recordName} in {zone.Name}");
    }

    private static async Task<ActionResult> CloudDeleteAsync(DnsProviderContext ctx, DnsZone zone, string recordName, string value)
    {
        var rel = RelativeName(recordName, zone.Name);
        var set = await GetRrsetAsync(ctx, zone, rel);
        var values = RrsetValues(set);
        if (!TxtValues.Contains(values, value)) return ActionResult.Ok($"TXT {recordName} with this value was already absent");
        var ours = values.Where(v => TxtValues.Matches(v, value)).Select(v => new { value = v }).ToArray();
        if (TxtValues.Remove(values, value).Count == 0)
            await DnsHttp.SendAsync(ctx.Http, Req(ctx, HttpMethod.Delete, $"zones/{zone.ZoneId}/rrsets/{Uri.EscapeDataString(rel)}/TXT"), Name);
        else
            await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"zones/{zone.ZoneId}/rrsets/{Uri.EscapeDataString(rel)}/TXT/actions/remove_records", new { records = ours }));
        return ActionResult.Ok($"Removed TXT value from {recordName} in {zone.Name}");
    }

    // ---------- Legacy DNS Console API ----------

    private static async Task<List<JsonElement>> LegacyTxtAsync(DnsProviderContext ctx, DnsZone zone, string rel)
    {
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"records?zone_id={Uri.EscapeDataString(zone.ZoneId)}"));
        return doc.Prop("records").Items()
            .Where(r => r.Str("type") == "TXT" && string.Equals(r.Str("name"), rel, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        if (!Legacy(ctx)) return await CloudCreateAsync(ctx, zone, recordName, value);
        var rel = RelativeName(recordName, zone.Name);
        if ((await LegacyTxtAsync(ctx, zone, rel)).Any(r => TxtValues.Matches(r.Str("value"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, "records", new { zone_id = zone.ZoneId, type = "TXT", name = rel, value, ttl = 60 }));
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        if (!Legacy(ctx)) return await CloudDeleteAsync(ctx, zone, recordName, value);
        var rel = RelativeName(recordName, zone.Name);
        var deleted = 0;
        foreach (var r in await LegacyTxtAsync(ctx, zone, rel))
        {
            if (!TxtValues.Matches(r.Str("value"), value)) continue;
            await DnsHttp.SendAsync(ctx.Http, Req(ctx, HttpMethod.Delete, $"records/{r.Str("id")}"), Name);
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
