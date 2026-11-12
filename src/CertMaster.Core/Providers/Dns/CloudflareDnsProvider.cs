using System.Net.Http.Headers;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

public class CloudflareDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.cloudflare.com/client/v4/";
    private const string Name = "Cloudflare";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Cloudflare",
        Title = "Cloudflare DNS API",
        Description = "Validates via Cloudflare DNS using a scoped API token (Zone:Read, DNS:Edit). Optionally restrict zone lookup to one account.",
        HelpUrl = "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "Cloudflare",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_token", Name = "API Token", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "account_id", Name = "Account ID (optional)", Description = "Only look for zones in this Cloudflare account (useful when the token can see several accounts)." },
        }
    };

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod method, string path, object? body = null)
    {
        var token = ctx.Require("api_token", "API Token", Name);
        var r = new HttpRequestMessage(method, Api + path);
        r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    /// <summary>Sends a request and unwraps Cloudflare's {success, errors, result} envelope.</summary>
    private static async Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpRequestMessage req, params int[] okErrorCodes)
    {
        using (req)
        {
            using var resp = await ctx.Http.SendAsync(req);
            var text = await resp.Content.ReadAsStringAsync();
            JsonElement doc;
            try { doc = JsonDocument.Parse(text).RootElement.Clone(); }
            catch (JsonException) { throw new DnsProviderException(DnsHttp.Describe(Name, resp.StatusCode, text)); }

            var success = doc.Prop("success").ValueKind == JsonValueKind.True;
            if (resp.IsSuccessStatusCode && success) return doc;

            var errors = doc.Prop("errors").Items().ToList();
            if (errors.Count > 0 && errors.All(e => int.TryParse(e.Str("code"), out var c) && okErrorCodes.Contains(c))) return doc;
            var detail = errors.Count > 0 ? string.Join("; ", errors.Select(e => $"{e.Str("code")}: {e.Str("message")}")) : text;
            var hint = (int)resp.StatusCode switch
            {
                401 or 403 => " Check the API token is valid and has Zone:Read and DNS:Edit permission for this zone.",
                404 => " The zone was not found; check the zone id or that the token can access the zone.",
                429 => " Rate limited; retry in a few minutes.",
                _ => "",
            };
            throw new DnsProviderException($"Cloudflare API error ({(int)resp.StatusCode}): {DnsHttp.Truncate(detail, 500)}.{hint}");
        }
    }

    private static string AccountFilter(DnsProviderContext ctx) =>
        ctx.Param("account_id") is { } acct ? "&account.id=" + Uri.EscapeDataString(acct) : "";

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 1; page < 200; page++)
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones?per_page=50&page={page}{AccountFilter(ctx)}"));
            foreach (var z in doc.Prop("result").Items())
                zones.Add(new DnsZone(z.Str("id")!, z.Str("name")!));
            var totalPages = doc.Prop("result_info").Prop("total_pages");
            if (totalPages.ValueKind != JsonValueKind.Number || page >= totalPages.GetInt32()) break;
        }
        return zones;
    }

    protected override async Task<DnsZone?> GetZoneByIdAsync(DnsProviderContext ctx, string zoneId)
    {
        try
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones/{Uri.EscapeDataString(zoneId)}"));
            var z = doc.Prop("result");
            return new DnsZone(z.Str("id")!, z.Str("name")!);
        }
        catch (DnsProviderException)
        {
            // Maybe a zone name was given instead of an id.
            return await FindZoneByNameAsync(ctx, zoneId);
        }
    }

    private static async Task<DnsZone?> FindZoneByNameAsync(DnsProviderContext ctx, string name)
    {
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones?name={Uri.EscapeDataString(DnsNames.Normalize(name))}{AccountFilter(ctx)}"));
        var z = doc.Prop("result").Items().FirstOrDefault();
        return z.ValueKind == JsonValueKind.Object ? new DnsZone(z.Str("id")!, z.Str("name")!) : null;
    }

    /// <summary>Looks up candidate zone names (longest first) so tokens limited to a few zones work without listing every zone.</summary>
    protected override async Task<DnsZone?> ResolveZoneAsync(DnsProviderContext ctx, string recordName)
    {
        if (!string.IsNullOrWhiteSpace(ctx.ZoneId)) return await base.ResolveZoneAsync(ctx, recordName);
        foreach (var candidate in DnsNames.CandidateZones(recordName, includeSelf: false))
        {
            var z = await FindZoneByNameAsync(ctx, candidate);
            if (z != null) return z;
        }
        return null;
    }

    private static async Task<List<JsonElement>> GetTxtRecordsAsync(DnsProviderContext ctx, DnsZone zone, string recordName)
    {
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get,
            $"zones/{zone.ZoneId}/dns_records?type=TXT&per_page=100&name={Uri.EscapeDataString(DnsNames.Normalize(recordName))}"));
        return doc.Prop("result").Items().ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var existing = await GetTxtRecordsAsync(ctx, zone, recordName);
        if (existing.Any(r => TxtValues.Matches(r.Str("content"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value in zone {zone.Name}");
        // 81058 = "An identical record already exists" (e.g. a concurrent request created it).
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"zones/{zone.ZoneId}/dns_records",
            new { type = "TXT", name = DnsNames.Normalize(recordName), content = value, ttl = 60, comment = "ACME challenge (CertMaster)" }), 81058);
        return ActionResult.Ok($"Created TXT {recordName} in zone {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var deleted = 0;
        foreach (var rec in await GetTxtRecordsAsync(ctx, zone, recordName))
        {
            if (!TxtValues.Matches(rec.Str("content"), value)) continue;
            // 81044 = record already gone.
            await SendAsync(ctx, Req(ctx, HttpMethod.Delete, $"zones/{zone.ZoneId}/dns_records/{rec.Str("id")}"), 81044);
            deleted++;
        }
        return ActionResult.Ok(deleted > 0 ? $"Deleted {deleted} TXT record(s) {recordName}" : $"TXT {recordName} with this value was already absent");
    });
}
