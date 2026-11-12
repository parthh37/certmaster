using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

public class GoDaddyDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.godaddy.com/v1/";
    private const string Name = "GoDaddy";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.GoDaddy",
        Title = "GoDaddy DNS API",
        Description = "Validates via GoDaddy DNS using a production API key and secret. Note: GoDaddy only grants DNS API access to some account types.",
        HelpUrl = "https://developer.godaddy.com/keys",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 120,
        CredentialType = "GoDaddy",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_key", Name = "API Key", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "api_secret", Name = "API Secret", Type = OptionType.Password, IsRequired = true, IsCredential = true },
        }
    };

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var key = ctx.Require("api_key", "API Key", Name);
        var secret = ctx.Require("api_secret", "API Secret", Name);
        var r = new HttpRequestMessage(m, Api + path);
        r.Headers.TryAddWithoutValidation("Authorization", $"sso-key {key}:{secret}");
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    private static async Task<string> SendAsync(DnsProviderContext ctx, HttpRequestMessage req)
    {
        try { return await DnsHttp.SendAsync(ctx.Http, req, Name); }
        catch (DnsProviderException ex) when (ex.Message.Contains("ACCESS_DENIED") || ex.Message.Contains("(Forbidden)"))
        {
            throw new DnsProviderException(ex.Message + " GoDaddy restricts DNS API access by account type; check the key is a Production key and that API access is enabled for this account.", ex);
        }
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var json = await SendAsync(ctx, Req(ctx, HttpMethod.Get, "domains?statuses=ACTIVE&limit=1000"));
        return DnsHttp.ParseJson(json, Name).Items()
            .Select(d => d.Str("domain"))
            .Where(d => !string.IsNullOrEmpty(d))
            .Select(d => new DnsZone(d!, d!)).ToList();
    }

    private static async Task<bool> DomainExistsAsync(DnsProviderContext ctx, string domain)
    {
        using var req = Req(ctx, HttpMethod.Get, $"domains/{Uri.EscapeDataString(domain)}");
        using var resp = await ctx.Http.SendAsync(req);
        if (resp.IsSuccessStatusCode) return true;
        if ((int)resp.StatusCode is 404 or 422) return false;
        throw new DnsProviderException(DnsHttp.Describe(Name, resp.StatusCode, await resp.Content.ReadAsStringAsync()));
    }

    // Zone id == domain name, so probe candidate names (longest first) instead of listing every domain.
    protected override async Task<DnsZone?> GetZoneByIdAsync(DnsProviderContext ctx, string zoneId)
    {
        var d = DnsNames.Normalize(zoneId);
        return await DomainExistsAsync(ctx, d) ? new DnsZone(d, d) : null;
    }

    protected override async Task<DnsZone?> ResolveZoneAsync(DnsProviderContext ctx, string recordName)
    {
        if (!string.IsNullOrWhiteSpace(ctx.ZoneId)) return await base.ResolveZoneAsync(ctx, recordName);
        foreach (var candidate in DnsNames.CandidateZones(recordName, includeSelf: false))
            if (await DomainExistsAsync(ctx, candidate)) return new DnsZone(candidate, candidate);
        return null;
    }

    private static async Task<List<(string Data, int Ttl)>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string rel)
    {
        var json = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"domains/{zone.Name}/records/TXT/{Uri.EscapeDataString(rel)}"));
        return DnsHttp.ParseJson(json, Name).Items()
            .Select(r => (r.Str("data") ?? "", int.TryParse(r.Str("ttl"), out var t) ? t : 600)).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var existing = await GetTxtAsync(ctx, zone, rel);
        if (existing.Any(r => TxtValues.Matches(r.Data, value)))
            return ActionResult.Ok($"TXT {rel} in {zone.Name} already has this value");
        // PATCH appends records and leaves the other values on this name in place.
        await SendAsync(ctx, Req(ctx, HttpMethod.Patch, $"domains/{zone.Name}/records",
            new[] { new { type = "TXT", name = rel, data = value, ttl = 600 } }));
        return ActionResult.Ok($"Created TXT {rel} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var existing = await GetTxtAsync(ctx, zone, rel);
        if (!existing.Any(r => TxtValues.Matches(r.Data, value)))
            return ActionResult.Ok($"TXT {rel} in {zone.Name} with this value was already absent");
        // Keep any other TXT values on the same name, remove only ours.
        var remaining = existing.Where(r => !TxtValues.Matches(r.Data, value)).ToList();
        if (remaining.Count == 0)
            await SendAsync(ctx, Req(ctx, HttpMethod.Delete, $"domains/{zone.Name}/records/TXT/{Uri.EscapeDataString(rel)}"));
        else
            await SendAsync(ctx, Req(ctx, HttpMethod.Put, $"domains/{zone.Name}/records/TXT/{Uri.EscapeDataString(rel)}",
                remaining.Select(r => new { data = r.Data, ttl = Math.Max(600, r.Ttl) }).ToArray()));
        return ActionResult.Ok($"Removed TXT value from {rel} in {zone.Name}");
    });
}
