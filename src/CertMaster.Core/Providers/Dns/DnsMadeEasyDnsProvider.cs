using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>DNS Made Easy REST API v2.0 with HMAC-SHA1 request signing. Each TXT value is a separate record.</summary>
public class DnsMadeEasyDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.dnsmadeeasy.com/V2.0/";
    private const string SandboxApi = "https://api.sandbox.dnsmadeeasy.com/V2.0/";
    private const string Name = "DNS Made Easy";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.DnsMadeEasy",
        Title = "DNS Made Easy API",
        Description = "Validates via DNS Made Easy using an API key and secret key (Account > API). The system clock must be accurate because requests are signed with the current time.",
        HelpUrl = "https://api-docs.dnsmadeeasy.com/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "DnsMadeEasy",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_key", Name = "API Key", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "api_secret", Name = "Secret Key", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "sandbox", Name = "Use sandbox API", Type = OptionType.Boolean, Value = "false" },
        }
    };

    // ---------- signing (unit tested) ----------

    /// <summary>x-dnsme-hmac: lower-case hex HMAC-SHA1 of the request date using the secret key.</summary>
    public static string ComputeHmac(string secretKey, string requestDate)
    {
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secretKey));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(requestDate))).ToLowerInvariant();
    }

    /// <summary>The three authentication headers for a request made at <paramref name="now"/>.</summary>
    public static IReadOnlyDictionary<string, string> BuildAuthHeaders(string apiKey, string secretKey, DateTimeOffset now)
    {
        var date = now.UtcDateTime.ToString("r", CultureInfo.InvariantCulture); // RFC 1123, e.g. "Sat, 12 Feb 2011 20:59:04 GMT"
        return new Dictionary<string, string>
        {
            ["x-dnsme-apiKey"] = apiKey,
            ["x-dnsme-requestDate"] = date,
            ["x-dnsme-hmac"] = ComputeHmac(secretKey, date),
        };
    }

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var key = ctx.Require("api_key", "API Key", Name);
        var secret = ctx.Require("api_secret", "Secret Key", Name);
        var r = new HttpRequestMessage(m, (ctx.Flag("sandbox") ? SandboxApi : Api) + path);
        foreach (var h in BuildAuthHeaders(key, secret, DateTimeOffset.UtcNow)) r.Headers.TryAddWithoutValidation(h.Key, h.Value);
        r.Headers.TryAddWithoutValidation("Accept", "application/json");
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    private static async Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpRequestMessage req)
    {
        try { return await DnsHttp.SendJsonAsync(ctx.Http, req, Name); }
        catch (DnsProviderException ex) when (ex.Message.Contains(" 403 ") || ex.Message.Contains(" 401 "))
        {
            throw new DnsProviderException(ex.Message + " DNS Made Easy also rejects requests when the server clock is more than a few seconds off; check the time is synchronised.", ex);
        }
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 0; page < 100; page++)
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"dns/managed/?page={page}&rows=1000"));
            foreach (var z in doc.Prop("data").Items()) zones.Add(new DnsZone(z.Str("id")!, z.Str("name")!));
            if (!int.TryParse(doc.Str("totalPages"), out var total) || page + 1 >= total) break;
        }
        return zones;
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string rel)
    {
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"dns/managed/{zone.ZoneId}/records?type=TXT&recordName={Uri.EscapeDataString(rel)}"));
        return doc.Prop("data").Items()
            .Where(r => r.Str("type") == "TXT" && string.Equals(r.Str("name") ?? "", rel, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = DnsNames.RelativeName(recordName, zone.Name, apex: "");
        if ((await GetTxtAsync(ctx, zone, rel)).Any(r => TxtValues.Matches(r.Str("value"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"dns/managed/{zone.ZoneId}/records",
            new { name = rel, type = "TXT", value = TxtValues.Quote(value), ttl = 60, gtdLocation = "DEFAULT" }));
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = DnsNames.RelativeName(recordName, zone.Name, apex: "");
        var deleted = 0;
        foreach (var r in await GetTxtAsync(ctx, zone, rel))
        {
            if (!TxtValues.Matches(r.Str("value"), value)) continue;
            await DnsHttp.SendAsync(ctx.Http, Req(ctx, HttpMethod.Delete, $"dns/managed/{zone.ZoneId}/records/{r.Str("id")}"), Name);
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
