using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>OVHcloud API with signed requests. Each TXT value is a separate record; the zone is refreshed after changes.</summary>
public class OvhDnsProvider : DnsProviderBase
{
    private const string Name = "OVH";
    private static readonly ConditionalWeakTable<DnsProviderContext, StrongBox<long>> TimeDeltas = new();

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.OVH",
        Title = "OVHcloud DNS API",
        Description = "Validates via OVHcloud DNS using an application key, application secret and consumer key (with GET/POST/DELETE rights on /domain/zone/*).",
        HelpUrl = "https://help.ovhcloud.com/csm/en-gb-api-getting-started-ovhcloud-api",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 60,
        CredentialType = "OVH",
        ProviderParameters =
        {
            new ProviderParameter { Key = "application_key", Name = "Application Key", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "application_secret", Name = "Application Secret", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "consumer_key", Name = "Consumer Key", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter
            {
                Key = "endpoint", Name = "API Endpoint", Type = OptionType.Select, Value = "ovh-eu",
                OptionsList = "ovh-eu=OVHcloud Europe;ovh-ca=OVHcloud Canada;ovh-us=OVHcloud US;soyoustart-eu=So you Start Europe;soyoustart-ca=So you Start Canada;kimsufi-eu=Kimsufi Europe;kimsufi-ca=Kimsufi Canada",
            },
        }
    };

    public static string ApiBase(string? endpoint) => (endpoint ?? "ovh-eu").Trim().ToLowerInvariant() switch
    {
        "ovh-eu" => "https://eu.api.ovh.com/1.0",
        "ovh-ca" => "https://ca.api.ovh.com/1.0",
        "ovh-us" => "https://api.us.ovhcloud.com/1.0",
        "soyoustart-eu" => "https://eu.api.soyoustart.com/1.0",
        "soyoustart-ca" => "https://ca.api.soyoustart.com/1.0",
        "kimsufi-eu" => "https://eu.api.kimsufi.com/1.0",
        "kimsufi-ca" => "https://ca.api.kimsufi.com/1.0",
        var e when e.StartsWith("https://") => e.TrimEnd('/'),
        var e => throw new DnsProviderException($"OVH: unknown API endpoint '{e}'. Use ovh-eu, ovh-ca or ovh-us."),
    };

    // ---------- signing (unit tested) ----------

    /// <summary>X-Ovh-Signature: "$1$" + hex SHA1 of "AS+CK+METHOD+FULLURL+BODY+TIMESTAMP".</summary>
    public static string ComputeSignature(string appSecret, string consumerKey, string method, string fullUrl, string body, long timestamp)
    {
        var toSign = $"{appSecret}+{consumerKey}+{method.ToUpperInvariant()}+{fullUrl}+{body}+{timestamp}";
        return "$1$" + Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(toSign))).ToLowerInvariant();
    }

    private static async Task<long> GetTimeDeltaAsync(DnsProviderContext ctx, string apiBase)
    {
        if (TimeDeltas.TryGetValue(ctx, out var box)) return box.Value;
        long delta = 0;
        try
        {
            var text = await DnsHttp.SendAsync(ctx.Http, new HttpRequestMessage(HttpMethod.Get, apiBase + "/auth/time"), Name);
            if (long.TryParse(text.Trim(), out var serverTime)) delta = serverTime - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
        catch { /* fall back to local time */ }
        TimeDeltas.AddOrUpdate(ctx, new StrongBox<long>(delta));
        return delta;
    }

    private static async Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpMethod method, string path, object? body = null)
    {
        var ak = ctx.Require("application_key", "Application Key", Name);
        var asec = ctx.Require("application_secret", "Application Secret", Name);
        var ck = ctx.Require("consumer_key", "Consumer Key", Name);
        var apiBase = ApiBase(ctx.Param("endpoint"));
        var url = apiBase + path;
        var json = body == null ? "" : DnsHttp.Serialize(body);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + await GetTimeDeltaAsync(ctx, apiBase);

        var req = new HttpRequestMessage(method, url);
        req.Headers.TryAddWithoutValidation("X-Ovh-Application", ak);
        req.Headers.TryAddWithoutValidation("X-Ovh-Consumer", ck);
        req.Headers.TryAddWithoutValidation("X-Ovh-Timestamp", ts.ToString());
        req.Headers.TryAddWithoutValidation("X-Ovh-Signature", ComputeSignature(asec, ck, method.Method, url, json, ts));
        if (body != null) req.Content = new StringContent(json, Encoding.UTF8, "application/json");
        try { return await DnsHttp.SendJsonAsync(ctx.Http, req, Name); }
        catch (DnsProviderException ex) when (ex.Message.Contains(" 403 ") || ex.Message.Contains(" 401 "))
        {
            throw new DnsProviderException(ex.Message + " Check the consumer key is validated and has GET/POST/DELETE rights on /domain/zone/* for this application.", ex);
        }
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var doc = await SendAsync(ctx, HttpMethod.Get, "/domain/zone");
        return doc.Items().Select(z => z.GetString()!).Select(z => new DnsZone(z, z)).ToList();
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string sub)
    {
        var query = $"/domain/zone/{zone.Name}/record?fieldType=TXT" + (sub.Length > 0 ? "&subDomain=" + Uri.EscapeDataString(sub) : "");
        var ids = (await SendAsync(ctx, HttpMethod.Get, query)).Items().Select(i => i.GetRawText()).ToList();
        var records = new List<JsonElement>();
        foreach (var id in ids)
        {
            var r = await SendAsync(ctx, HttpMethod.Get, $"/domain/zone/{zone.Name}/record/{id}");
            if (string.Equals(r.Str("subDomain") ?? "", sub, StringComparison.OrdinalIgnoreCase)) records.Add(r);
        }
        return records;
    }

    private static Task RefreshAsync(DnsProviderContext ctx, DnsZone zone) => SendAsync(ctx, HttpMethod.Post, $"/domain/zone/{zone.Name}/refresh");

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var sub = DnsNames.RelativeName(recordName, zone.Name, apex: "");
        if ((await GetTxtAsync(ctx, zone, sub)).Any(r => TxtValues.Matches(r.Str("target"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await SendAsync(ctx, HttpMethod.Post, $"/domain/zone/{zone.Name}/record", new { fieldType = "TXT", subDomain = sub, target = value, ttl = 60 });
        await RefreshAsync(ctx, zone);
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name} and refreshed the zone");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var sub = DnsNames.RelativeName(recordName, zone.Name, apex: "");
        var deleted = 0;
        foreach (var r in await GetTxtAsync(ctx, zone, sub))
        {
            if (!TxtValues.Matches(r.Str("target"), value)) continue;
            await SendAsync(ctx, HttpMethod.Delete, $"/domain/zone/{zone.Name}/record/{r.Str("id")}");
            deleted++;
        }
        if (deleted > 0) await RefreshAsync(ctx, zone);
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
