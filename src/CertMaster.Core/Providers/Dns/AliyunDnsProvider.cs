using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Alibaba Cloud DNS (Aliyun alidns) RPC API with HMAC-SHA1 signature version 1.0. Each TXT value is a separate record.</summary>
public class AliyunDnsProvider : DnsProviderBase
{
    private const string Name = "Alibaba Cloud DNS";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Aliyun",
        Title = "Alibaba Cloud (Aliyun) DNS API",
        Description = "Validates via Alibaba Cloud DNS using a RAM user AccessKey (needs AliyunDNSFullAccess or equivalent alidns:DescribeDomains/DescribeDomainRecords/AddDomainRecord/DeleteDomainRecord).",
        HelpUrl = "https://www.alibabacloud.com/help/en/dns/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 60,
        CredentialType = "Aliyun",
        ProviderParameters =
        {
            new ProviderParameter { Key = "access_key_id", Name = "AccessKey ID", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "access_key_secret", Name = "AccessKey Secret", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "endpoint", Name = "API endpoint (optional)", Value = "alidns.aliyuncs.com", Description = "e.g. alidns.aliyuncs.com or a regional endpoint such as alidns.ap-southeast-1.aliyuncs.com" },
        }
    };

    // ---------- signing (unit tested) ----------

    /// <summary>RFC 3986 percent encoding as required by the Alibaba Cloud RPC signature (unreserved: A-Z a-z 0-9 - _ . ~).</summary>
    public static string PercentEncode(string value)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            var c = (char)b;
            if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_' or '.' or '~') sb.Append(c);
            else sb.Append('%').Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    /// <summary>Parameters sorted by name (ordinal), percent-encoded and joined with '&amp;'.</summary>
    public static string CanonicalQuery(IEnumerable<KeyValuePair<string, string>> parameters) =>
        string.Join("&", parameters.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => PercentEncode(p.Key) + "=" + PercentEncode(p.Value)));

    /// <summary>Base64 HMAC-SHA1 over "METHOD&amp;%2F&amp;percentEncode(canonicalQuery)" keyed with "secret&amp;".</summary>
    public static string ComputeSignature(string httpMethod, IEnumerable<KeyValuePair<string, string>> parameters, string accessKeySecret)
    {
        var stringToSign = httpMethod.ToUpperInvariant() + "&" + PercentEncode("/") + "&" + PercentEncode(CanonicalQuery(parameters));
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(accessKeySecret + "&"));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
    }

    /// <summary>Full signed GET URL for an action.</summary>
    public static string BuildSignedUrl(string endpoint, string accessKeyId, string accessKeySecret, string action, IDictionary<string, string> actionParameters, DateTimeOffset now, string nonce)
    {
        var p = new Dictionary<string, string>(actionParameters)
        {
            ["Action"] = action,
            ["Format"] = "JSON",
            ["Version"] = "2015-01-09",
            ["AccessKeyId"] = accessKeyId,
            ["SignatureMethod"] = "HMAC-SHA1",
            ["SignatureVersion"] = "1.0",
            ["SignatureNonce"] = nonce,
            ["Timestamp"] = now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
        };
        var signature = ComputeSignature("GET", p, accessKeySecret);
        return $"https://{endpoint}/?{CanonicalQuery(p)}&Signature={PercentEncode(signature)}";
    }

    private static async Task<JsonElement> CallAsync(DnsProviderContext ctx, string action, Dictionary<string, string> parameters, params string[] okCodes)
    {
        var id = ctx.Require("access_key_id", "AccessKey ID", Name);
        var secret = ctx.Require("access_key_secret", "AccessKey Secret", Name);
        var endpoint = (ctx.Param("endpoint") ?? "alidns.aliyuncs.com").Trim().TrimEnd('/');
        if (endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) endpoint = endpoint[8..];
        var url = BuildSignedUrl(endpoint, id, secret, action, parameters, DateTimeOffset.UtcNow, Guid.NewGuid().ToString());

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        using var resp = await ctx.Http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        var doc = DnsHttp.ParseJson(text, Name);
        if (resp.IsSuccessStatusCode) return doc;
        var code = doc.Str("Code");
        if (code != null && okCodes.Contains(code)) return doc;
        var hint = code switch
        {
            "InvalidAccessKeyId.NotFound" or "InvalidAccessKeyId" => " Check the AccessKey ID.",
            "SignatureDoesNotMatch" or "IncompleteSignature" => " Check the AccessKey Secret.",
            "Forbidden.RAM" or "Forbidden" => " Grant the RAM user AliyunDNSFullAccess (or the specific alidns actions).",
            "InvalidDomainName.NoExist" or "DomainRecordNotBelongToUser" => " The domain is not in this Alibaba Cloud account.",
            "InvalidTimeStamp.Expired" => " The server clock is wrong; synchronise the time.",
            _ => "",
        };
        throw new DnsProviderException($"Alibaba Cloud DNS error {(int)resp.StatusCode} {code}: {doc.Str("Message") ?? DnsHttp.Truncate(text, 300)}.{hint}");
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 1; page < 100; page++)
        {
            var doc = await CallAsync(ctx, "DescribeDomains", new() { ["PageNumber"] = page.ToString(), ["PageSize"] = "100" });
            var items = doc.Prop("Domains").Prop("Domain").Items().ToList();
            foreach (var d in items) if (d.Str("DomainName") is { } n) zones.Add(new DnsZone(n, n));
            if (!int.TryParse(doc.Str("TotalCount"), out var total) || zones.Count >= total || items.Count == 0) break;
        }
        return zones;
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string rr)
    {
        var doc = await CallAsync(ctx, "DescribeDomainRecords", new()
        {
            ["DomainName"] = zone.Name, ["RRKeyWord"] = rr, ["TypeKeyWord"] = "TXT", ["PageSize"] = "500",
        });
        return doc.Prop("DomainRecords").Prop("Record").Items()
            .Where(r => r.Str("Type") == "TXT" && string.Equals(r.Str("RR"), rr, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rr = RelativeName(recordName, zone.Name);
        if ((await GetTxtAsync(ctx, zone, rr)).Any(r => TxtValues.Matches(r.Str("Value"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await CallAsync(ctx, "AddDomainRecord", new() { ["DomainName"] = zone.Name, ["RR"] = rr, ["Type"] = "TXT", ["Value"] = value, ["TTL"] = "600" },
            "DomainRecordDuplicate");
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rr = RelativeName(recordName, zone.Name);
        var deleted = 0;
        foreach (var r in await GetTxtAsync(ctx, zone, rr))
        {
            if (!TxtValues.Matches(r.Str("Value"), value)) continue;
            await CallAsync(ctx, "DeleteDomainRecord", new() { ["RecordId"] = r.Str("RecordId")! });
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    });
}
