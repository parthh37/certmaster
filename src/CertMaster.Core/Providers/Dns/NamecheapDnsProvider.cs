using System.Xml.Linq;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>One host record as returned by namecheap.domains.dns.getHosts.</summary>
public sealed record NamecheapHost(string Name, string Type, string Address, string MXPref = "10", string TTL = "1800");

/// <summary>
/// Pure record-merge logic for Namecheap. setHosts REPLACES every host record of the domain, so an update must
/// re-send all existing records unchanged plus/minus the one TXT value.
/// </summary>
public static class NamecheapHostMerge
{
    /// <summary>Parses a getHosts response: (hosts, EmailType, IsUsingOurDNS). Throws on API errors.</summary>
    public static (List<NamecheapHost> Hosts, string? EmailType, bool UsingNamecheapDns) ParseGetHosts(string xml)
    {
        var doc = NamecheapDnsProvider.ParseResponse(xml);
        var result = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "DomainDNSGetHostsResult")
                     ?? throw new DnsProviderException("Namecheap: getHosts response did not contain DomainDNSGetHostsResult.");
        var hosts = result.Elements().Where(e => e.Name.LocalName.Equals("host", StringComparison.OrdinalIgnoreCase))
            .Select(h => new NamecheapHost(
                Attr(h, "Name") ?? "@",
                Attr(h, "Type") ?? "",
                Attr(h, "Address") ?? "",
                Attr(h, "MXPref") ?? "10",
                Attr(h, "TTL") ?? "1800"))
            .ToList();
        var usingOurs = !string.Equals(Attr(result, "IsUsingOurDNS"), "false", StringComparison.OrdinalIgnoreCase);
        return (hosts, Attr(result, "EmailType"), usingOurs);
    }

    private static string? Attr(XElement e, string name) =>
        e.Attributes().FirstOrDefault(a => a.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    private static bool IsOurTxt(NamecheapHost h, string hostName, string value) =>
        h.Type.Equals("TXT", StringComparison.OrdinalIgnoreCase) && h.Name.Equals(hostName, StringComparison.OrdinalIgnoreCase) && TxtValues.Matches(h.Address, value);

    /// <summary>All existing hosts (unchanged, same order) plus the TXT value unless it already exists.</summary>
    public static List<NamecheapHost> AddTxt(IEnumerable<NamecheapHost> hosts, string hostName, string value, int ttl = 60)
    {
        var list = hosts.ToList();
        if (!list.Any(h => IsOurTxt(h, hostName, value))) list.Add(new NamecheapHost(hostName, "TXT", value, "10", ttl.ToString()));
        return list;
    }

    /// <summary>All existing hosts (unchanged, same order) except the TXT record(s) with this name and value.</summary>
    public static List<NamecheapHost> RemoveTxt(IEnumerable<NamecheapHost> hosts, string hostName, string value) =>
        hosts.Where(h => !IsOurTxt(h, hostName, value)).ToList();

    /// <summary>Form fields for namecheap.domains.dns.setHosts (without the API auth fields).</summary>
    public static List<KeyValuePair<string, string>> BuildSetHostsFields(string sld, string tld, IReadOnlyList<NamecheapHost> hosts, string? emailType)
    {
        var f = new List<KeyValuePair<string, string>>
        {
            new("Command", "namecheap.domains.dns.setHosts"),
            new("SLD", sld),
            new("TLD", tld),
        };
        // Keep the domain's mail setting; without it Namecheap may ignore/reset MX records.
        if (!string.IsNullOrWhiteSpace(emailType)) f.Add(new("EmailType", emailType));
        for (var i = 0; i < hosts.Count; i++)
        {
            var n = (i + 1).ToString();
            var h = hosts[i];
            f.Add(new("HostName" + n, h.Name));
            f.Add(new("RecordType" + n, h.Type));
            f.Add(new("Address" + n, h.Address));
            f.Add(new("MXPref" + n, h.MXPref));
            f.Add(new("TTL" + n, h.TTL));
        }
        return f;
    }
}

/// <summary>Namecheap XML API. Uses getHosts + setHosts, re-sending every existing record.</summary>
public class NamecheapDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.namecheap.com/xml.response";
    private const string SandboxApi = "https://api.sandbox.namecheap.com/xml.response";
    private const string Name = "Namecheap";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Namecheap",
        Title = "Namecheap DNS API",
        Description = "Validates via Namecheap DNS (domain must use Namecheap BasicDNS/PremiumDNS). Enable API access and whitelist this server's public IP under Profile > Tools > API Access. All host records are re-sent on every change.",
        HelpUrl = "https://www.namecheap.com/support/api/intro/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 120,
        CredentialType = "Namecheap",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_user", Name = "API User (account username)", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "api_key", Name = "API Key", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "client_ip", Name = "Whitelisted public IPv4 of this server", IsRequired = true },
            new ProviderParameter { Key = "sandbox", Name = "Use sandbox API", Type = OptionType.Boolean, Value = "false" },
        }
    };

    /// <summary>Parses an API response; throws a <see cref="DnsProviderException"/> for Status="ERROR".</summary>
    public static XDocument ParseResponse(string xml)
    {
        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch (Exception) { throw new DnsProviderException($"Namecheap: unexpected (non-XML) response: {DnsHttp.Truncate(xml, 300)}"); }
        var root = doc.Root;
        var status = root?.Attributes().FirstOrDefault(a => a.Name.LocalName == "Status")?.Value;
        if (!string.Equals(status, "OK", StringComparison.OrdinalIgnoreCase))
        {
            var errors = doc.Descendants().Where(e => e.Name.LocalName == "Error")
                .Select(e => $"{e.Attributes().FirstOrDefault(a => a.Name.LocalName == "Number")?.Value}: {e.Value.Trim()}").ToList();
            var text = errors.Count > 0 ? string.Join("; ", errors) : DnsHttp.Truncate(xml, 300);
            var hint = text.Contains("1011150") || text.Contains("RequestIP", StringComparison.OrdinalIgnoreCase)
                       || text.Contains("ClientIp", StringComparison.OrdinalIgnoreCase) || text.Contains("whitelist", StringComparison.OrdinalIgnoreCase)
                ? " Whitelist this server's public IP under Profile > Tools > API Access and set it as the client IP."
                : text.Contains("1011102") || text.Contains("API Key") || text.Contains("ApiKey")
                    ? " Check the API user and API key, and that API access is enabled for the account."
                    : text.Contains("2019166") ? " The domain was not found in this Namecheap account." : "";
            throw new DnsProviderException($"Namecheap API error: {text}.{hint}");
        }
        return doc;
    }

    private async Task<XDocument> CallAsync(DnsProviderContext ctx, IEnumerable<KeyValuePair<string, string>> fields)
    {
        var user = ctx.Require("api_user", "API User", Name);
        var all = new List<KeyValuePair<string, string>>
        {
            new("ApiUser", user),
            new("ApiKey", ctx.Require("api_key", "API Key", Name)),
            new("UserName", user),
            new("ClientIp", ctx.Require("client_ip", "Client IP", Name)),
        };
        all.AddRange(fields);
        // POST so the API key never appears in a URL (and setHosts with many records fits).
        var req = new HttpRequestMessage(HttpMethod.Post, ctx.Flag("sandbox") ? SandboxApi : Api) { Content = new FormUrlEncodedContent(all) };
        return ParseResponse(await DnsHttp.SendAsync(ctx.Http, req, Name));
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 1; page < 100; page++)
        {
            var doc = await CallAsync(ctx, new KeyValuePair<string, string>[]
            {
                new("Command", "namecheap.domains.getList"), new("PageSize", "100"), new("Page", page.ToString()),
            });
            var domains = doc.Descendants().Where(e => e.Name.LocalName == "Domain")
                .Select(e => e.Attributes().FirstOrDefault(a => a.Name.LocalName == "Name")?.Value)
                .Where(n => !string.IsNullOrEmpty(n)).ToList();
            zones.AddRange(domains.Select(d => new DnsZone(d!, d!)));
            var total = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "TotalItems")?.Value;
            if (domains.Count == 0 || !int.TryParse(total, out var t) || zones.Count >= t) break;
        }
        return zones;
    }

    private async Task<(DnsZone Zone, string Sld, string Tld, string Host, List<NamecheapHost> Hosts, string? EmailType)> LoadAsync(DnsProviderContext ctx, string recordName)
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var (sld, tld) = DnsNames.SplitZone(zone.Name);
        var doc = await CallAsync(ctx, new KeyValuePair<string, string>[] { new("Command", "namecheap.domains.dns.getHosts"), new("SLD", sld), new("TLD", tld) });
        var (hosts, emailType, usingOurs) = NamecheapHostMerge.ParseGetHosts(doc.ToString());
        if (!usingOurs)
            throw new DnsProviderException($"Namecheap: {zone.Name} does not use Namecheap DNS, so its records cannot be changed here. Use the provider that hosts the zone's name servers.");
        if (hosts.Any(h => h.Type.Equals("CAA", StringComparison.OrdinalIgnoreCase)))
            ctx.Log?.Warn($"Namecheap: {zone.Name} has CAA records; they are re-sent as returned by getHosts. Verify them after the request.");
        return (zone, sld, tld, RelativeName(recordName, zone.Name), hosts, emailType);
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var (zone, sld, tld, host, hosts, emailType) = await LoadAsync(ctx, recordName);
        var merged = NamecheapHostMerge.AddTxt(hosts, host, value);
        if (merged.Count == hosts.Count) return ActionResult.Ok($"TXT {host} in {zone.Name} already has this value");
        await CallAsync(ctx, NamecheapHostMerge.BuildSetHostsFields(sld, tld, merged, emailType));
        return ActionResult.Ok($"Added TXT {host} to {zone.Name} ({merged.Count} host records preserved/sent)");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var (zone, sld, tld, host, hosts, emailType) = await LoadAsync(ctx, recordName);
        var remaining = NamecheapHostMerge.RemoveTxt(hosts, host, value);
        if (remaining.Count == hosts.Count) return ActionResult.Ok($"TXT {host} in {zone.Name} with this value was already absent");
        if (remaining.Count == 0)
            return ActionResult.Fail($"Namecheap: refusing to send an empty host list for {zone.Name}; remove the TXT record {host} manually.");
        await CallAsync(ctx, NamecheapHostMerge.BuildSetHostsFields(sld, tld, remaining, emailType));
        return ActionResult.Ok($"Removed TXT {host} from {zone.Name}");
    });
}
