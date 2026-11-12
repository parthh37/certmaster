using System.Net;
using CertMaster.Models;

namespace CertMaster.Core.Iis;

/// <summary>Turns binding hostnames into domain options for a new certificate.</summary>
public static class DomainOptionBuilder
{
    private static readonly string[] NonPublicSuffixes =
        { ".localhost", ".local", ".lan", ".internal", ".intranet", ".home.arpa", ".test", ".invalid", ".example" };

    /// <summary>
    /// Deduplicates (case-insensitive) and lower-cases hostnames, keeping their order. Names a public CA cannot issue
    /// for are kept but unselected with a Comment. The first selectable name becomes the primary domain.
    /// </summary>
    public static List<DomainOption> FromHosts(IEnumerable<string?> hosts)
    {
        var result = new List<DomainOption>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in hosts)
        {
            var host = (raw ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (host.Length == 0 || !seen.Add(host)) continue;
            var reason = GetNonPublicReason(host);
            result.Add(new DomainOption
            {
                Domain = host,
                IsSelected = reason == null,
                Comment = reason ?? (host.StartsWith("*.") ? "Wildcard: requires dns-01 validation." : null),
            });
        }
        var primary = result.FirstOrDefault(o => o.IsSelected);
        if (primary != null) primary.IsPrimaryDomain = true;
        return result;
    }

    /// <summary>Why a public CA cannot issue a certificate for this name, or null when it looks like a public DNS name.</summary>
    public static string? GetNonPublicReason(string host)
    {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(h.Trim('[', ']'), out _)) return "IP address, not a domain name.";
        var check = h.StartsWith("*.") ? h[2..] : h;
        if (check == "localhost" || NonPublicSuffixes.Any(s => check.EndsWith(s, StringComparison.Ordinal)))
            return "Local or reserved name; a public CA cannot issue a certificate for it.";
        if (!check.Contains('.')) return "Single-label (intranet) name; a public CA cannot issue a certificate for it.";
        if (check.Contains('*') || Uri.CheckHostName(check) != UriHostNameType.Dns) return "Not a valid DNS name.";
        return null;
    }
}
