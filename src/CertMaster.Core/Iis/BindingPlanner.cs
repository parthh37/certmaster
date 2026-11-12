using CertMaster.Models;

namespace CertMaster.Core.Iis;

/// <summary>Input of the binding planner: what to deploy and how.</summary>
public class BindingPlanRequest
{
    public CertRequestConfig Config { get; set; } = new();
    /// <summary>The site associated with the certificate (ManagedCertificate.ServerSiteId).</summary>
    public string? ServerSiteId { get; set; }
    /// <summary>Certificate domains, wildcards allowed (e.g. "*.example.com").</summary>
    public List<string> Domains { get; set; } = new();
    /// <summary>Thumbprint of the certificate being deployed. Null in a preview before the certificate exists.</summary>
    public string? NewThumbprint { get; set; }
    /// <summary>Thumbprint of the certificate this one replaces (used by the "replace previous" match option).</summary>
    public string? PreviousThumbprint { get; set; }

    public static BindingPlanRequest FromItem(ManagedCertificate item, string? newThumbprint, string? previousThumbprint) => new()
    {
        Config = item.RequestConfig,
        ServerSiteId = item.ServerSiteId,
        Domains = item.GetAllDomains().ToList(),
        NewThumbprint = newThumbprint,
        PreviousThumbprint = previousThumbprint,
    };
}

/// <summary>Output of the binding planner.</summary>
public class BindingPlan
{
    public List<BindingAction> Actions { get; } = new();
    /// <summary>Things the user should know about because they may have side effects or need attention.</summary>
    public List<string> Warnings { get; } = new();
    /// <summary>Informational notes (skipped bindings, domains with nothing to do).</summary>
    public List<string> Notes { get; } = new();
    /// <summary>Set when the plan cannot be carried out (e.g. SingleSite without a valid site).</summary>
    public string? Error { get; set; }
    /// <summary>Matching bindings that already use the new certificate.</summary>
    public int UpToDateCount { get; set; }

    public IEnumerable<BindingAction> Updates => Actions.Where(a => !a.IsNewBinding);
    public IEnumerable<BindingAction> Additions => Actions.Where(a => a.IsNewBinding);
}

/// <summary>
/// Pure planner deciding which https bindings to update or add for a certificate, given a snapshot of the server's
/// sites. It has no dependency on IIS so it can be unit tested and used by preview.
/// </summary>
public static class BindingPlanner
{
    public static BindingPlan Plan(IReadOnlyList<ServerSiteSnapshot> sites, BindingPlanRequest request)
    {
        var plan = new BindingPlan();
        var cfg = request.Config;
        var mode = cfg.DeploymentSiteOption;
        if (mode == DeploymentOption.NoDeployment)
        {
            plan.Notes.Add("Automatic deployment is disabled; no bindings are changed.");
            return plan;
        }
        if (mode == DeploymentOption.CertificateStoreOnly)
        {
            plan.Notes.Add("Certificate is only stored in the machine certificate store; no bindings are changed.");
            return plan;
        }

        var domains = request.Domains
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim().TrimEnd('.').ToLowerInvariant())
            .Distinct().ToList();
        var newThumb = NormalizeThumbprint(request.NewThumbprint);
        var prevThumb = NormalizeThumbprint(request.PreviousThumbprint);
        if (prevThumb != null && prevThumb == newThumb) prevThumb = null;

        var siteId = string.IsNullOrWhiteSpace(request.ServerSiteId) ? null : request.ServerSiteId.Trim();
        var selectedSite = siteId == null ? null : sites.FirstOrDefault(s => s.Id == siteId);

        // Which sites may have existing bindings updated, and the default site for new bindings.
        IReadOnlyList<ServerSiteSnapshot> eligible;
        switch (mode)
        {
            case DeploymentOption.SingleSite:
                if (siteId == null) { plan.Error = "Single site deployment requires a site to be selected for this certificate."; return plan; }
                if (selectedSite == null) { plan.Error = $"The selected site (id {siteId}) was not found on this server."; return plan; }
                eligible = new[] { selectedSite };
                break;
            default: // Auto, AllSites
                if (siteId != null && selectedSite == null)
                    plan.Warnings.Add($"The selected site (id {siteId}) was not found on this server; new bindings cannot be added to it.");
                eligible = sites;
                break;
        }

        // ---- 1. Update existing https bindings that match ----
        var targeted = new HashSet<ServerBindingSnapshot>(ReferenceEqualityComparer.Instance);
        foreach (var site in eligible)
        {
            foreach (var b in site.Bindings.Where(b => b.IsHttps))
            {
                var reasons = MatchReasons(b, domains, cfg, prevThumb);
                if (reasons.Count == 0) continue;
                if (b.UsesCentralCertStore)
                {
                    plan.Notes.Add($"Binding {b.BindingInformation} on site '{site.Name}' uses the Centralized Certificate Store; skipped.");
                    continue;
                }
                var current = NormalizeThumbprint(b.CertificateHash);
                if (newThumb != null && current == newThumb)
                {
                    plan.UpToDateCount++;
                    plan.Notes.Add($"Binding {b.BindingInformation} on site '{site.Name}' already uses this certificate.");
                    continue;
                }
                targeted.Add(b);
                plan.Actions.Add(new BindingAction
                {
                    SiteId = site.Id, SiteName = site.Name, IsNewBinding = false, Protocol = "https",
                    IP = BindingEndpoint.NormalizeIP(b.IP), Port = b.Port, Host = b.Host, UseSNI = b.UsesSni,
                    PreviousThumbprint = current,
                    Description = $"Update https binding {b.BindingInformation} ({SniText(b.UsesSni)}) on site '{site.Name}' [{string.Join(", ", reasons)}]"
                                  + (current == null ? "" : $"; replaces certificate {Short(current)}"),
                });
            }
        }

        // ---- 2. Add new https bindings (AddOrUpdate only) ----
        if (cfg.DeploymentBindingOption == DeploymentBindingOption.AddOrUpdate)
        {
            var existingKeys = new Dictionary<string, string>(); // endpoint key -> site name (https bindings on any site)
            foreach (var s in sites)
                foreach (var b in s.Bindings.Where(b => b.IsHttps))
                    existingKeys.TryAdd(BindingEndpoint.Key(b.IP, b.Port, b.Host), s.Name);

            foreach (var domain in domains)
            {
                if (domain.StartsWith("*.")) continue; // wildcards never create bindings
                var covered = eligible.Any(s => s.Bindings.Any(b => b.IsHttps && string.Equals(b.Host, domain, StringComparison.OrdinalIgnoreCase)));
                if (covered) continue;

                var target = ResolveAddTarget(mode, sites, selectedSite, domain);
                if (target == null)
                {
                    plan.Notes.Add(mode == DeploymentOption.Auto
                        ? $"No https binding exists for {domain}; select a site for this certificate to have one added."
                        : $"No https binding exists for {domain} and no site serves it; select a site for this certificate to have one added.");
                    continue;
                }

                string ip; int port; bool sni;
                if (cfg.UseSpecificBindingIPPort)
                {
                    ip = BindingEndpoint.NormalizeIP(cfg.BindingIPAddress);
                    port = cfg.BindingPort is > 0 and <= 65535 ? cfg.BindingPort : 443;
                    sni = cfg.BindingUseSNI;
                }
                else { ip = "*"; port = 443; sni = true; }
                // Host header only with SNI or when bound to a specific IP; a non-SNI "*" binding is IP:port only.
                var host = sni || ip != "*" ? domain : "";
                var key = BindingEndpoint.Key(ip, port, host);
                if (existingKeys.TryGetValue(key, out var ownerSite))
                {
                    if (host.Length > 0)
                        plan.Notes.Add($"An https binding {BindingEndpoint.Format(ip, port, host)} already exists on site '{ownerSite}'; not adding a duplicate.");
                    continue;
                }
                existingKeys[key] = target.Name;
                plan.Actions.Add(new BindingAction
                {
                    SiteId = target.Id, SiteName = target.Name, IsNewBinding = true, Protocol = "https",
                    IP = ip, Port = port, Host = host, UseSNI = sni,
                    Description = $"Add https binding {BindingEndpoint.Format(ip, port, host)} ({SniText(sni)}) to site '{target.Name}'",
                });
            }
        }

        // ---- 3. Non-SNI bindings share one certificate per ip:port in IIS (HTTP.sys) ----
        var warnedEndpoints = new HashSet<string>();
        foreach (var action in plan.Actions.Where(a => !a.UseSNI))
        {
            var ipPort = BindingEndpoint.IPPortKey(action.IP, action.Port);
            if (!warnedEndpoints.Add(ipPort)) continue;
            var affected = new List<(string SiteId, string Text)>();
            foreach (var s in sites)
                foreach (var b in s.Bindings.Where(b => b.IsHttps && !b.UsesSni && !b.UsesCentralCertStore))
                {
                    if (BindingEndpoint.IPPortKey(b.IP, b.Port) != ipPort || targeted.Contains(b)) continue;
                    if (newThumb != null && NormalizeThumbprint(b.CertificateHash) == newThumb) continue;
                    affected.Add((s.Id, $"site '{s.Name}' ({b.BindingInformation})"));
                }
            if (affected.Count == 0) continue;
            var otherSites = affected.Count(a => a.SiteId != action.SiteId);
            plan.Warnings.Add($"Non-SNI https bindings on {ipPort} share a single certificate in IIS: changing it also changes the certificate used by "
                              + string.Join(", ", affected.Select(a => a.Text))
                              + (otherSites > 0 ? $" ({otherSites} binding(s) on other sites)." : ".")
                              + " Use SNI bindings to give each hostname its own certificate.");
        }

        return plan;
    }

    /// <summary>Why an existing https binding should receive the certificate (empty = no match).</summary>
    public static List<string> MatchReasons(ServerBindingSnapshot binding, IReadOnlyCollection<string> domains, CertRequestConfig cfg, string? previousThumbprint)
    {
        var reasons = new List<string>();
        var host = (binding.Host ?? "").Trim();
        if (cfg.DeploymentBindingMatchHostname && host.Length > 0 && HostMatchesAny(host, domains)) reasons.Add("hostname match");
        if (cfg.DeploymentBindingBlankHostname && host.Length == 0) reasons.Add("blank hostname");
        var prev = NormalizeThumbprint(previousThumbprint);
        if (cfg.DeploymentBindingReplacePrevious && prev != null && NormalizeThumbprint(binding.CertificateHash) == prev) reasons.Add("uses previous certificate");
        return reasons;
    }

    /// <summary>
    /// True when the binding host equals a certificate domain, or a certificate wildcard covers it one level deep
    /// (*.example.com covers www.example.com but not example.com or a.b.example.com).
    /// </summary>
    public static bool HostMatchesAny(string host, IEnumerable<string> domains)
    {
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (h.Length == 0) return false;
        foreach (var raw in domains)
        {
            var d = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (d == h) return true;
            if (d.StartsWith("*.") && !h.StartsWith("*."))
            {
                var suffix = d[1..]; // ".example.com"
                if (h.Length > suffix.Length && h.EndsWith(suffix, StringComparison.Ordinal) && !h[..^suffix.Length].Contains('.'))
                    return true;
            }
        }
        return false;
    }

    /// <summary>Upper-case hex with separators/invisible characters removed; null when empty.</summary>
    public static string? NormalizeThumbprint(string? thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint)) return null;
        var hex = new string(thumbprint.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        return hex.Length == 0 ? null : hex;
    }

    private static ServerSiteSnapshot? ResolveAddTarget(DeploymentOption mode, IReadOnlyList<ServerSiteSnapshot> sites, ServerSiteSnapshot? selected, string domain)
    {
        switch (mode)
        {
            case DeploymentOption.SingleSite:
            case DeploymentOption.Auto:
                return selected;
            case DeploymentOption.AllSites:
                // The site already serving the hostname (any binding), otherwise the selected site.
                return sites.FirstOrDefault(s => s.Bindings.Any(b => string.Equals(b.Host, domain, StringComparison.OrdinalIgnoreCase))) ?? selected;
            default:
                return null;
        }
    }

    private static string SniText(bool sni) => sni ? "SNI" : "no SNI";
    private static string Short(string thumb) => thumb.Length > 8 ? thumb[..8] + "…" : thumb;
}
