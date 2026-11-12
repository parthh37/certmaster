using CertMaster.Core.Iis;
using CertMaster.Models;

namespace CertMaster.Tests.Iis;

/// <summary>Builders for site snapshots and plan requests.</summary>
internal static class PlannerTestData
{
    public const string OldThumb = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    public const string NewThumb = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    public const string OtherThumb = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    public static ServerSiteSnapshot Site(string id, string name, params ServerBindingSnapshot[] bindings) =>
        new() { Id = id, Name = name, PhysicalPath = $@"C:\inetpub\{name}", Bindings = bindings.ToList() };

    public static ServerBindingSnapshot Https(string info, string? hash = OldThumb, bool sni = true, bool ccs = false)
    {
        Assert.True(BindingEndpoint.TryParse(info, out var ip, out var port, out var host), info);
        return new ServerBindingSnapshot
        {
            Protocol = "https", IP = ip, Port = port, Host = host, CertificateHash = hash, CertificateStoreName = "My",
            SslFlags = (sni ? BindingSslFlags.Sni : BindingSslFlags.None) | (ccs ? BindingSslFlags.CentralCertStore : BindingSslFlags.None),
        };
    }

    public static ServerBindingSnapshot Http(string info)
    {
        Assert.True(BindingEndpoint.TryParse(info, out var ip, out var port, out var host), info);
        return new ServerBindingSnapshot { Protocol = "http", IP = ip, Port = port, Host = host };
    }

    public static BindingPlanRequest Request(DeploymentOption mode, params string[] domains) => new()
    {
        Config = new CertRequestConfig { DeploymentSiteOption = mode },
        Domains = domains.ToList(),
        NewThumbprint = NewThumb,
        PreviousThumbprint = OldThumb,
    };

    public static BindingPlanRequest WithSite(this BindingPlanRequest r, string? siteId) { r.ServerSiteId = siteId; return r; }

    public static BindingPlanRequest With(this BindingPlanRequest r, Action<CertRequestConfig> configure) { configure(r.Config); return r; }

    public static string Info(this BindingAction a) => BindingEndpoint.Format(a.IP, a.Port, a.Host);
}
