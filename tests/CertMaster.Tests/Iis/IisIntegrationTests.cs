using CertMaster.Core.Iis;

namespace CertMaster.Tests.Iis;

/// <summary>A fact that only runs when CERTMASTER_IIS_TESTS=1 (needs Windows, IIS and an elevated process).</summary>
public sealed class IisFactAttribute : FactAttribute
{
    public IisFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("CERTMASTER_IIS_TESTS") != "1")
            Skip = "Set CERTMASTER_IIS_TESTS=1 and run elevated on a machine with IIS to run real IIS tests.";
        else if (!OperatingSystem.IsWindows())
            Skip = "IIS tests require Windows.";
    }
}

/// <summary>Read-only checks against the real IIS configuration. Nothing is changed.</summary>
public class IisIntegrationTests
{
    [IisFact]
    public async Task ReadsStatusSitesAndBindings()
    {
        var iis = new IisServerProvider();
        var status = await iis.GetStatusAsync();
        Assert.True(status.IsIisAvailable, status.Message);
        Assert.False(string.IsNullOrEmpty(status.IisVersion));

        var sites = await iis.GetSitesAsync();
        var snapshots = await iis.GetSiteSnapshotsAsync();
        Assert.Equal(sites.Count, snapshots.Count);
        Assert.All(snapshots, s => Assert.All(s.Bindings, b => Assert.True(b.IsHttp || b.IsHttps)));

        // Planning against the real configuration must not throw.
        var plan = BindingPlanner.Plan(snapshots, new BindingPlanRequest { Domains = { "certmaster-test.example.com" } });
        Assert.Null(plan.Error);
    }
}
