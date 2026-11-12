using CertMaster.Core.Iis;
using CertMaster.Models;
using static CertMaster.Tests.Iis.PlannerTestData;

namespace CertMaster.Tests.Iis;

public class BindingPlannerTests
{
    // Site 1 "Main": https www (old cert), http only for new.example.com. Site 2 "Other": https shop (old cert).
    private static List<ServerSiteSnapshot> StandardSites() => new()
    {
        Site("1", "Main", Https("*:443:www.example.com"), Http("*:80:www.example.com"), Http("*:80:new.example.com")),
        Site("2", "Other", Https("*:443:shop.example.com"), Http("*:80:shop.example.com")),
    };

    // ---------------- Deployment modes ----------------

    [Theory]
    [InlineData(DeploymentOption.NoDeployment)]
    [InlineData(DeploymentOption.CertificateStoreOnly)]
    public void NoBindingActions_ForNoDeploymentAndStoreOnly(DeploymentOption mode)
    {
        foreach (var bindingOption in new[] { DeploymentBindingOption.AddOrUpdate, DeploymentBindingOption.UpdateOnly })
        {
            var plan = BindingPlanner.Plan(StandardSites(), Request(mode, "www.example.com", "shop.example.com", "new.example.com")
                .WithSite("1").With(c => { c.DeploymentBindingOption = bindingOption; c.DeploymentBindingBlankHostname = true; c.DeploymentBindingReplacePrevious = true; }));
            Assert.Empty(plan.Actions);
            Assert.Null(plan.Error);
            Assert.Empty(plan.Warnings);
        }
    }

    public static TheoryData<DeploymentOption, DeploymentBindingOption, string[], string[]> ModeMatrix => new()
    {
        // mode, binding option, expected updates (site:binding), expected adds (site:binding)
        { DeploymentOption.Auto, DeploymentBindingOption.AddOrUpdate, new[] { "1:*:443:www.example.com", "2:*:443:shop.example.com" }, new[] { "1:*:443:new.example.com" } },
        { DeploymentOption.Auto, DeploymentBindingOption.UpdateOnly, new[] { "1:*:443:www.example.com", "2:*:443:shop.example.com" }, Array.Empty<string>() },
        // shop is bound on site 2 which is not eligible; adding it to site 1 would duplicate *:443:shop.example.com
        { DeploymentOption.SingleSite, DeploymentBindingOption.AddOrUpdate, new[] { "1:*:443:www.example.com" }, new[] { "1:*:443:new.example.com" } },
        { DeploymentOption.SingleSite, DeploymentBindingOption.UpdateOnly, new[] { "1:*:443:www.example.com" }, Array.Empty<string>() },
        { DeploymentOption.AllSites, DeploymentBindingOption.AddOrUpdate, new[] { "1:*:443:www.example.com", "2:*:443:shop.example.com" }, new[] { "1:*:443:new.example.com" } },
        { DeploymentOption.AllSites, DeploymentBindingOption.UpdateOnly, new[] { "1:*:443:www.example.com", "2:*:443:shop.example.com" }, Array.Empty<string>() },
    };

    [Theory]
    [MemberData(nameof(ModeMatrix))]
    public void ModeAndBindingOptionMatrix(DeploymentOption mode, DeploymentBindingOption bindingOption, string[] updates, string[] adds)
    {
        var plan = BindingPlanner.Plan(StandardSites(), Request(mode, "www.example.com", "shop.example.com", "new.example.com")
            .WithSite("1").With(c => c.DeploymentBindingOption = bindingOption));

        Assert.Null(plan.Error);
        Assert.Equal(updates, plan.Updates.Select(a => $"{a.SiteId}:{a.Info()}").ToArray());
        Assert.Equal(adds, plan.Additions.Select(a => $"{a.SiteId}:{a.Info()}").ToArray());
        Assert.All(plan.Actions, a => Assert.Equal("https", a.Protocol));
    }

    [Fact]
    public void Auto_WithoutSelectedSite_UpdatesButNeverAdds()
    {
        var plan = BindingPlanner.Plan(StandardSites(), Request(DeploymentOption.Auto, "www.example.com", "new.example.com"));
        Assert.Single(plan.Updates);
        Assert.Empty(plan.Additions);
        Assert.Contains(plan.Notes, n => n.Contains("new.example.com"));
    }

    [Fact]
    public void Auto_AddsOnlyToSelectedSite_EvenWhenAnotherSiteServesTheHostOverHttp()
    {
        // new.example.com is served over http by site 1, but site 2 is the selected site.
        var plan = BindingPlanner.Plan(StandardSites(), Request(DeploymentOption.Auto, "new.example.com").WithSite("2"));
        var add = Assert.Single(plan.Additions);
        Assert.Equal("2", add.SiteId);
        Assert.Equal("Other", add.SiteName);
    }

    [Fact]
    public void Auto_DomainBoundOnAnotherSite_IsUpdatedThereAndNotAddedToSelectedSite()
    {
        var plan = BindingPlanner.Plan(StandardSites(), Request(DeploymentOption.Auto, "shop.example.com").WithSite("1"));
        var update = Assert.Single(plan.Actions);
        Assert.False(update.IsNewBinding);
        Assert.Equal("2", update.SiteId);
    }

    [Fact]
    public void Auto_SelectedSiteMissing_WarnsAndStillUpdates()
    {
        var plan = BindingPlanner.Plan(StandardSites(), Request(DeploymentOption.Auto, "www.example.com", "new.example.com").WithSite("99"));
        Assert.Null(plan.Error);
        Assert.Contains(plan.Warnings, w => w.Contains("99"));
        Assert.Single(plan.Updates);
        Assert.Empty(plan.Additions);
    }

    [Fact]
    public void SingleSite_IgnoresMatchingBindingsOnOtherSites()
    {
        var sites = new List<ServerSiteSnapshot>
        {
            Site("1", "A", Https("*:443:www.example.com")),
            Site("2", "B", Https("*:443:www.example.com", sni: true), Https("10.0.0.1:443:www.example.com")),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1"));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("1", a.SiteId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("42")]
    public void SingleSite_WithoutValidSite_IsAnError(string? siteId)
    {
        var plan = BindingPlanner.Plan(StandardSites(), Request(DeploymentOption.SingleSite, "www.example.com").WithSite(siteId));
        Assert.NotNull(plan.Error);
        Assert.Empty(plan.Actions);
    }

    [Fact]
    public void AllSites_AddsToTheSiteServingTheHost_OtherwiseSelectedSite_OtherwiseNothing()
    {
        var sites = new List<ServerSiteSnapshot>
        {
            Site("1", "A", Http("*:80:a.example.com")),
            Site("2", "B", Http("*:80:b.example.com")),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.AllSites, "a.example.com", "b.example.com", "c.example.com").WithSite("1"));
        Assert.Equal(new[] { "1:a.example.com", "2:b.example.com", "1:c.example.com" }, plan.Additions.Select(a => $"{a.SiteId}:{a.Host}").ToArray());

        var noSite = BindingPlanner.Plan(sites, Request(DeploymentOption.AllSites, "c.example.com"));
        Assert.Empty(noSite.Actions);
        Assert.Contains(noSite.Notes, n => n.Contains("c.example.com"));
    }

    [Fact]
    public void AllSites_UpdatesMatchingBindingsOnEverySite()
    {
        var sites = new List<ServerSiteSnapshot>
        {
            Site("1", "A", Https("*:443:www.example.com")),
            Site("2", "B", Https("*:8443:www.example.com")),
            Site("3", "C", Https("*:443:unrelated.org")),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.AllSites, "www.example.com"));
        Assert.Equal(new[] { "1", "2" }, plan.Updates.Select(a => a.SiteId).ToArray());
        Assert.Empty(plan.Additions);
    }

    // ---------------- Match options ----------------

    public static IEnumerable<object[]> MatchOptionCombinations()
    {
        foreach (var hostname in new[] { false, true })
            foreach (var blank in new[] { false, true })
                foreach (var previous in new[] { false, true })
                    yield return new object[] { hostname, blank, previous };
    }

    [Theory]
    [MemberData(nameof(MatchOptionCombinations))]
    public void MatchOptions_AnyEnabledOptionSelectsTheBinding(bool matchHostname, bool matchBlank, bool replacePrevious)
    {
        var site = Site("1", "S",
            Https("*:443:www.example.com", OtherThumb),        // hostname match only
            Https("*:8443:", OtherThumb, sni: false),         // blank hostname only
            Https("*:443:legacy.example.org", OldThumb),       // previous certificate only
            Https("*:443:www2.example.com", OldThumb),         // hostname + previous
            Https("*:443:unrelated.example.org", OtherThumb)); // never
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.SingleSite, "www.example.com", "www2.example.com").WithSite("1")
            .With(c =>
            {
                c.DeploymentBindingMatchHostname = matchHostname;
                c.DeploymentBindingBlankHostname = matchBlank;
                c.DeploymentBindingReplacePrevious = replacePrevious;
                c.DeploymentBindingOption = DeploymentBindingOption.UpdateOnly;
            }));

        var expected = new List<string>();
        if (matchHostname) expected.Add("*:443:www.example.com");
        if (matchBlank) expected.Add("*:8443:");
        if (replacePrevious) expected.Add("*:443:legacy.example.org");
        if (matchHostname || replacePrevious) expected.Add("*:443:www2.example.com");

        Assert.Equal(expected.OrderBy(x => x), plan.Updates.Select(a => a.Info()).OrderBy(x => x));
        Assert.DoesNotContain(plan.Actions, a => a.Host == "unrelated.example.org");
    }

    [Fact]
    public void UpdateDescription_ListsAllReasons_AndPreviousCertificate()
    {
        var site = Site("1", "S", Https("*:443:www.example.com", OldThumb));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.Auto, "www.example.com")
            .With(c => c.DeploymentBindingReplacePrevious = true));
        var a = Assert.Single(plan.Actions);
        Assert.Contains("hostname match", a.Description);
        Assert.Contains("uses previous certificate", a.Description);
        Assert.Contains("Update https binding *:443:www.example.com", a.Description);
        Assert.Equal(OldThumb, a.PreviousThumbprint);
        Assert.True(a.UseSNI);
    }

    [Fact]
    public void ReplacePrevious_WithoutPreviousThumbprint_MatchesNothing()
    {
        var site = Site("1", "S", Https("*:443:other.org", null), Https("*:443:other2.org", OldThumb));
        var req = Request(DeploymentOption.Auto, "www.example.com").With(c => { c.DeploymentBindingReplacePrevious = true; c.DeploymentBindingOption = DeploymentBindingOption.UpdateOnly; });
        req.PreviousThumbprint = null;
        Assert.Empty(BindingPlanner.Plan(new[] { site }, req).Actions);
    }

    [Fact]
    public void PreviousEqualToNew_IsIgnored()
    {
        var site = Site("1", "S", Https("*:443:other.org", NewThumb));
        var req = Request(DeploymentOption.Auto, "www.example.com").With(c => c.DeploymentBindingReplacePrevious = true);
        req.PreviousThumbprint = NewThumb;
        var plan = BindingPlanner.Plan(new[] { site }, req);
        Assert.Empty(plan.Actions);
        Assert.Equal(0, plan.UpToDateCount);
    }

    [Fact]
    public void ThumbprintsAreComparedNormalised()
    {
        var site = Site("1", "S",
            Https("*:443:www.example.com", NewThumb.ToLowerInvariant()),
            Https("*:443:legacy.org", "aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa"));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.Auto, "www.example.com").With(c => c.DeploymentBindingReplacePrevious = true));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("legacy.org", a.Host);
        Assert.Equal(1, plan.UpToDateCount);
    }

    [Fact]
    public void BindingsAlreadyUsingNewCertificate_AreSkipped_AndNotReAdded()
    {
        var site = Site("1", "S", Https("*:443:www.example.com", NewThumb));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1"));
        Assert.Empty(plan.Actions);
        Assert.Equal(1, plan.UpToDateCount);
        Assert.Contains(plan.Notes, n => n.Contains("already uses"));
    }

    [Fact]
    public void WithoutNewThumbprint_ExistingBindingsAreAlwaysPlannedForUpdate()
    {
        var site = Site("1", "S", Https("*:443:www.example.com", NewThumb));
        var req = Request(DeploymentOption.Auto, "www.example.com");
        req.NewThumbprint = null;
        Assert.Single(BindingPlanner.Plan(new[] { site }, req).Updates);
    }

    [Fact]
    public void HttpBindingsAreNeverUpdated()
    {
        var site = Site("1", "S", Http("*:80:www.example.com"), Http("*:80:"));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.Auto, "www.example.com")
            .With(c => { c.DeploymentBindingBlankHostname = true; c.DeploymentBindingOption = DeploymentBindingOption.UpdateOnly; }));
        Assert.Empty(plan.Actions);
    }

    [Fact]
    public void CentralCertStoreBindings_AreSkipped()
    {
        var site = Site("1", "S", Https("*:443:www.example.com", null, sni: true, ccs: true));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1"));
        Assert.Empty(plan.Actions); // and no add either: the hostname is already bound
        Assert.Contains(plan.Notes, n => n.Contains("Centralized Certificate Store"));
    }

    [Fact]
    public void BindingWithoutCertificate_IsUpdatedWhenHostMatches()
    {
        var site = Site("1", "S", Https("*:443:www.example.com", null));
        var a = Assert.Single(BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.Auto, "www.example.com")).Actions);
        Assert.Null(a.PreviousThumbprint);
        Assert.DoesNotContain("replaces certificate", a.Description);
    }

    // ---------------- Wildcards ----------------

    [Theory]
    [InlineData("www.example.com", true)]
    [InlineData("API.Example.com", true)]
    [InlineData("example.com", false)]
    [InlineData("a.b.example.com", false)]
    [InlineData("wwwexample.com", false)]
    [InlineData("www.example.org", false)]
    [InlineData("*.example.com", true)] // IIS wildcard host header equal to the certificate wildcard
    [InlineData("*.sub.example.com", false)]
    public void WildcardCoversOneLevel(string host, bool expected)
    {
        Assert.Equal(expected, BindingPlanner.HostMatchesAny(host, new[] { "*.example.com" }));
    }

    [Fact]
    public void WildcardCertificate_UpdatesCoveredBindings_AndNeverAddsBindings()
    {
        var site = Site("1", "S", Https("*:443:www.example.com"), Https("*:443:deep.sub.example.com"), Https("*:443:example.com"));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.SingleSite, "*.example.com").WithSite("1"));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("www.example.com", a.Host);
        Assert.False(a.IsNewBinding);

        var empty = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "*.example.com").WithSite("1"));
        Assert.Empty(empty.Actions);
    }

    [Fact]
    public void WildcardPlusApex_AddsOnlyTheApex()
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "example.com", "*.example.com").WithSite("1"));
        var add = Assert.Single(plan.Actions);
        Assert.Equal("example.com", add.Host);
    }

    // ---------------- New bindings ----------------

    [Fact]
    public void DefaultNewBinding_IsAllUnassigned443WithHostAndSni()
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "WWW.Example.com").WithSite("1"));
        var a = Assert.Single(plan.Actions);
        Assert.True(a.IsNewBinding);
        Assert.Equal("*:443:www.example.com", a.Info());
        Assert.True(a.UseSNI);
        Assert.Null(a.PreviousThumbprint);
        Assert.StartsWith("Add https binding *:443:www.example.com (SNI) to site 'S'", a.Description);
    }

    [Fact]
    public void DuplicateDomainsInRequest_AddOnlyOneBinding()
    {
        var req = Request(DeploymentOption.SingleSite, "www.example.com", "WWW.EXAMPLE.COM", "www.example.com.").WithSite("1");
        Assert.Single(BindingPlanner.Plan(new[] { Site("1", "S") }, req).Actions);
    }

    [Fact]
    public void NeverAddsDuplicateOfABindingOnAnotherSite()
    {
        var sites = new[] { Site("1", "A"), Site("2", "B", Https("*:443:www.example.com", OtherThumb)) };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1"));
        Assert.Empty(plan.Actions);
        Assert.Contains(plan.Notes, n => n.Contains("already exists on site 'B'"));
    }

    [Fact]
    public void SpecificIPPort_WithSni()
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = true; c.BindingIPAddress = "10.0.0.5"; c.BindingPort = 8443; c.BindingUseSNI = true; }));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("10.0.0.5:8443:www.example.com", a.Info());
        Assert.True(a.UseSNI);
        Assert.Contains("(SNI)", a.Description);
    }

    [Fact]
    public void SpecificIP_WithoutSni_KeepsHostHeader()
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = true; c.BindingIPAddress = "10.0.0.5"; c.BindingPort = 443; c.BindingUseSNI = false; }));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("10.0.0.5:443:www.example.com", a.Info());
        Assert.False(a.UseSNI);
        Assert.Contains("(no SNI)", a.Description);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("")]
    [InlineData("0.0.0.0")]
    public void AllUnassigned_WithoutSni_AddsOneBlankHostBinding(string ip)
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "a.example.com", "b.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = true; c.BindingIPAddress = ip; c.BindingPort = 8443; c.BindingUseSNI = false; }));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("*:8443:", a.Info());
        Assert.Equal("", a.Host);
        Assert.False(a.UseSNI);
    }

    [Fact]
    public void AllUnassigned_WithoutSni_DoesNotDuplicateExistingBlankBinding()
    {
        var site = Site("1", "S", Https("*:8443:", OtherThumb, sni: false));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.SingleSite, "a.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = true; c.BindingIPAddress = "*"; c.BindingPort = 8443; c.BindingUseSNI = false; }));
        Assert.Empty(plan.Actions); // blank-hostname matching is off, and the binding exists already
    }

    [Fact]
    public void SpecificIPPort_InvalidPort_FallsBackTo443()
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = true; c.BindingIPAddress = "10.0.0.5"; c.BindingPort = 0; }));
        Assert.Equal(443, Assert.Single(plan.Actions).Port);
    }

    [Fact]
    public void IgnoresSpecificIPSettings_WhenNotEnabled()
    {
        var plan = BindingPlanner.Plan(new[] { Site("1", "S") }, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = false; c.BindingIPAddress = "10.0.0.5"; c.BindingPort = 8443; c.BindingUseSNI = false; }));
        var a = Assert.Single(plan.Actions);
        Assert.Equal("*:443:www.example.com", a.Info());
        Assert.True(a.UseSNI);
    }

    [Fact]
    public void UpdatesComeBeforeAdds()
    {
        var site = Site("1", "S", Https("*:443:b.example.com"));
        var plan = BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.SingleSite, "a.example.com", "b.example.com").WithSite("1"));
        Assert.Equal(new[] { false, true }, plan.Actions.Select(a => a.IsNewBinding).ToArray());
    }

    // ---------------- Non-SNI shared certificate ----------------

    [Fact]
    public void NonSniUpdate_SharedIpPortWithOtherSite_Warns()
    {
        var sites = new[]
        {
            Site("1", "A", Https("*:443:www.example.com", OldThumb, sni: false)),
            Site("2", "B", Https("*:443:other.org", OtherThumb, sni: false)),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.Auto, "www.example.com"));
        Assert.Single(plan.Actions);
        var w = Assert.Single(plan.Warnings);
        Assert.Contains("*:443", w);
        Assert.Contains("site 'B'", w);
        Assert.Contains("1 binding(s) on other sites", w);
    }

    [Fact]
    public void NonSniUpdate_AllSharedBindingsUpdatedTogether_NoWarning()
    {
        var sites = new[]
        {
            Site("1", "A", Https("*:443:www.example.com", OldThumb, sni: false)),
            Site("2", "B", Https("*:443:api.example.com", OldThumb, sni: false)),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.Auto, "www.example.com", "api.example.com"));
        Assert.Equal(2, plan.Actions.Count);
        Assert.Empty(plan.Warnings);
    }

    [Fact]
    public void NonSniUpdate_OtherBindingOnDifferentPortOrIpOrSni_NoWarning()
    {
        var sites = new[]
        {
            Site("1", "A", Https("*:443:www.example.com", OldThumb, sni: false)),
            Site("2", "B", Https("*:8443:other.org", OtherThumb, sni: false), Https("10.0.0.1:443:x.org", OtherThumb, sni: false), Https("*:443:sni.org", OtherThumb, sni: true)),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.Auto, "www.example.com"));
        Assert.Single(plan.Actions);
        Assert.Empty(plan.Warnings);
    }

    [Fact]
    public void NonSniUpdate_SharedBindingAlreadyOnNewCertificate_NoWarning()
    {
        var sites = new[]
        {
            Site("1", "A", Https("*:443:www.example.com", OldThumb, sni: false)),
            Site("2", "B", Https("*:443:other.org", NewThumb, sni: false)),
        };
        Assert.Empty(BindingPlanner.Plan(sites, Request(DeploymentOption.Auto, "www.example.com")).Warnings);
    }

    [Fact]
    public void NonSniAdd_OntoIpPortUsedByAnotherSite_Warns()
    {
        var sites = new[] { Site("1", "A"), Site("2", "B", Https("10.0.0.5:443:", OtherThumb, sni: false)) };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.SingleSite, "www.example.com").WithSite("1")
            .With(c => { c.UseSpecificBindingIPPort = true; c.BindingIPAddress = "10.0.0.5"; c.BindingPort = 443; c.BindingUseSNI = false; }));
        Assert.Single(plan.Additions);
        var w = Assert.Single(plan.Warnings);
        Assert.Contains("10.0.0.5:443", w);
        Assert.Contains("site 'B'", w);
    }

    [Fact]
    public void SniUpdate_NeverWarnsAboutSharedPort()
    {
        var sites = new[]
        {
            Site("1", "A", Https("*:443:www.example.com", OldThumb, sni: true)),
            Site("2", "B", Https("*:443:", OtherThumb, sni: false)),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.Auto, "www.example.com"));
        Assert.Single(plan.Actions);
        Assert.Empty(plan.Warnings);
    }

    [Fact]
    public void NonSniWarning_IsReportedOncePerEndpoint()
    {
        var sites = new[]
        {
            Site("1", "A", Https("*:443:a.example.com", OldThumb, sni: false), Https("*:443:b.example.com", OldThumb, sni: false)),
            Site("2", "B", Https("*:443:", OtherThumb, sni: false)),
        };
        var plan = BindingPlanner.Plan(sites, Request(DeploymentOption.Auto, "a.example.com", "b.example.com"));
        Assert.Equal(2, plan.Actions.Count);
        Assert.Single(plan.Warnings);
    }

    // ---------------- Helpers ----------------

    [Theory]
    [InlineData(null, null)]
    [InlineData("  ", null)]
    [InlineData("ab cd", "ABCD")]
    [InlineData("‎abcd", "ABCD")]
    public void NormalizeThumbprint(string? input, string? expected) => Assert.Equal(expected, BindingPlanner.NormalizeThumbprint(input));

    [Fact]
    public void UpdateAction_NormalisesIp()
    {
        var site = Site("1", "S", new ServerBindingSnapshot { Protocol = "HTTPS", IP = "0.0.0.0", Port = 443, Host = "www.example.com", CertificateHash = OldThumb, SslFlags = BindingSslFlags.Sni });
        var a = Assert.Single(BindingPlanner.Plan(new[] { site }, Request(DeploymentOption.Auto, "www.example.com")).Actions);
        Assert.Equal("*", a.IP);
    }
}
