using CertMaster.Core;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Iis;
using CertMaster.Core.Providers;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using static CertMaster.Tests.Iis.PlannerTestData;

namespace CertMaster.Tests.Iis;

/// <summary>In-memory web server used to test CertManager's deployment and preview without IIS.</summary>
internal sealed class FakeWebServer : IWebServerProvider
{
    public ServerStatus Status { get; set; } = new() { IsIisAvailable = false, Message = "IIS is not installed." };
    public List<ServerSiteSnapshot> Sites { get; set; } = new();
    public Exception? SnapshotError { get; set; }
    public ActionResult<string> ImportResult { get; set; } = new() { IsSuccess = true, Result = NewThumb, Message = "Imported" };
    public int ImportCalls { get; private set; }
    public string? ImportedFriendlyName { get; private set; }
    public List<(IReadOnlyList<BindingAction> Actions, string Thumbprint, string Store)> Applied { get; } = new();

    public Task<ServerStatus> GetStatusAsync() => Task.FromResult(Status);

    public Task<List<SiteInfo>> GetSitesAsync() =>
        Task.FromResult(Sites.Select(s => new SiteInfo { Id = s.Id, Name = s.Name, PhysicalPath = s.PhysicalPath, HasCertificate = s.Bindings.Any(b => b.IsHttps) }).ToList());

    public Task<List<ServerSiteSnapshot>> GetSiteSnapshotsAsync() =>
        SnapshotError != null ? Task.FromException<List<ServerSiteSnapshot>>(SnapshotError) : Task.FromResult(Sites);

    public Task<ActionResult> ApplyBindingActionsAsync(IReadOnlyList<BindingAction> actions, string thumbprint, string storeName, CancellationToken ct)
    {
        Applied.Add((actions.ToList(), thumbprint, storeName));
        return Task.FromResult(ActionResult.Ok("applied"));
    }

    public Task<ActionResult<string>> ImportCertificateAsync(string pfxPath, string? pfxPassword, string friendlyNamePrefix, CancellationToken ct)
    {
        ImportCalls++;
        ImportedFriendlyName = friendlyNamePrefix;
        return Task.FromResult(ImportResult);
    }
}

public sealed class CertManagerServerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"));
    private readonly CertManager _manager;
    private readonly FakeWebServer _server = new();
    private readonly DataPaths _paths;
    private readonly string _pfx;

    public CertManagerServerTests()
    {
        _paths = new DataPaths(_root);
        var store = new DocumentStore(_paths.Database);
        _manager = new CertManager(store, new CredentialsManager(store, new SecretProtector(_paths)),
            new AcmeService(store, NullLogger<AcmeService>.Instance), new ProviderRegistry(),
            new HttpChallengeServer(NullLogger<HttpChallengeServer>.Instance), _paths, NullLogger<CertManager>.Instance)
        { WebServer = _server };
        _pfx = Path.Combine(_root, "test.pfx");
        File.WriteAllBytes(_pfx, new byte[] { 1, 2, 3 }); // content is irrelevant: the fake does the import
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch { /* best effort */ }
    }

    private static ManagedCertificate Item(DeploymentOption mode, params string[] domains) => new ManagedCertificate
    {
        Name = "Test Item",
        RequestConfig = new CertRequestConfig
        {
            PrimaryDomain = domains[0],
            SubjectAlternativeNames = domains.ToList(),
            DeploymentSiteOption = mode,
        },
        CertificateThumbprintHash = NewThumb,
        CertificatePreviousThumbprintHash = OldThumb,
    }.WithDnsChallenge(); // dns-01 without a provider keeps the configuration test offline

    private ItemLog Log(ManagedCertificate item) => new(_paths, item.Id, NullLogger.Instance);

    private void IisWithSites(params ServerSiteSnapshot[] sites)
    {
        _server.Status = new ServerStatus { IsIisAvailable = true, IisVersion = "10.0", Message = "IIS 10.0 is installed." };
        _server.Sites = sites.ToList();
    }

    // ---------------- Status / sites / domain options ----------------

    [Fact]
    public async Task SitesAndDomainOptions_EmptyWithoutIis()
    {
        Assert.False((await _manager.GetServerStatusAsync()).IsIisAvailable);
        Assert.Empty(await _manager.GetSitesAsync());
        Assert.Empty(await _manager.GetDomainOptionsFromSiteAsync("1"));
        Assert.Null(await _manager.GetSiteWebRootAsync("1"));
    }

    [Fact]
    public async Task DomainOptions_FromHttpAndHttpsBindingHosts()
    {
        IisWithSites(Site("1", "Main", Http("*:80:WWW.example.com"), Https("*:443:www.example.com"), Http("*:80:localhost"), Https("*:443:shop.example.com"), Http("*:80:")),
                     Site("2", "Other", Http("*:80:other.org")));
        var options = await _manager.GetDomainOptionsFromSiteAsync("1");
        Assert.Equal(new[] { "www.example.com", "localhost", "shop.example.com" }, options.Select(o => o.Domain).ToArray());
        Assert.True(options[0].IsPrimaryDomain);
        Assert.False(options[1].IsSelected);
        Assert.NotNull(options[1].Comment);
        Assert.Empty(await _manager.GetDomainOptionsFromSiteAsync("missing"));
    }

    [Fact]
    public async Task SiteWebRoot_IsRootPhysicalPath()
    {
        IisWithSites(Site("3", "Main"));
        Assert.Equal(@"C:\inetpub\Main", await _manager.GetSiteWebRootAsync("3"));
    }

    [Fact]
    public async Task Sites_AccessDenied_ReturnsEmpty()
    {
        IisWithSites(Site("1", "Main"));
        _server.SnapshotError = new WebServerAccessException("denied");
        Assert.Empty(await _manager.GetDomainOptionsFromSiteAsync("1"));
    }

    // ---------------- Deployment ----------------

    [Fact]
    public async Task Deploy_NoDeployment_DoesNothing()
    {
        var item = Item(DeploymentOption.NoDeployment, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.True(r.IsSuccess);
        Assert.Equal(0, _server.ImportCalls);
        Assert.Empty(_server.Applied);
    }

    [Fact]
    public async Task Deploy_Auto_WithoutIis_StoresCertificateAndSucceeds()
    {
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Contains("IIS not available; certificate stored", r.Message);
        Assert.Equal(1, _server.ImportCalls);
        Assert.Equal("Test Item", _server.ImportedFriendlyName);
        Assert.Empty(_server.Applied);
    }

    [Fact]
    public async Task Deploy_Auto_WithoutIis_ImportFailure_DoesNotFailRequest()
    {
        _server.ImportResult = new ActionResult<string> { Message = "Access denied. Run the agent as Administrator" };
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.True(r.IsSuccess);
        Assert.Contains("IIS not available", r.Message);
    }

    [Theory]
    [InlineData(DeploymentOption.SingleSite)]
    [InlineData(DeploymentOption.AllSites)]
    public async Task Deploy_SiteModes_WithoutIis_Fail(DeploymentOption mode)
    {
        var item = Item(mode, "www.example.com");
        item.ServerSiteId = "1";
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("IIS is not available", r.Message);
        Assert.Empty(_server.Applied);
    }

    [Fact]
    public async Task Deploy_StoreOnly_ImportsButNeverTouchesBindings()
    {
        IisWithSites(Site("1", "Main", Https("*:443:www.example.com")));
        var item = Item(DeploymentOption.CertificateStoreOnly, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, "secret", Log(item), false, CancellationToken.None);
        Assert.True(r.IsSuccess);
        Assert.Equal(1, _server.ImportCalls);
        Assert.Empty(_server.Applied);
        Assert.Contains("no binding changes", r.Message);
    }

    [Fact]
    public async Task Deploy_StoreImportFailure_WithIis_Fails()
    {
        IisWithSites(Site("1", "Main", Https("*:443:www.example.com")));
        _server.ImportResult = new ActionResult<string> { Message = "Access denied" };
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Empty(_server.Applied);
    }

    [Fact]
    public async Task Deploy_Auto_AppliesPlannedBindingsWithImportedThumbprint()
    {
        IisWithSites(
            Site("1", "Main", Https("*:443:www.example.com")),
            Site("2", "Other", Https("*:443:shop.example.com")));
        var item = Item(DeploymentOption.Auto, "www.example.com", "shop.example.com", "new.example.com");
        item.ServerSiteId = "1";
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);

        Assert.True(r.IsSuccess, r.Message);
        var (actions, thumb, store) = Assert.Single(_server.Applied);
        Assert.Equal(NewThumb, thumb);
        Assert.Equal("My", store);
        Assert.Equal(new[] { "1:*:443:www.example.com", "2:*:443:shop.example.com", "1:*:443:new.example.com" }, actions.Select(a => $"{a.SiteId}:{a.Info()}").ToArray());
        Assert.Contains("updated 2 and added 1", r.Message);
        Assert.Equal(3, r.Actions.Count);
    }

    [Fact]
    public async Task Deploy_NothingToChange_SucceedsWithoutApplying()
    {
        IisWithSites(Site("1", "Main", Https("*:443:www.example.com", NewThumb)));
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.True(r.IsSuccess);
        Assert.Empty(_server.Applied);
        Assert.Contains("already up to date", r.Message);
    }

    [Fact]
    public async Task Deploy_SingleSite_MissingSite_Fails()
    {
        IisWithSites(Site("1", "Main"));
        var item = Item(DeploymentOption.SingleSite, "www.example.com");
        item.ServerSiteId = "7";
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("not found", r.Message);
    }

    [Fact]
    public async Task Deploy_AccessDenied_FailsWithActionableMessage()
    {
        IisWithSites(Site("1", "Main"));
        _server.SnapshotError = new WebServerAccessException("Access to the IIS configuration was denied. " + IisServerProvider.AdminHint);
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), false, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("Administrator", r.Message);
    }

    [Fact]
    public async Task Deploy_MissingPfx_Fails()
    {
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, Path.Combine(_root, "missing.pfx"), null, Log(item), false, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Equal(0, _server.ImportCalls);
    }

    [Fact]
    public async Task Deploy_PreviewMode_OnlyDescribes()
    {
        IisWithSites(Site("1", "Main", Https("*:443:www.example.com")));
        var item = Item(DeploymentOption.Auto, "www.example.com");
        var r = await _manager.DeployToServerAsync(item, _pfx, null, Log(item), true, CancellationToken.None);
        Assert.True(r.IsSuccess);
        Assert.Equal(0, _server.ImportCalls);
        Assert.Empty(_server.Applied);
        var step = Assert.Single(r.Actions);
        Assert.Contains(step.Substeps, s => s.Title == "Update binding" && s.Description!.Contains("www.example.com"));
    }

    // ---------------- Preview ----------------

    [Fact]
    public async Task Preview_WithoutIis_HasAllGroupsInOrder()
    {
        var item = Item(DeploymentOption.Auto, "www.example.com", "*.example.com");
        item.UseStagingMode = true;
        item.RequestConfig.CSRKeyAlg = "ES256";
        item.PreRequestTasks.Add(new DeploymentTaskConfig { TaskName = "Stop app", TaskTypeId = "unknown.type", TaskTrigger = TaskTriggerType.ON_SUCCESS });
        item.PostRequestTasks.Add(new DeploymentTaskConfig { TaskName = "Notify", TaskTypeId = "unknown.type", TaskTrigger = TaskTriggerType.ANY_STATUS, RetriesAllowed = 2 });

        var steps = await _manager.GeneratePreviewAsync(item);

        Assert.Equal(new[] { "Certificate Request", "Authorization", "Deployment", "Pre-request tasks", "Deployment tasks", "Checks" }, steps.Select(s => s.Title).ToArray());

        var request = steps[0];
        Assert.Contains("(staging)", request.Description);
        Assert.Contains(request.Substeps, s => s.Title == "Key type" && s.Description!.StartsWith("ECDSA P-256"));
        Assert.Contains(request.Substeps, s => s.Title == "Domains" && s.Description!.Contains("*.example.com"));

        var authz = steps[1];
        Assert.Equal(2, authz.Substeps.Count);
        Assert.Contains("_acme-challenge.example.com", authz.Substeps[1].Description);
        Assert.Contains("dns-01", authz.Substeps[0].Description);

        var deploy = steps[2];
        Assert.Contains("IIS not available", deploy.Description);
        Assert.False(deploy.HasError);

        Assert.Contains("before every request", steps[3].Substeps.Single().Description);
        Assert.Contains("always", steps[4].Substeps.Single().Description);
        Assert.Contains("2 retries", steps[4].Substeps.Single().Description);

        var checks = steps[5];
        Assert.NotEmpty(checks.Substeps);
        Assert.True(checks.HasError); // no ACME account / DNS provider in the test environment
        Assert.Contains(checks.Substeps, s => s.Title == "ACME Account");
    }

    [Theory]
    [InlineData(DeploymentOption.SingleSite, true)]
    [InlineData(DeploymentOption.AllSites, true)]
    [InlineData(DeploymentOption.Auto, false)]
    public async Task Preview_WithoutIis_SiteModesAreErrors(DeploymentOption mode, bool isError)
    {
        var item = Item(mode, "www.example.com");
        var deploy = (await _manager.GeneratePreviewAsync(item)).Single(s => s.Title == "Deployment");
        Assert.Equal(isError, deploy.HasError);
        Assert.Contains("IIS not available", deploy.Description);
    }

    [Theory]
    [InlineData(DeploymentOption.NoDeployment, "No deployment")]
    [InlineData(DeploymentOption.CertificateStoreOnly, "Store only")]
    public async Task Preview_NonBindingModes(DeploymentOption mode, string text)
    {
        var deploy = (await _manager.GeneratePreviewAsync(Item(mode, "www.example.com"))).Single(s => s.Title == "Deployment");
        Assert.Contains(text, deploy.Description);
        Assert.Empty(deploy.Substeps);
    }

    [Fact]
    public async Task Preview_WithIis_ListsPlannedBindingActionsAndWarnings()
    {
        IisWithSites(
            Site("1", "Main", Https("*:443:www.example.com", NewThumb, sni: false)),
            Site("2", "Other", Https("*:443:", OtherThumb, sni: false)));
        var item = Item(DeploymentOption.SingleSite, "www.example.com", "new.example.com");
        item.ServerSiteId = "1";

        var deploy = (await _manager.GeneratePreviewAsync(item)).Single(s => s.Title == "Deployment");

        // In a preview the current certificate (NewThumb here) becomes the previous one, so the binding is updated.
        Assert.Contains(deploy.Substeps, s => s.Title == "Update binding" && s.Description!.Contains("*:443:www.example.com"));
        Assert.Contains(deploy.Substeps, s => s.Title == "Add binding" && s.Description!.Contains("*:443:new.example.com"));
        Assert.Contains(deploy.Substeps, s => s.Title == "Warning" && s.HasWarning && s.Description!.Contains("site 'Other'"));
        Assert.True(deploy.HasWarning);
        Assert.Contains("update 1 and add 1", deploy.Description);
    }

    [Fact]
    public async Task Preview_HttpChallenge_UsesSiteRootWhenNoWebRoot()
    {
        IisWithSites(Site("5", "Web"));
        var item = Item(DeploymentOption.Auto, "www.example.com");
        item.RequestConfig.Challenges.Clear();
        item.RequestConfig.Challenges.Add(new CertRequestChallengeConfig { ChallengeType = ChallengeTypes.Http01 });
        item.ServerSiteId = "5";
        // The authorization description only (the full preview's configuration test would make an HTTP request).
        var authz = (await _manager.DescribeAuthorizationAsync(item)).Substeps.Single();
        Assert.Contains(@"C:\inetpub\Web (IIS site root)", authz.Description);
    }
}

internal static class ItemExtensions
{
    public static ManagedCertificate WithDnsChallenge(this ManagedCertificate item)
    {
        item.RequestConfig.Challenges.Clear();
        item.RequestConfig.Challenges.Add(new CertRequestChallengeConfig { ChallengeType = ChallengeTypes.Dns01 });
        return item;
    }
}
