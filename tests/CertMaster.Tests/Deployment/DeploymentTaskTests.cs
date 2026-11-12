using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertMaster.Core.Providers;
using CertMaster.Core.Providers.Deployment;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Tests.Deployment;

public class CcsNamingTests
{
    [Theory]
    [InlineData("example.com", "example.com.pfx")]
    [InlineData("WWW.Example.COM", "www.example.com.pfx")]
    [InlineData("*.example.com", "_.example.com.pfx")]
    [InlineData("example.com.", "example.com.pfx")]
    public void File_names_follow_ccs_convention(string domain, string expected) => Assert.Equal(expected, CentralizedCertificateStore.GetFileName(domain));

    [Fact]
    public void Names_are_distinct_per_domain()
    {
        var names = CentralizedCertificateStore.GetFileNames(new[] { "example.com", "*.example.com", "EXAMPLE.com", " " });
        Assert.Equal(new[] { "example.com.pfx", "_.example.com.pfx" }, names);
    }

    [Theory]
    [InlineData("a*.example.com")]
    [InlineData("")]
    public void Invalid_names_throw(string domain) => Assert.Throws<ArgumentException>(() => CentralizedCertificateStore.GetFileName(domain));
}

public class DeploymentTaskTests : IDisposable
{
    private readonly TempDir _dir = new();
    private static readonly ProviderRegistry Registry = new();

    public void Dispose() => _dir.Dispose();

    private static IDeploymentTaskProvider Provider(string id) => Registry.GetDeploymentProvider(id) ?? throw new Xunit.Sdk.XunitException("missing provider " + id);

    public static readonly string[] AllIds =
    {
        "CertMaster.Deploy.ADFS", "CertMaster.Deploy.Apache", "CertMaster.Deploy.AzureAppService", "CertMaster.Deploy.AzureKeyVault",
        "CertMaster.Deploy.CCS", "CertMaster.Deploy.CertificateStore", "CertMaster.Deploy.Doppler", "CertMaster.Deploy.GenericServer",
        "CertMaster.Deploy.HashicorpVault", "CertMaster.Deploy.Exchange", "CertMaster.Deploy.Nginx", "CertMaster.Deploy.RAS",
        "CertMaster.Deploy.RDPGateway", "CertMaster.Deploy.RDPListener", "CertMaster.Deploy.Tomcat", "CertMaster.Deploy.CertificateExport",
        "CertMaster.Deploy.ServiceManager", "CertMaster.Deploy.PowershellScript", "CertMaster.Deploy.RunCommand", "CertMaster.Deploy.KeyPermissions",
        "CertMaster.Deploy.PortBinding", "CertMaster.Deploy.Wait", "CertMaster.Deploy.Webhook",
    };

    // ---------------------------------------------------------------- registry

    [Fact]
    public void All_tasks_are_discovered_with_unique_ids()
    {
        var ids = Registry.DeploymentProviders.Select(p => p.Definition.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        foreach (var id in AllIds) Assert.Contains(id, ids);
        Assert.All(Registry.DeploymentProviders, p =>
        {
            Assert.StartsWith("CertMaster.Deploy.", p.Definition.Id);
            Assert.False(string.IsNullOrWhiteSpace(p.Definition.Description));
            Assert.Contains(DeploymentContextType.LocalAsService, p.Definition.SupportedTargets);
        });
    }

    [Fact]
    public void Azure_credential_type_is_registered()
    {
        var t = Registry.GetCredentialTypes().Single(c => c.ProviderType == AzureCredentialTypes.AzureServicePrincipal);
        Assert.Equal(new[] { "tenant_id", "client_id", "client_secret" }, t.Fields.Select(f => f.Key));
    }

    // ---------------------------------------------------------------- validation

    [Theory]
    [InlineData("CertMaster.Deploy.CertificateExport", "Destination File Path is required")]
    [InlineData("CertMaster.Deploy.Apache", "Certificate file is required")]
    [InlineData("CertMaster.Deploy.Apache", "Private key file is required")]
    [InlineData("CertMaster.Deploy.Nginx", "Full chain file (ssl_certificate) is required")]
    [InlineData("CertMaster.Deploy.Tomcat", "Keystore (PFX) file is required")]
    [InlineData("CertMaster.Deploy.CCS", "CCS folder is required")]
    [InlineData("CertMaster.Deploy.GenericServer", "Set at least one destination file path")]
    [InlineData("CertMaster.Deploy.AzureAppService", "Subscription ID is required")]
    [InlineData("CertMaster.Deploy.AzureAppService", "A stored credential is required for this task")]
    [InlineData("CertMaster.Deploy.AzureKeyVault", "Vault URI is required")]
    [InlineData("CertMaster.Deploy.Doppler", "Project is required")]
    [InlineData("CertMaster.Deploy.HashicorpVault", "Vault URI is required")]
    [InlineData("CertMaster.Deploy.PowershellScript", "Script Path is required")]
    [InlineData("CertMaster.Deploy.RunCommand", "Program / Command is required")]
    [InlineData("CertMaster.Deploy.ServiceManager", "Service Name is required")]
    [InlineData("CertMaster.Deploy.Webhook", "URL is required")]
    public async Task Missing_required_parameters_are_reported(string id, string expected)
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider(id);
        var steps = await p.ValidateAsync(Ctx.Create(p, chain.Files));
        Assert.Contains(steps, s => s.HasError && s.Title == expected);
    }

    [Theory]
    [InlineData("CertMaster.Deploy.CertificateExport", "path", "relative\\file.pfx", "must be a full path")]
    [InlineData("CertMaster.Deploy.CertificateExport", "type", "pemwhatever", "Unknown export format")]
    [InlineData("CertMaster.Deploy.PortBinding", "ipport", "0.0.0.0", "Invalid IP:Port")]
    [InlineData("CertMaster.Deploy.PortBinding", "appid", "not-a-guid", "must be a GUID")]
    [InlineData("CertMaster.Deploy.PowershellScript", "timeout", "500", "between 1 and 120")]
    [InlineData("CertMaster.Deploy.PowershellScript", "args", "=oops", "has no name")]
    [InlineData("CertMaster.Deploy.Webhook", "url", "ftp://x", "absolute http(s)")]
    [InlineData("CertMaster.Deploy.Wait", "duration", "-5", "between 0 and 3600")]
    [InlineData("CertMaster.Deploy.Exchange", "services", "IIS,BOGUS", "Unknown Exchange service 'BOGUS'")]
    [InlineData("CertMaster.Deploy.AzureKeyVault", "vaulturi", "http://vault", "https address")]
    [InlineData("CertMaster.Deploy.HashicorpVault", "secretpath", "secret/data/x", "starting with /v1/")]
    [InlineData("CertMaster.Deploy.Doppler", "certsecret", "lower-case", "Invalid Doppler secret name")]
    public async Task Invalid_parameters_are_reported(string id, string key, string value, string fragment)
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider(id);
        var steps = await p.ValidateAsync(Ctx.Create(p, chain.Files, new() { [key] = value }));
        Assert.Contains(steps, s => s.HasError && s.Title.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Export_rejects_folder_path_in_validation()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.CertificateExport");
        var steps = await p.ValidateAsync(Ctx.Create(p, chain.Files, new() { ["path"] = _dir.Path + "\\" }));
        Assert.Contains(steps, s => s.HasError && s.Title.Contains("not a folder"));
    }

    [Theory]
    [InlineData("restart")]
    [InlineData("stop")]
    public async Task Service_manager_skips_stopping_the_agent_with_a_warning(string action)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.ServiceManager");
        var ctx = Ctx.Create(p, chain.Files, new() { ["servicename"] = "certmaster agent", ["action"] = action });
        // Valid configuration: the task is not an error, it just won't stop the agent.
        Assert.DoesNotContain(await p.ValidateAsync(ctx), s => s.HasError);

        var r = await p.ExecuteAsync(ctx, CancellationToken.None);
        Assert.True(r.IsSuccess);
        Assert.True(r.IsWarning);
        Assert.Contains("Skipped", r.Message);

        var preview = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["servicename"] = "CertMaster Agent", ["action"] = action }, preview: true), CancellationToken.None);
        Assert.Contains("Skipped", preview.Message);
    }

    [Fact]
    public async Task Unsupported_target_and_missing_ssh_settings_are_reported()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var adfs = Provider("CertMaster.Deploy.ADFS");
        Assert.Contains(await adfs.ValidateAsync(Ctx.Create(adfs, chain.Files, target: DeploymentContextType.SSH)), s => s.HasError && s.Title.Contains("cannot run against"));

        var apache = Provider("CertMaster.Deploy.Apache");
        var parameters = new Dictionary<string, string> { ["certpath"] = "/etc/ssl/a.pem", ["keypath"] = "/etc/ssl/a.key" };
        var steps = await apache.ValidateAsync(Ctx.Create(apache, chain.Files, parameters, target: DeploymentContextType.SSH));
        Assert.Contains(steps, s => s.HasError && s.Title == "Target host is required for SSH targets");
        Assert.Contains(steps, s => s.HasError && s.Title.Contains("SSH credential"));

        var ok = await apache.ValidateAsync(Ctx.Create(apache, chain.Files, parameters, target: DeploymentContextType.SSH, targetHost: "server.example.test:2222",
            credentials: new() { ["username"] = "deploy", ["password"] = "x" }));
        Assert.DoesNotContain(ok, s => s.HasError);

        var asUser = Provider("CertMaster.Deploy.PowershellScript");
        Assert.Contains(await asUser.ValidateAsync(Ctx.Create(asUser, chain.Files, target: DeploymentContextType.LocalAsUser)),
            s => s.HasError && s.Title.Contains("Windows credential"));
    }

    [Fact]
    public async Task Valid_configuration_has_no_errors()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.CertificateExport");
        Assert.Empty(await p.ValidateAsync(Ctx.Create(p, chain.Files, new() { ["path"] = _dir.Combine("out", "x.pfx") })));
    }

    // ---------------------------------------------------------------- preview mode

    /// <summary>A valid parameter set for every task, pointing at the temp folder, so preview runs can be checked for side effects.</summary>
    private Dictionary<string, string> ValidParams(string id) => id switch
    {
        "CertMaster.Deploy.CertificateExport" => new() { ["path"] = _dir.Combine("out", "export.pfx") },
        "CertMaster.Deploy.Apache" or "CertMaster.Deploy.Nginx" or "CertMaster.Deploy.GenericServer" => new()
        {
            ["certpath"] = _dir.Combine("out", "cert.pem"), ["keypath"] = _dir.Combine("out", "key.pem"),
            ["fullchainpath"] = _dir.Combine("out", "fullchain.pem"), ["chainpath"] = _dir.Combine("out", "chain.pem"),
        },
        "CertMaster.Deploy.Tomcat" => new() { ["pfxpath"] = _dir.Combine("out", "keystore.pfx") },
        "CertMaster.Deploy.CCS" => new() { ["path"] = _dir.Combine("ccs") },
        "CertMaster.Deploy.AzureAppService" => new() { ["subscriptionid"] = Guid.NewGuid().ToString(), ["resourcegroup"] = "rg", ["appname"] = "app", ["hostname"] = "www.example.test" },
        "CertMaster.Deploy.AzureKeyVault" => new() { ["vaulturi"] = "https://vault.example.test/" },
        "CertMaster.Deploy.Doppler" => new() { ["project"] = "p", ["config"] = "prd", ["pfxsecret"] = "TLS_PFX" },
        "CertMaster.Deploy.HashicorpVault" => new() { ["vaulturi"] = "https://vault.example.test", ["secretpath"] = "/v1/secret/data/example" },
        "CertMaster.Deploy.PowershellScript" => new() { ["scriptpath"] = WriteScript("noop.ps1", "New-Item -ItemType File -Path $env:TEMP\\should-not-exist.txt") },
        "CertMaster.Deploy.RunCommand" => new() { ["path"] = "cmd.exe", ["args"] = $"/c echo x > \"{_dir.Combine("out", "run.txt")}\"" },
        "CertMaster.Deploy.ServiceManager" => new() { ["servicename"] = "Spooler", ["action"] = "restart" },
        "CertMaster.Deploy.Webhook" => new() { ["url"] = "https://hooks.example.test/x" },
        "CertMaster.Deploy.Wait" => new() { ["duration"] = "3600" },
        _ => new(),
    };

    private string WriteScript(string name, string content)
    {
        var path = _dir.Combine("scripts", name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    private static Dictionary<string, string>? CredentialsFor(IDeploymentTaskProvider p) => p.Definition.CredentialType switch
    {
        AzureCredentialTypes.AzureServicePrincipal => new() { ["tenant_id"] = "t", ["client_id"] = "c", ["client_secret"] = "s" },
        StandardCredentialTypes.ApiToken => new() { ["api_token"] = "token" },
        _ => null,
    };

    public static IEnumerable<object[]> ProviderIds => AllIds.Select(id => new object[] { id });

    [Theory]
    [MemberData(nameof(ProviderIds))]
    public async Task Preview_makes_no_changes(string id)
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var parameters = ValidParams(id);
        var before = _dir.Snapshot();
        var handler = new RecordingHandler();
        var p = Provider(id);
        var ctx = Ctx.Create(p, chain.Files, parameters, preview: true, credentials: CredentialsFor(p), http: handler);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await p.ExecuteAsync(ctx, CancellationToken.None);

        Assert.True(result.IsSuccess, result.Message);
        Assert.False(string.IsNullOrWhiteSpace(result.Message));
        Assert.Equal(before, _dir.Snapshot());
        Assert.Empty(handler.Requests);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), "preview should not wait or run anything");
    }

    // ---------------------------------------------------------------- local file target writes

    [Fact]
    public async Task Export_writes_selected_format_to_local_path()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.CertificateExport");
        var dest = _dir.Combine("out", "nested", "site.pem");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["path"] = dest, ["type"] = ExportFormats.PemCrtPartialChain }), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        var text = await File.ReadAllTextAsync(dest);
        Assert.Equal(2, text.Split("BEGIN CERTIFICATE").Length - 1);
        Assert.DoesNotContain("PRIVATE KEY", text);
    }

    [Fact]
    public async Task Export_reprotects_pfx_with_second_credential()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.CertificateExport");
        var dest = _dir.Combine("out", "site.pfx");
        string? requested = null;
        var ctx = Ctx.Create(p, chain.Files, new() { ["path"] = dest, ["pfxpasswordcredential"] = "cred-1" },
            unlock: key => { requested = key; return Task.FromResult(new Dictionary<string, string> { ["password"] = "s3cret" }); });
        var r = await p.ExecuteAsync(ctx, CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal("cred-1", requested);
        var col = X509CertificateLoader.LoadPkcs12CollectionFromFile(dest, "s3cret", X509KeyStorageFlags.EphemeralKeySet);
        Assert.Contains(col.Cast<X509Certificate2>(), c => c.HasPrivateKey && c.Thumbprint == chain.Leaf.Thumbprint);
    }

    [Fact]
    public async Task Export_fails_cleanly_for_missing_password_credential_and_folder_destination()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.CertificateExport");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["path"] = _dir.Combine("out", "a.pfx"), ["pfxpasswordcredential"] = "missing" }), CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("missing", r.Message);

        Directory.CreateDirectory(_dir.Combine("folder"));
        var r2 = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["path"] = _dir.Combine("folder") }), CancellationToken.None);
        Assert.False(r2.IsSuccess);
        Assert.Contains("is a folder", r2.Message);
    }

    [Fact]
    public async Task Export_fails_when_certificate_not_issued()
    {
        var p = Provider("CertMaster.Deploy.CertificateExport");
        var files = new CertificateFiles { Folder = _dir.Combine("none") };
        var r = await p.ExecuteAsync(Ctx.Create(p, files, new() { ["path"] = _dir.Combine("x.pfx") }), CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("Request the certificate", r.Message);
    }

    [Fact]
    public async Task Apache_writes_component_files()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.Apache");
        var parameters = ValidParams("CertMaster.Deploy.Apache");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, parameters), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);

        static int Count(string path) => File.ReadAllText(path).Split("BEGIN CERTIFICATE").Length - 1;
        Assert.Equal(1, Count(parameters["certpath"]));
        Assert.Equal(2, Count(parameters["fullchainpath"]));
        Assert.Equal(1, Count(parameters["chainpath"]));
        using var fromChain = X509Certificate2.CreateFromPem(File.ReadAllText(parameters["chainpath"]));
        Assert.Equal(chain.Intermediate.Thumbprint, fromChain.Thumbprint);
        using var rebuilt = X509Certificate2.CreateFromPem(File.ReadAllText(parameters["certpath"]), File.ReadAllText(parameters["keypath"]));
        Assert.True(rebuilt.HasPrivateKey);
    }

    [Fact]
    public async Task Nginx_writes_only_configured_files()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var p = Provider("CertMaster.Deploy.Nginx");
        var fullchain = _dir.Combine("nginx", "fullchain.pem");
        var key = _dir.Combine("nginx", "key.pem");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["fullchainpath"] = fullchain, ["keypath"] = key }), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(new[] { "fullchain.pem", "key.pem" }, Directory.GetFiles(_dir.Combine("nginx")).Select(Path.GetFileName).Order());
    }

    [Fact]
    public async Task Tomcat_and_generic_write_pfx()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var tomcat = Provider("CertMaster.Deploy.Tomcat");
        var ks = _dir.Combine("tomcat", "keystore.p12");
        var r = await tomcat.ExecuteAsync(Ctx.Create(tomcat, chain.Files, new() { ["pfxpath"] = ks }), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Contains(X509CertificateLoader.LoadPkcs12CollectionFromFile(ks, "test-pfx", X509KeyStorageFlags.EphemeralKeySet).Cast<X509Certificate2>(), c => c.HasPrivateKey);

        var generic = Provider("CertMaster.Deploy.GenericServer");
        var pfx = _dir.Combine("generic", "a.pfx");
        var cert = _dir.Combine("generic", "a.crt");
        var r2 = await generic.ExecuteAsync(Ctx.Create(generic, chain.Files, new() { ["pfxpath"] = pfx, ["certpath"] = cert }), CancellationToken.None);
        Assert.True(r2.IsSuccess, r2.Message);
        Assert.True(File.Exists(pfx) && File.Exists(cert));
    }

    [Fact]
    public async Task Ccs_writes_one_pfx_per_domain()
    {
        using var chain = new TestChain(_dir.Combine("c"), dnsNames: new[] { "example.test", "*.example.test" });
        var p = Provider("CertMaster.Deploy.CCS");
        var folder = _dir.Combine("ccs");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["path"] = folder }, item: Ctx.Item("example.test", "*.example.test")), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(new[] { "_.example.test.pfx", "example.test.pfx" }, Directory.GetFiles(folder).Select(Path.GetFileName).Order());
    }

    [Fact]
    public async Task Local_file_system_creates_folders_and_reports_existence()
    {
        using var fs = new LocalFileSystem();
        var path = _dir.Combine("a", "b", "c.bin");
        await fs.WriteAllBytesAsync(path, new byte[] { 1, 2, 3 });
        Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(path));
        Assert.True(await fs.ExistsAsync(path));
        Assert.False(await fs.IsDirectoryAsync(path));
        Assert.True(await fs.IsDirectoryAsync(_dir.Combine("a")));
        Assert.False(await fs.ExistsAsync(_dir.Combine("nope")));
    }

    // ---------------------------------------------------------------- HTTP based tasks (fake handler, no network)

    [Fact]
    public async Task Doppler_posts_secrets_with_bearer_token()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var handler = new RecordingHandler();
        var p = Provider("CertMaster.Deploy.Doppler");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["project"] = "web", ["config"] = "prd", ["fullchainsecret"] = "TLS_FULLCHAIN", ["pfxsecret"] = "TLS_PFX" },
            credentials: new() { ["api_token"] = "dp.st.123" }, http: handler), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        var (req, body) = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal(DopplerDeploymentTask.ApiUrl, req.RequestUri!.ToString());
        Assert.Equal("Bearer", req.Headers.Authorization!.Scheme);
        Assert.Equal("dp.st.123", req.Headers.Authorization.Parameter);
        using var doc = JsonDocument.Parse(body!);
        Assert.Equal("web", doc.RootElement.GetProperty("project").GetString());
        Assert.Equal("prd", doc.RootElement.GetProperty("config").GetString());
        var secrets = doc.RootElement.GetProperty("secrets");
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", secrets.GetProperty("TLS_CERT").GetString());
        Assert.Contains("PRIVATE KEY", secrets.GetProperty("TLS_KEY").GetString());
        Assert.NotNull(secrets.GetProperty("TLS_FULLCHAIN").GetString());
        Assert.NotEmpty(Convert.FromBase64String(secrets.GetProperty("TLS_PFX").GetString()!));
    }

    [Fact]
    public async Task Doppler_reports_api_errors()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var handler = new RecordingHandler { Status = HttpStatusCode.Unauthorized, ResponseBody = "{\"messages\":[\"Invalid auth token\"],\"success\":false}" };
        var p = Provider("CertMaster.Deploy.Doppler");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["project"] = "web", ["config"] = "prd" }, credentials: new() { ["api_token"] = "bad" }, http: handler), CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("401", r.Message);
        Assert.Contains("Invalid auth token", r.Message);
    }

    [Fact]
    public async Task Vault_posts_data_with_token_and_namespace()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var handler = new RecordingHandler();
        var p = Provider("CertMaster.Deploy.HashicorpVault");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["vaulturi"] = "https://vault.example.test:8200/", ["secretpath"] = "/v1/secret/data/{PrimaryDomain}", ["namespace"] = "admin" },
            credentials: new() { ["api_token"] = "hvs.abc" }, http: handler), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        var (req, body) = Assert.Single(handler.Requests);
        Assert.Equal("https://vault.example.test:8200/v1/secret/data/example.test", req.RequestUri!.ToString());
        Assert.Equal("hvs.abc", req.Headers.GetValues("X-Vault-Token").Single());
        Assert.Equal("admin", req.Headers.GetValues("X-Vault-Namespace").Single());
        var data = JsonDocument.Parse(body!).RootElement.GetProperty("data");
        foreach (var k in new[] { "key", "cert", "intermediates", "pfx" }) Assert.False(string.IsNullOrEmpty(data.GetProperty(k).GetString()));
    }

    [Fact]
    public async Task Webhook_sends_expanded_body_and_reports_failures()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var handler = new RecordingHandler();
        var p = Provider("CertMaster.Deploy.Webhook");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["url"] = "https://hooks.example.test/{PrimaryDomain}", ["body"] = "{\"d\":\"{PrimaryDomain}\"}" }, http: handler), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal("https://hooks.example.test/example.test", handler.Requests[0].Request.RequestUri!.ToString());
        Assert.Equal("{\"d\":\"example.test\"}", handler.Requests[0].Body);

        handler.Status = HttpStatusCode.InternalServerError;
        var r2 = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["url"] = "https://hooks.example.test/x" }, http: handler), CancellationToken.None);
        Assert.False(r2.IsSuccess);
        Assert.Contains("500", r2.Message);
    }

    // ---------------------------------------------------------------- scripts / commands (local, Windows)

    [Fact]
    public async Task PowerShell_script_receives_named_args_and_result_object()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var chain = new TestChain(_dir.Combine("c"));
        var output = _dir.Combine("out", "script.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var script = WriteScript("deploy.ps1", """
            param($result, [string]$Target, [string]$Label)
            Set-Content -LiteralPath $Target -Value ("{0}|{1}|{2}|{3}" -f $Label, $result.ManagedItem.RequestConfig.PrimaryDomain, $result.IsSuccess, $env:CERT_PRIMARY_DOMAIN)
            """);
        var p = Provider("CertMaster.Deploy.PowershellScript");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new()
        {
            ["scriptpath"] = script, ["passresult"] = "true",
            ["args"] = $"Target={output.Replace(";", "\\;")};Label=a\\;b=c {{PrimaryDomain}}",
        }), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal("a;b=c example.test|example.test|True|example.test", (await File.ReadAllTextAsync(output)).Trim());
    }

    [Fact]
    public async Task PowerShell_script_failure_is_reported()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var chain = new TestChain(_dir.Combine("c"));
        var script = WriteScript("fail.ps1", "throw 'deliberate failure'");
        var p = Provider("CertMaster.Deploy.PowershellScript");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["scriptpath"] = script }), CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("deliberate failure", r.Message);
    }

    [Fact]
    public async Task Run_command_runs_batch_file_with_arguments()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var chain = new TestChain(_dir.Combine("c"));
        var output = _dir.Combine("out", "run.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var bat = WriteScript("run.bat", "@echo %~1 > \"%~2\"");
        var p = Provider("CertMaster.Deploy.RunCommand");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["path"] = bat, ["args"] = $"{{PrimaryDomain}} \"{output}\"" }), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal("example.test", (await File.ReadAllTextAsync(output)).Trim());
    }

    // ---------------------------------------------------------------- helpers

    [Theory]
    [InlineData("host", "host", 22)]
    [InlineData("host.example.test:2222", "host.example.test", 2222)]
    [InlineData("10.0.0.5", "10.0.0.5", 22)]
    [InlineData("[::1]:2200", "::1", 2200)]
    [InlineData("fe80::1", "fe80::1", 22)]
    public void Parses_ssh_hosts(string value, string host, int port)
    {
        Assert.True(DeploymentTargets.TryParseHost(value, out var h, out var p));
        Assert.Equal(host, h);
        Assert.Equal(port, p);
    }

    [Theory]
    [InlineData("")]
    [InlineData("host:0")]
    [InlineData("host:99999")]
    [InlineData("ssh://host")]
    [InlineData("bad host")]
    public void Rejects_invalid_ssh_hosts(string value) => Assert.False(DeploymentTargets.TryParseHost(value, out _, out _));

    [Theory]
    [InlineData("0.0.0.0:443", "0.0.0.0:443")]
    [InlineData("10.1.2.3:8443", "10.1.2.3:8443")]
    [InlineData("[::]:443", "[::]:443")]
    [InlineData("0.0.0.0", null)]
    [InlineData("host:443", null)]
    public void Normalizes_netsh_ipport(string value, string? expected) => Assert.Equal(expected, PortBindingTask.NormalizeIpPort(value));

    [Fact]
    public void Builds_remote_ssh_commands()
    {
        Assert.Equal("systemctl reload nginx", SshCommandRunner.BuildRemoteCommand(new CommandSpec("systemctl") { RawArguments = "reload nginx" }));
        Assert.Equal("/opt/x.sh 'a b' 'it'\\''s'", SshCommandRunner.BuildRemoteCommand(new CommandSpec("/opt/x.sh") { Arguments = new[] { "a b", "it's" } }));
        Assert.Equal("nohup sh -c '/opt/run' >/dev/null 2>&1 &", SshCommandRunner.BuildRemoteCommand(new CommandSpec("/opt/run") { Detached = true }));
    }

    [Fact]
    public void Windows_credentials_parse_domain_forms()
    {
        Assert.Equal(new WindowsCredential("bob", "CORP", "pw"), WindowsCredential.FromDictionary(new Dictionary<string, string> { ["username"] = @"CORP\bob", ["password"] = "pw" }));
        Assert.Equal(new WindowsCredential("bob@corp.test", null, "pw"), WindowsCredential.FromDictionary(new Dictionary<string, string> { ["username"] = "bob@corp.test", ["password"] = "pw" }));
        Assert.Equal("CORP\\bob", WindowsCredential.FromDictionary(new Dictionary<string, string> { ["username"] = "bob", ["domain"] = "CORP", ["password"] = "pw" })!.AccountName);
        Assert.Null(WindowsCredential.FromDictionary(new Dictionary<string, string> { ["username"] = "bob" }));
        Assert.Equal(WindowsLogonType.NewCredentials, WindowsLogon.Parse("NewCredentials", WindowsLogonType.Interactive));
        Assert.Equal(WindowsLogonType.Interactive, WindowsLogon.Parse("auto", WindowsLogonType.Interactive));
    }

    [Theory]
    [InlineData("www.example.com", true)]
    [InlineData("example.com", true)]
    [InlineData("api.example.com", true)]
    [InlineData("a.b.example.com", false)]
    [InlineData("other.com", false)]
    public void App_service_hostname_must_be_covered(string host, bool expected) =>
        Assert.Equal(expected, AzureAppServiceDeploymentTask.MatchesCertificate(host, new[] { "example.com", "*.example.com" }));

    [Theory]
    [InlineData("www.example.com", "www-example-com")]
    [InlineData("*.example.com", "wildcard-example-com")]
    public void Key_vault_default_names(string domain, string expected) => Assert.Equal(expected, AzureKeyVaultDeploymentTask.DefaultName(domain));

    [Fact]
    public void Vault_uri_is_combined()
    {
        Assert.Equal("https://v:8200/v1/secret/data/x", HashiCorpVaultDeploymentTask.BuildUri("https://v:8200/", "/v1/secret/data/x").ToString());
        Assert.Equal("https://v/v1/kv/x", HashiCorpVaultDeploymentTask.BuildUri("https://v", "v1/kv/x").ToString());
    }

    [Fact]
    public void Doppler_payload_shape()
    {
        var json = DopplerDeploymentTask.BuildPayload("p", "c", new Dictionary<string, string> { ["A"] = "1" });
        Assert.Equal("{\"project\":\"p\",\"config\":\"c\",\"secrets\":{\"A\":\"1\"}}", json);
    }
}
