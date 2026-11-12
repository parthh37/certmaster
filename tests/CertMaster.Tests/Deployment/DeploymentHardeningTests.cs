using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using CertMaster.Core.Providers;
using CertMaster.Core.Providers.Deployment;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Tests.Deployment;

/// <summary>File permissions/atomic replacement, webhook escaping, script temp folder, port binding and service ordering.</summary>
[SupportedOSPlatform("windows")] // the Windows-only parts return early on other platforms
public class DeploymentHardeningTests : IDisposable
{
    private readonly TempDir _dir = new();
    private static readonly ProviderRegistry Registry = new();

    public void Dispose() => _dir.Dispose();

    private static IDeploymentTaskProvider Provider(string id) => Registry.GetDeploymentProvider(id) ?? throw new Xunit.Sdk.XunitException("missing provider " + id);

    private static SecurityIdentifier Users => new(WellKnownSidType.BuiltinUsersSid, null);
    private static SecurityIdentifier NetworkService => new(WellKnownSidType.NetworkServiceSid, null);

    [SupportedOSPlatform("windows")]
    private static List<FileSystemAccessRule> Rules(string path) =>
        new FileInfo(path).GetAccessControl(AccessControlSections.Access).GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();

    // ---------------------------------------------------------------- local writes

    [Fact]
    public async Task Sensitive_local_file_gets_protected_acl_without_inherited_access()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fs = new LocalFileSystem();
        var path = _dir.Combine("certs", "privkey.pem");
        await fs.WriteAllBytesAsync(path, new byte[] { 1, 2, 3 }, sensitive: true);

        Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(path));
        var acl = new FileInfo(path).GetAccessControl(AccessControlSections.Access);
        Assert.True(acl.AreAccessRulesProtected);
        var rules = Rules(path);
        Assert.All(rules, r => Assert.False(r.IsInherited));
        Assert.DoesNotContain(rules, r => r.IdentityReference.Equals(Users));
        Assert.Contains(rules, r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)) && r.FileSystemRights.HasFlag(FileSystemRights.FullControl));
        Assert.Contains(rules, r => r.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)));
        using var me = WindowsIdentity.GetCurrent();
        Assert.Contains(rules, r => r.IdentityReference.Equals(me.User));
        Assert.Single(Directory.GetFiles(_dir.Combine("certs"))); // no temp file left behind
    }

    [Fact]
    public async Task Sensitive_overwrite_keeps_explicit_grants_but_drops_inherited_access()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = _dir.Combine("certs", "site.pfx");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, new byte[] { 9 }); // pre-existing file with inherited permissions
        FileAcl.Grant(path, NetworkService, FileSystemRights.Read); // an administrator granted a service account read access

        using var fs = new LocalFileSystem();
        await fs.WriteAllBytesAsync(path, new byte[] { 4, 5 }, sensitive: true);

        Assert.Equal(new byte[] { 4, 5 }, await File.ReadAllBytesAsync(path));
        var rules = Rules(path);
        Assert.All(rules, r => Assert.False(r.IsInherited));
        Assert.Contains(rules, r => r.IdentityReference.Equals(NetworkService) && r.FileSystemRights.HasFlag(FileSystemRights.Read));
    }

    [Fact]
    public async Task Non_sensitive_local_file_inherits_folder_permissions()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var fs = new LocalFileSystem();
        var path = _dir.Combine("certs", "cert.pem");
        await fs.WriteAllBytesAsync(path, new byte[] { 1 });
        await fs.WriteAllBytesAsync(path, new byte[] { 2 }); // replace
        Assert.Equal(new byte[] { 2 }, await File.ReadAllBytesAsync(path));
        Assert.False(new FileInfo(path).GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected);
        Assert.Contains(Rules(path), r => r.IsInherited);
    }

    [Fact]
    public async Task Replace_waits_for_a_reader_that_holds_the_file_open()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = _dir.Combine("ccs", "example.test.pfx");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, new byte[] { 1 });
        var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); // blocks rename-over
        var release = Task.Run(async () => { await Task.Delay(700); reader.Dispose(); });

        using var fs = new LocalFileSystem();
        await fs.WriteAllBytesAsync(path, new byte[] { 7, 7 }, sensitive: true);
        await release;
        Assert.Equal(new byte[] { 7, 7 }, await File.ReadAllBytesAsync(path));
        Assert.Single(Directory.GetFiles(_dir.Combine("ccs")));
    }

    [Fact]
    public void Network_paths_are_detected()
    {
        Assert.True(SafeFileWriter.IsNetworkPath(@"\\fileserver\ccs\a.pfx"));
        Assert.True(SafeFileWriter.IsNetworkPath(@"\\?\UNC\fileserver\ccs\a.pfx"));
        Assert.False(SafeFileWriter.IsNetworkPath(@"\\?\C:\certs\a.pfx"));
        if (OperatingSystem.IsWindows()) Assert.False(SafeFileWriter.IsNetworkPath(Path.GetFullPath(_dir.Combine("x.pfx"))));
        Assert.EndsWith(".pfx.tmp-", SafeFileWriter.TempPathFor(@"C:\ccs\a.pfx")[..^32]);
    }

    // ---------------------------------------------------------------- webhook escaping

    [Fact]
    public async Task Webhook_default_json_body_stays_valid_with_quotes_and_newlines_in_the_message()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var handler = new RecordingHandler();
        var p = Provider("CertMaster.Deploy.Webhook");
        var message = "Order failed: \"urn:acme:error\" at C:\\certs\\x\nsecond line\t<tag> & é";
        var item = Ctx.Item();
        item.Name = "Cert \"quoted\" \\ name";
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["url"] = "https://hooks.example.test/x" }, http: handler,
            item: item, requestMessage: message, requestSucceeded: false), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);

        var json = JsonDocument.Parse(handler.Requests[0].Body!).RootElement;
        Assert.Equal(message, json.GetProperty("message").GetString());
        Assert.Equal(item.Name, json.GetProperty("name").GetString());
        Assert.False(json.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task Webhook_url_placeholders_are_percent_encoded_and_plain_bodies_are_raw()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        var handler = new RecordingHandler();
        var p = Provider("CertMaster.Deploy.Webhook");
        var item = Ctx.Item();
        item.Name = "a b&c=d/e";
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new()
        {
            ["url"] = "https://hooks.example.test/notify?name={Name}", ["contenttype"] = "text/plain", ["body"] = "{Name}: {Message}",
        }, http: handler, item: item, requestMessage: "say \"hi\""), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal("https://hooks.example.test/notify?name=a%20b%26c%3Dd%2Fe", handler.Requests[0].Request.RequestUri!.AbsoluteUri);
        Assert.Equal("a b&c=d/e: say \"hi\"", handler.Requests[0].Body);
    }

    [Fact]
    public void Json_encoder_escapes_without_adding_quotes() =>
        Assert.Equal("a\\\"b\\\\c\\nd", DeploymentContext.JsonStringEncoder("a\"b\\c\nd"));

    // ---------------------------------------------------------------- script temp files

    [Fact]
    public async Task Script_temp_files_live_in_a_private_folder_and_are_deleted()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var chain = new TestChain(_dir.Combine("c"));
        var output = _dir.Combine("out", "path.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        var script = _dir.Combine("scripts", "where.cmd");
        Directory.CreateDirectory(Path.GetDirectoryName(script)!);
        File.WriteAllText(script, $"@echo %CERT_RESULT_JSON%> \"{output}\"\r\n");

        var p = Provider("CertMaster.Deploy.PowershellScript");
        var r = await p.ExecuteAsync(Ctx.Create(p, chain.Files, new() { ["scriptpath"] = script }), CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);

        var resultPath = (await File.ReadAllTextAsync(output)).Trim();
        Assert.StartsWith(Path.GetFullPath(Ctx.ScriptTemp), resultPath, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(resultPath));
        var acl = new DirectoryInfo(Ctx.ScriptTemp).GetAccessControl(AccessControlSections.Access);
        Assert.True(acl.AreAccessRulesProtected);
        Assert.DoesNotContain(acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), x => x.IdentityReference.Equals(Users));
    }

    [Fact]
    public void Default_script_temp_folder_is_under_the_agent_data_folder()
    {
        var folder = DeploymentContext.DefaultScriptTempFolder();
        Assert.EndsWith("temp", folder);
        Assert.False(folder.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Private_temp_files_are_never_reused()
    {
        var folder = PrivateTempFolder.Ensure(_dir.Combine("private"));
        var file = Path.Combine(folder, "args.json");
        await PrivateTempFolder.WriteNewFileAsync(file, "{}", CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => PrivateTempFolder.WriteNewFileAsync(file, "{}", CancellationToken.None));
    }

    // ---------------------------------------------------------------- netsh port binding

    private const string EnglishShow = """

        SSL Certificate bindings:
        -------------------------

            IP:port                      : 0.0.0.0:443
            Certificate Hash             : aabbccddeeff00112233445566778899aabbccdd
            Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
            Certificate Store Name       : WebHosting
            Verify Client Certificate Revocation : Enabled
            Ctl Identifier               : (null)
            Ctl Store Name               : (null)
            DS Mapper Usage              : Disabled
            Negotiate Client Certificate : Disabled

        """;

    private const string GermanShow = """
        SSL-Zertifikatbindungen:
        ------------------------

            IP:Port                      : 0.0.0.0:443
            Zertifikathash               : AABBCCDDEEFF00112233445566778899AABBCCDD
            Anwendungs-ID                : {4dc3e181-e14b-4a21-b022-59fc669b0914}
            Zertifikatspeichername       : My
        """;

    [Fact]
    public void Parses_netsh_show_sslcert_output()
    {
        var b = PortBindingTask.ParseShowSslCert(EnglishShow)!;
        Assert.Equal("AABBCCDDEEFF00112233445566778899AABBCCDD", b.CertificateHash);
        Assert.Equal(Guid.Parse("4dc3e181-e14b-4a21-b022-59fc669b0914"), b.AppId);
        Assert.Equal("WebHosting", b.CertStoreName);

        var de = PortBindingTask.ParseShowSslCert(GermanShow)!;
        Assert.Equal("AABBCCDDEEFF00112233445566778899AABBCCDD", de.CertificateHash);
        Assert.Equal(Guid.Parse("4dc3e181-e14b-4a21-b022-59fc669b0914"), de.AppId);

        Assert.Null(PortBindingTask.ParseShowSslCert("\r\nSSL Certificate bindings:\r\n-------------------------\r\n\r\n"));
        Assert.Null(PortBindingTask.ParseShowSslCert("The system cannot find the file specified."));
        Assert.Null(PortBindingTask.ParseShowSslCert(null));
    }

    [Fact]
    public void Builds_netsh_arguments()
    {
        var id = Guid.Parse("4dc3e181-e14b-4a21-b022-59fc669b0914");
        Assert.Equal(new[] { "http", "update", "sslcert", "ipport=0.0.0.0:443", "certhash=ABC", "appid={4dc3e181-e14b-4a21-b022-59fc669b0914}", "certstorename=MY" },
            PortBindingTask.SetArgs("update", "0.0.0.0:443", "ABC", id));
        Assert.Equal("certstorename=WebHosting", PortBindingTask.SetArgs("add", "[::]:443", "ABC", id, "WebHosting")[^1]);
        Assert.Equal(new[] { "http", "show", "sslcert", "ipport=[::]:443" }, PortBindingTask.ShowArgs("[::]:443"));
    }

    private sealed class FakeNetsh
    {
        public List<string[]> Calls { get; } = new();
        public string ShowOutput { get; set; } = "";
        public Func<string[], int> ExitCode { get; set; } = _ => 0;

        public Task<ProcessResult> Run(string[] args, CancellationToken ct)
        {
            Calls.Add(args);
            return Task.FromResult(args[1] == "show" ? new ProcessResult(0, ShowOutput, "") : new ProcessResult(ExitCode(args), "", ExitCode(args) == 0 ? "" : "netsh error"));
        }

        public IEnumerable<string> Verbs => Calls.Select(c => c[1]);
    }

    private DeploymentContext PortCtx()
    {
        var p = Provider("CertMaster.Deploy.PortBinding");
        return Ctx.Create(p, new CertificateFiles { Folder = _dir.Combine("none") });
    }

    private const string NewHash = "0123456789ABCDEF0123456789ABCDEF01234567";
    private const string OldHash = "AABBCCDDEEFF00112233445566778899AABBCCDD";
    private static readonly Guid OldAppId = Guid.Parse("4dc3e181-e14b-4a21-b022-59fc669b0914");

    [Fact]
    public async Task Port_binding_adds_when_there_is_no_binding()
    {
        var netsh = new FakeNetsh();
        var r = await PortBindingTask.ApplyBindingAsync(PortCtx(), netsh.Run, "0.0.0.0:443", NewHash, null, CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(new[] { "show", "add" }, netsh.Verbs);
        Assert.Contains($"certhash={NewHash}", netsh.Calls[1]);
    }

    [Fact]
    public async Task Port_binding_updates_in_place_keeping_the_app_id()
    {
        var netsh = new FakeNetsh { ShowOutput = EnglishShow };
        var r = await PortBindingTask.ApplyBindingAsync(PortCtx(), netsh.Run, "0.0.0.0:443", NewHash, null, CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(new[] { "show", "update" }, netsh.Verbs);
        Assert.Contains($"appid={{{OldAppId}}}", netsh.Calls[1]);
        Assert.Contains($"certhash={NewHash}", netsh.Calls[1]);

        var configured = Guid.NewGuid();
        var netsh2 = new FakeNetsh { ShowOutput = EnglishShow };
        await PortBindingTask.ApplyBindingAsync(PortCtx(), netsh2.Run, "0.0.0.0:443", NewHash, configured, CancellationToken.None);
        Assert.Contains($"appid={{{configured}}}", netsh2.Calls[1]);
    }

    [Fact]
    public async Task Port_binding_is_left_alone_when_already_current()
    {
        var netsh = new FakeNetsh { ShowOutput = EnglishShow };
        var r = await PortBindingTask.ApplyBindingAsync(PortCtx(), netsh.Run, "0.0.0.0:443", OldHash.ToLowerInvariant(), null, CancellationToken.None);
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal(new[] { "show" }, netsh.Verbs);
    }

    [Fact]
    public async Task Port_binding_restores_the_previous_certificate_when_replacement_fails()
    {
        var adds = 0;
        var netsh = new FakeNetsh
        {
            ShowOutput = EnglishShow,
            ExitCode = a => a[1] switch { "update" => 1, "add" => ++adds == 1 ? 1 : 0, _ => 0 },
        };
        var r = await PortBindingTask.ApplyBindingAsync(PortCtx(), netsh.Run, "0.0.0.0:443", NewHash, null, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains("restored", r.Message);
        Assert.Equal(new[] { "show", "update", "delete", "add", "add" }, netsh.Verbs);
        var restore = netsh.Calls[^1];
        Assert.Contains($"certhash={OldHash}", restore);
        Assert.Contains($"appid={{{OldAppId}}}", restore);
        Assert.Contains("certstorename=WebHosting", restore);
    }

    [Fact]
    public async Task Port_binding_does_not_delete_when_update_and_delete_fail()
    {
        var netsh = new FakeNetsh { ShowOutput = EnglishShow, ExitCode = a => a[1] is "update" or "delete" ? 1 : 0 };
        var r = await PortBindingTask.ApplyBindingAsync(PortCtx(), netsh.Run, "0.0.0.0:443", NewHash, null, CancellationToken.None);
        Assert.False(r.IsSuccess);
        Assert.Contains(OldHash, r.Message);
        Assert.Equal(new[] { "show", "update", "delete" }, netsh.Verbs);
    }

    // ---------------------------------------------------------------- service dependents

    [Fact]
    public void Dependent_services_start_after_their_dependencies()
    {
        // WAS <- W3SVC <- AppSvc; AppSvc also depends on WAS directly; WMSVC <- WAS
        var graph = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["WAS"] = new[] { "AppSvc", "W3SVC", "WMSVC" },
            ["W3SVC"] = new[] { "AppSvc" },
            ["AppSvc"] = Array.Empty<string>(),
            ["WMSVC"] = Array.Empty<string>(),
        };
        var calls = new List<string>();
        var order = ServiceManagerTask.DependentStartOrder("was", n => { calls.Add(n); return graph[n]; });
        Assert.Equal(new[] { "W3SVC", "WMSVC", "AppSvc" }, order);
        Assert.Equal(calls.Count, calls.Distinct(StringComparer.OrdinalIgnoreCase).Count()); // each service queried once
        Assert.Empty(ServiceManagerTask.DependentStartOrder("Spooler", _ => Array.Empty<string>()));
    }

    [Fact]
    public void Circular_service_dependencies_are_rejected()
    {
        var graph = new Dictionary<string, string[]> { ["A"] = new[] { "B" }, ["B"] = new[] { "C" }, ["C"] = new[] { "B" } };
        Assert.Throws<InvalidOperationException>(() => ServiceManagerTask.DependentStartOrder("A", n => graph[n]));
    }

    // ---------------------------------------------------------------- certificate store re-import

    [Fact]
    public void Existing_store_entry_with_key_is_reused_and_one_without_key_is_not()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=certmaster-reuse-test-" + Guid.NewGuid().ToString("N")[..8], key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var pfx = ephemeral.Export(X509ContentType.Pkcs12, "pw");
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        using var publicOnly = X509CertificateLoader.LoadCertificate(ephemeral.RawData);
        using var withKey = X509CertificateLoader.LoadPkcs12(pfx, "pw", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
        try
        {
            store.Add(publicOnly);
            Assert.False(CertificateStoreHelper.TryUseExisting(store, ephemeral.Thumbprint, "name"));

            store.Add(withKey);
            Assert.True(CertificateStoreHelper.TryUseExisting(store, ephemeral.Thumbprint, "CertMaster reuse test"));
            var found = CertificateStoreHelper.Find(store, ephemeral.Thumbprint);
            try { Assert.Equal("CertMaster reuse test", Assert.Single(found).FriendlyName); }
            finally { CertificateStoreHelper.DisposeAll(found); }
        }
        finally
        {
            var leftovers = CertificateStoreHelper.Find(store, ephemeral.Thumbprint);
            foreach (var c in leftovers) store.Remove(c);
            CertificateStoreHelper.DisposeAll(leftovers);
            try { using var rsa = withKey.GetRSAPrivateKey(); if (rsa is RSACng cng) cng.Key.Delete(); } catch (CryptographicException) { }
        }
    }
}
