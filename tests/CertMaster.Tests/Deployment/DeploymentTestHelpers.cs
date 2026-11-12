using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertMaster.Core.Providers.Deployment;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertMaster.Tests.Deployment;

/// <summary>A root → intermediate → leaf chain generated in-test, written to a folder in the agent's file layout.</summary>
public sealed class TestChain : IDisposable
{
    public X509Certificate2 Root { get; }
    public X509Certificate2 Intermediate { get; }
    public X509Certificate2 Leaf { get; }
    public RSA LeafKey { get; }
    public string Folder { get; }
    public CertificateFiles Files { get; }

    public TestChain(string folder, string? pfxPassword = "test-pfx", bool includeRootInPfx = false, params string[] dnsNames)
    {
        Folder = folder;
        Directory.CreateDirectory(folder);
        if (dnsNames.Length == 0) dnsNames = new[] { "example.test", "www.example.test" };
        var now = DateTimeOffset.UtcNow;

        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=CertMaster Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        Root = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));

        using var intKey = RSA.Create(2048);
        var intReq = new CertificateRequest("CN=CertMaster Test Intermediate", intKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intPub = intReq.Create(Root, now.AddDays(-1), now.AddYears(3), new byte[] { 1, 2, 3, 4 });
        Intermediate = intPub.CopyWithPrivateKey(intKey);

        LeafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=" + dnsNames[0], LeafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var d in dnsNames) san.AddDnsName(d);
        leafReq.CertificateExtensions.Add(san.Build());
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        using var leafPub = leafReq.Create(Intermediate, now.AddDays(-1), now.AddDays(90), new byte[] { 5, 6, 7, 8 });
        Leaf = leafPub.CopyWithPrivateKey(LeafKey);

        Files = new CertificateFiles { Folder = folder, PfxPassword = pfxPassword };
        var certPem = Pem(Leaf);
        var chainPem = Pem(Intermediate);
        File.WriteAllText(Files.CertPem, certPem);
        File.WriteAllText(Files.ChainPem, chainPem);
        File.WriteAllText(Files.FullChainPem, certPem + chainPem);
        File.WriteAllText(Files.KeyPem, LeafKey.ExportPkcs8PrivateKeyPem() + "\n");
        var pfx = new X509Certificate2Collection { Leaf, X509CertificateLoader.LoadCertificate(Intermediate.RawData) };
        if (includeRootInPfx) pfx.Add(X509CertificateLoader.LoadCertificate(Root.RawData));
        File.WriteAllBytes(Files.Pfx, pfx.Export(X509ContentType.Pkcs12, pfxPassword)!);
    }

    public static string Pem(X509Certificate2 c) => PemEncoding.WriteString("CERTIFICATE", c.RawData) + "\n";

    public void Dispose()
    {
        Root.Dispose(); Intermediate.Dispose(); Leaf.Dispose(); LeafKey.Dispose();
    }
}

/// <summary>Temporary folder deleted on dispose.</summary>
public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "certmaster-tests", Guid.NewGuid().ToString("N")[..10]);
    public TempDir() => Directory.CreateDirectory(Path);
    public string Combine(params string[] parts) => System.IO.Path.Combine(new[] { Path }.Concat(parts).ToArray());

    /// <summary>Relative paths of all files (for "nothing changed" assertions).</summary>
    public List<string> Snapshot() => Directory.Exists(Path)
        ? Directory.GetFiles(Path, "*", SearchOption.AllDirectories).Select(f => System.IO.Path.GetRelativePath(Path, f) + "|" + new FileInfo(f).Length + "|" + File.GetLastWriteTimeUtc(f).Ticks).OrderBy(x => x).ToList()
        : new List<string>();

    public void Dispose() { try { Directory.Delete(Path, true); } catch { /* ignore */ } }
}

/// <summary>Records HTTP requests and returns a canned response (no network).</summary>
public sealed class RecordingHandler : HttpMessageHandler
{
    public List<(HttpRequestMessage Request, string? Body)> Requests { get; } = new();
    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
    public string ResponseBody { get; set; } = "{}";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content == null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request, body));
        return new HttpResponseMessage(Status) { Content = new StringContent(ResponseBody) };
    }
}

public static class Ctx
{
    private static readonly string LogRoot = Path.Combine(Path.GetTempPath(), "certmaster-tests", "data");
    /// <summary>Private script temp folder for tests (the default is under %ProgramData%CertMaster, which tests may not be able to write).</summary>
    public static readonly string ScriptTemp = Path.Combine(Path.GetTempPath(), "certmaster-tests", "script-temp");

    public static ManagedCertificate Item(params string[] domains)
    {
        if (domains.Length == 0) domains = new[] { "example.test", "www.example.test" };
        return new ManagedCertificate
        {
            Name = "Test cert",
            RequestConfig = new CertRequestConfig { PrimaryDomain = domains[0], SubjectAlternativeNames = domains.ToList() },
            CertificateThumbprintHash = "0123456789ABCDEF0123456789ABCDEF01234567",
        };
    }

    public static DeploymentContext Create(IDeploymentTaskProvider provider, CertificateFiles files, Dictionary<string, string>? parameters = null,
        bool preview = false, Dictionary<string, string>? credentials = null, ManagedCertificate? item = null, HttpMessageHandler? http = null,
        DeploymentContextType target = DeploymentContextType.LocalAsService, string? targetHost = null,
        Func<string?, Task<Dictionary<string, string>>>? unlock = null, string? requestMessage = null, bool? requestSucceeded = null)
    {
        item ??= Item();
        var task = new DeploymentTaskConfig { TaskTypeId = provider.Definition.Id, TaskName = provider.Definition.DefaultTitle, TargetType = target, TargetHost = targetHost };
        // defaults from the definition, then the test's values (mirrors CertManager.MergeParameters)
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in provider.Definition.ProviderParameters.Where(p => !p.IsCredential && !string.IsNullOrEmpty(p.Value))) merged[p.Key] = p.Value!;
        if (parameters != null) foreach (var kv in parameters) merged[kv.Key] = kv.Value;
        return new DeploymentContext
        {
            Item = item, Task = task, Files = files, Parameters = merged, Credentials = credentials ?? new Dictionary<string, string>(),
            Log = new ItemLog(new DataPaths(LogRoot), item.Id, NullLogger.Instance),
            Http = new HttpClient(http ?? new RecordingHandler()),
            IsPreviewOnly = preview,
            ScriptTempFolder = ScriptTemp,
            RequestMessage = requestMessage, RequestSucceeded = requestSucceeded,
            UnlockCredentialAsync = unlock ?? (_ => Task.FromResult(new Dictionary<string, string>())),
        };
    }
}
