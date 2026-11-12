using System.Net;
using System.Security.Cryptography;
using CertMaster.Core.Storage;
using CertMaster.Core.Util;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertMaster.Tests.Core;

/// <summary>Failure handling for unattended servers: damaged files, locked files, flaky APIs.</summary>
public class HardeningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cm-hardening-" + Guid.NewGuid().ToString("N"));
    private readonly DataPaths _paths;

    public HardeningTests() => _paths = new DataPaths(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { /* best effort */ }
    }

    private static void Corrupt(string dbPath)
    {
        SqliteConnection.ClearAllPools(); // close pooled connections so the WAL is checkpointed and released
        using var fs = new FileStream(dbPath, FileMode.Open, FileAccess.Write);
        fs.Write(new byte[4096]); // wipes the "SQLite format 3" header and the first page
    }

    [Fact]
    public async Task DamagedDatabase_IsRestoredFromNewestBackup()
    {
        var backups = Path.Combine(_dir, "backups");
        var store = new DocumentStore(_paths.Database);
        await store.UpsertAsync("x", "1", new { v = 1 });
        await store.BackupAsync(backups);
        Corrupt(_paths.Database);

        var recovered = DocumentStore.OpenWithRecovery(_paths.Database, backups, NullLogger.Instance);

        Assert.NotNull(recovered.RestoredFromBackup);
        Assert.NotNull(await recovered.GetAsync<Dictionary<string, int>>("x", "1"));
        Assert.Single(Directory.GetFiles(_dir, "certmaster.db.damaged-*"), f => !f.EndsWith("-wal") && !f.EndsWith("-shm"));
    }

    [Fact]
    public void DamagedDatabase_WithoutBackup_FailsAndKeepsTheFile()
    {
        _ = new DocumentStore(_paths.Database);
        Corrupt(_paths.Database);

        var ex = Assert.Throws<InvalidOperationException>(() => DocumentStore.OpenWithRecovery(_paths.Database, Path.Combine(_dir, "backups")));
        Assert.Contains("no backup", ex.Message);
        Assert.True(File.Exists(_paths.Database)); // never silently replaced by an empty database
    }

    [Fact]
    public async Task Backup_LeavesNoPartialFiles()
    {
        var store = new DocumentStore(_paths.Database);
        await store.UpsertAsync("x", "1", new { v = 1 });
        var folder = Path.Combine(_dir, "backups");
        var file = await store.BackupAsync(folder);
        Assert.True(File.Exists(file));
        Assert.Empty(Directory.GetFiles(folder, "*.partial"));
    }

    [Fact]
    public void SecretProtector_RejectsDamagedKeyFile()
    {
        File.WriteAllBytes(_paths.Combine("secret.key"), new byte[5]);
        Assert.Throws<CryptographicException>(() => new SecretProtector(_paths));
    }

    [Fact]
    public void SecretProtector_CreatesKeyAndRoundTrips()
    {
        var p = new SecretProtector(_paths);
        Assert.Equal(32, new FileInfo(_paths.Combine("secret.key")).Length);
        Assert.Equal("s3cret", new SecretProtector(_paths).Unprotect(p.Protect("s3cret")));
        Assert.Empty(Directory.GetFiles(_dir, "secret.key.*.tmp"));
    }

    [Fact]
    public void AtomicWrite_ReplacesContentWithoutLeftovers()
    {
        var path = Path.Combine(_dir, "privkey.pem");
        AtomicFile.WriteAllTextNoBackup(path, "old");
        AtomicFile.WriteAllTextNoBackup(path, "new");
        Assert.Equal("new", File.ReadAllText(path));
        Assert.Single(Directory.GetFiles(_dir, "privkey.pem*"));
    }

    [Fact]
    public void ItemLog_LockedFile_DoesNotThrow()
    {
        var log = new ItemLog(_paths, "locked", NullLogger.Instance);
        log.Info("first");
        using (new FileStream(Path.Combine(_paths.Logs, "item_locked.log"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            log.Error("written while another process holds the file exclusively");
        Assert.Contains(ItemLog.Read(_paths, "locked"), e => e.Message == "first");
    }

    // ---- HTTP retries ----

    private sealed class Scripted(params Func<HttpResponseMessage>[] steps) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(steps[Math.Min(Calls++, steps.Length - 1)]());
    }

    private static HttpResponseMessage Status(HttpStatusCode code) => new(code);
    private static HttpClient Client(HttpMessageHandler inner) => new(new TransientRetryHandler(inner, 3, TimeSpan.FromMilliseconds(5)));

    [Fact]
    public async Task Retry_IdempotentRequestOn503()
    {
        var inner = new Scripted(() => Status(HttpStatusCode.ServiceUnavailable), () => Status(HttpStatusCode.OK));
        using var resp = await Client(inner).GetAsync("http://dns.test/zones");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(2, inner.Calls);
    }

    [Fact]
    public async Task Retry_NeverResendsPostOn5xx()
    {
        var inner = new Scripted(() => Status(HttpStatusCode.BadGateway), () => Status(HttpStatusCode.OK));
        using var resp = await Client(inner).PostAsync("http://dns.test/records", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.BadGateway, resp.StatusCode);
        Assert.Equal(1, inner.Calls);
    }

    [Fact]
    public async Task Retry_PostOnRateLimit()
    {
        var inner = new Scripted(() => Status(HttpStatusCode.TooManyRequests), () => Status(HttpStatusCode.Created));
        using var resp = await Client(inner).PostAsync("http://dns.test/records", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        Assert.Equal(2, inner.Calls);
    }

    [Fact]
    public async Task Retry_GivesUpAfterMaxAttempts()
    {
        var inner = new Scripted(() => Status(HttpStatusCode.ServiceUnavailable));
        using var resp = await Client(inner).GetAsync("http://dns.test/zones");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Equal(3, inner.Calls);
    }

    [Fact]
    public async Task Retry_ConnectionFailureThenSuccess()
    {
        var inner = new Scripted(() => throw new HttpRequestException("connection reset"), () => Status(HttpStatusCode.OK));
        using var resp = await Client(inner).PostAsync("http://dns.test/records", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
