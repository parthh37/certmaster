using System.Net;
using System.Text;
using CertMaster.Core.Providers.Dns;
using CertMaster.Core.Storage;

namespace CertMaster.Tests.Dns;

/// <summary>Exercises REST providers against a fake HTTP handler (no network).</summary>
public class RestProviderTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, string?, (HttpStatusCode, string)> _respond;
        public List<(string Method, string Url, string? Body)> Calls { get; } = new();

        public FakeHandler(Func<HttpRequestMessage, string?, (HttpStatusCode, string)> respond) => _respond = respond;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content == null ? null : await request.Content.ReadAsStringAsync(ct);
            Calls.Add((request.Method.Method, request.RequestUri!.ToString(), body));
            var (code, text) = _respond(request, body);
            return new HttpResponseMessage(code) { Content = new StringContent(text, Encoding.UTF8, "application/json") };
        }
    }

    private static DnsProviderContext Ctx(FakeHandler handler, Dictionary<string, string> creds, Dictionary<string, string>? parameters = null, string? zoneId = null) => new()
    {
        Credentials = creds,
        Parameters = parameters ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        Http = new HttpClient(handler),
        Paths = new DataPaths(Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"))),
        ZoneId = zoneId,
    };

    [Fact]
    public async Task GoDaddy_Delete_KeepsTheOtherValue()
    {
        var fake = new FakeHandler((req, body) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/v1/domains/example.com/records/TXT/_acme-challenge" && req.Method == HttpMethod.Get)
                return (HttpStatusCode.OK, "[{\"data\":\"apex-token\",\"ttl\":600},{\"data\":\"wildcard-token\",\"ttl\":600}]");
            if (path == "/v1/domains/example.com" && req.Method == HttpMethod.Get) return (HttpStatusCode.OK, "{\"domain\":\"example.com\"}");
            if (req.Method == HttpMethod.Get) return (HttpStatusCode.NotFound, "{\"code\":\"NOT_FOUND\"}");
            return (HttpStatusCode.OK, "");
        });
        var ctx = Ctx(fake, new() { ["api_key"] = "k", ["api_secret"] = "s" });

        var provider = new GoDaddyDnsProvider();
        var result = await provider.DeleteRecordAsync(ctx, "_acme-challenge.example.com", "wildcard-token");
        Assert.True(result.IsSuccess, result.Message);
        var put = Assert.Single(fake.Calls, c => c.Method == "PUT");
        Assert.EndsWith("/v1/domains/example.com/records/TXT/_acme-challenge", put.Url);
        Assert.Contains("apex-token", put.Body);
        Assert.DoesNotContain("wildcard-token", put.Body);
        Assert.DoesNotContain(fake.Calls, c => c.Method == "DELETE");
    }

    [Fact]
    public async Task GoDaddy_Create_PatchesOnlyWhenValueMissing()
    {
        var fake = new FakeHandler((req, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/v1/domains/example.com/records/TXT/_acme-challenge.www") return (HttpStatusCode.OK, "[{\"data\":\"apex-token\",\"ttl\":600}]");
            if (path == "/v1/domains/example.com") return (HttpStatusCode.OK, "{}");
            if (req.Method == HttpMethod.Get) return (HttpStatusCode.NotFound, "{}");
            return (HttpStatusCode.OK, "");
        });
        var ctx = Ctx(fake, new() { ["api_key"] = "k", ["api_secret"] = "s" });
        var provider = new GoDaddyDnsProvider();

        var again = await provider.CreateRecordAsync(ctx, "_acme-challenge.www.example.com", "apex-token");
        Assert.True(again.IsSuccess, again.Message);
        Assert.DoesNotContain(fake.Calls, c => c.Method == "PATCH");

        var created = await provider.CreateRecordAsync(ctx, "_acme-challenge.www.example.com", "wildcard-token");
        Assert.True(created.IsSuccess, created.Message);
        var patch = Assert.Single(fake.Calls, c => c.Method == "PATCH");
        Assert.Contains("\"name\":\"_acme-challenge.www\"", patch.Body);
        Assert.Contains("\"data\":\"wildcard-token\"", patch.Body);
    }

    [Fact]
    public async Task Cloudflare_ResolvesZoneByCandidates_AndDeletesOnlyMatchingValue()
    {
        var fake = new FakeHandler((req, _) =>
        {
            var uri = req.RequestUri!;
            var q = Uri.UnescapeDataString(uri.Query);
            if (uri.AbsolutePath.EndsWith("/zones") && q.Contains("name=sub.example.com"))
                return (HttpStatusCode.OK, "{\"success\":true,\"errors\":[],\"result\":[]}");
            if (uri.AbsolutePath.EndsWith("/zones") && q.Contains("name=example.com"))
                return (HttpStatusCode.OK, "{\"success\":true,\"errors\":[],\"result\":[{\"id\":\"zid\",\"name\":\"example.com\"}]}");
            if (uri.AbsolutePath.EndsWith("/zones/zid/dns_records") && req.Method == HttpMethod.Get)
                return (HttpStatusCode.OK, "{\"success\":true,\"errors\":[],\"result\":[{\"id\":\"r1\",\"content\":\"\\\"apex-token\\\"\"},{\"id\":\"r2\",\"content\":\"wildcard-token\"}]}");
            return (HttpStatusCode.OK, "{\"success\":true,\"errors\":[],\"result\":{}}");
        });
        var ctx = Ctx(fake, new() { ["api_token"] = "t" }, new(StringComparer.OrdinalIgnoreCase) { ["account_id"] = "acct" });

        var result = await new CloudflareDnsProvider().DeleteRecordAsync(ctx, "_acme-challenge.sub.example.com", "apex-token");
        Assert.True(result.IsSuccess, result.Message);
        var calls = fake.Calls;
        var delete = Assert.Single(calls, c => c.Method == "DELETE");
        Assert.EndsWith("/zones/zid/dns_records/r1", delete.Url);
        Assert.All(calls.Where(c => c.Url.Contains("/zones?")), c => Assert.Contains("account.id=acct", c.Url));
    }

    [Fact]
    public async Task Cloudflare_ApiErrors_AreReportedWithHint()
    {
        var fake = new FakeHandler((_, _) => (HttpStatusCode.Forbidden, "{\"success\":false,\"errors\":[{\"code\":9109,\"message\":\"Unauthorized to access requested resource\"}]}"));
        var ctx = Ctx(fake, new() { ["api_token"] = "t" });
        var result = await new CloudflareDnsProvider().CreateRecordAsync(ctx, "_acme-challenge.example.com", "v");
        Assert.False(result.IsSuccess);
        Assert.Contains("9109", result.Message);
        Assert.Contains("DNS:Edit", result.Message);
    }

    [Fact]
    public async Task MissingCredential_GivesActionableMessage()
    {
        var fake = new FakeHandler((_, _) => (HttpStatusCode.OK, "{}"));
        var ctx = Ctx(fake, new());
        var result = await new DigitalOceanDnsProvider().CreateRecordAsync(ctx, "_acme-challenge.example.com", "v");
        Assert.False(result.IsSuccess);
        Assert.Contains("API Token", result.Message);
    }

    [Fact]
    public async Task DigitalOcean_Create_UsesRelativeName()
    {
        var fake = new FakeHandler((req, _) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path == "/v2/domains" ) return (HttpStatusCode.OK, "{\"domains\":[{\"name\":\"example.com\"},{\"name\":\"sub.example.com\"}],\"links\":{}}");
            if (path == "/v2/domains/sub.example.com/records" && req.Method == HttpMethod.Get) return (HttpStatusCode.OK, "{\"domain_records\":[]}");
            return (HttpStatusCode.Created, "{}");
        });
        var ctx = Ctx(fake, new() { ["api_token"] = "t" });
        var result = await new DigitalOceanDnsProvider().CreateRecordAsync(ctx, "_acme-challenge.a.sub.example.com", "v");
        Assert.True(result.IsSuccess, result.Message);
        var post = Assert.Single(fake.Calls, c => c.Method == "POST");
        Assert.EndsWith("/v2/domains/sub.example.com/records", post.Url);
        Assert.Contains("\"name\":\"_acme-challenge.a\"", post.Body);
    }

    [Fact]
    public async Task ExplicitZoneId_NotContainingRecord_Fails()
    {
        var fake = new FakeHandler((req, _) => (HttpStatusCode.OK, "{\"domains\":[{\"name\":\"example.com\"},{\"name\":\"other.org\"}],\"links\":{}}"));
        var ctx = Ctx(fake, new() { ["api_token"] = "t" }, zoneId: "other.org");
        var result = await new DigitalOceanDnsProvider().CreateRecordAsync(ctx, "_acme-challenge.example.com", "v");
        Assert.False(result.IsSuccess);
        Assert.Contains("does not contain", result.Message);
    }
}
