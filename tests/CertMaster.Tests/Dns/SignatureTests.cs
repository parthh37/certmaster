using System.Security.Cryptography;
using System.Text;
using CertMaster.Core.Providers.Dns;

namespace CertMaster.Tests.Dns;

public class SignatureTests
{
    [Fact]
    public void DnsMadeEasy_Hmac_MatchesRfc2202Vector()
    {
        // RFC 2202 HMAC-SHA1 test case 2
        Assert.Equal("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", DnsMadeEasyDnsProvider.ComputeHmac("Jefe", "what do ya want for nothing?"));
    }

    [Fact]
    public void DnsMadeEasy_Headers_UseRfc1123DateAndLowerHexHmac()
    {
        var now = new DateTimeOffset(2011, 2, 12, 20, 59, 4, TimeSpan.Zero);
        var h = DnsMadeEasyDnsProvider.BuildAuthHeaders("my-api-key", "c9b5625f-9834-4ff8-baba-4ed5f32cae55", now);
        Assert.Equal("my-api-key", h["x-dnsme-apiKey"]);
        Assert.Equal("Sat, 12 Feb 2011 20:59:04 GMT", h["x-dnsme-requestDate"]);
        // expected value computed independently with: openssl dgst -sha1 -hmac <secret>
        Assert.Equal("b3502e6116a324f3cf4a8ed693d78bcee8d8fe3c", h["x-dnsme-hmac"]);
    }

    [Fact]
    public void DnsMadeEasy_Headers_DateIsUtcEvenForOffsetInput()
    {
        var now = new DateTimeOffset(2011, 2, 12, 22, 59, 4, TimeSpan.FromHours(2));
        Assert.Equal("Sat, 12 Feb 2011 20:59:04 GMT", DnsMadeEasyDnsProvider.BuildAuthHeaders("k", "s", now)["x-dnsme-requestDate"]);
    }

    [Fact]
    public void Ovh_Signature_IsSha1OfJoinedFields()
    {
        // expected value computed independently with sha1sum over
        // "AS+CK+GET+https://eu.api.ovh.com/1.0/domain/zone/example.com/record?fieldType=TXT&subDomain=_acme-challenge++1366560945"
        var sig = OvhDnsProvider.ComputeSignature(
            "EgWWYOTl5g5Uq7xEj0i8KYYYtFu8hBzD", "7EMWRKtZqZ3Q2HiK5DkktrMcm5DL3QrK", "get",
            "https://eu.api.ovh.com/1.0/domain/zone/example.com/record?fieldType=TXT&subDomain=_acme-challenge", "", 1366560945);
        Assert.Equal("$1$1765652be109de9d9fb76320865dac259276a56b", sig);
    }

    [Fact]
    public void Ovh_Signature_IncludesBody()
    {
        var a = OvhDnsProvider.ComputeSignature("as", "ck", "POST", "https://eu.api.ovh.com/1.0/domain/zone/x/record", "{\"a\":1}", 1);
        var b = OvhDnsProvider.ComputeSignature("as", "ck", "POST", "https://eu.api.ovh.com/1.0/domain/zone/x/record", "", 1);
        Assert.NotEqual(a, b);
        Assert.StartsWith("$1$", a);
        Assert.Equal(43, a.Length);
    }

    [Theory]
    [InlineData("ovh-eu", "https://eu.api.ovh.com/1.0")]
    [InlineData("ovh-ca", "https://ca.api.ovh.com/1.0")]
    [InlineData("ovh-us", "https://api.us.ovhcloud.com/1.0")]
    [InlineData(null, "https://eu.api.ovh.com/1.0")]
    public void Ovh_Endpoints(string? endpoint, string expected) => Assert.Equal(expected, OvhDnsProvider.ApiBase(endpoint));

    private static readonly Dictionary<string, string> AliyunDocParameters = new()
    {
        ["Format"] = "XML",
        ["AccessKeyId"] = "testid",
        ["Action"] = "DescribeDomainRecords",
        ["SignatureMethod"] = "HMAC-SHA1",
        ["DomainName"] = "example.com",
        ["SignatureNonce"] = "f59ed6a9-83fc-473b-9cc6-99c95df3856e",
        ["SignatureVersion"] = "1.0",
        ["Version"] = "2015-01-09",
        ["Timestamp"] = "2016-03-24T16:41:54Z",
    };

    [Fact]
    public void Aliyun_CanonicalQuery_SortsAndEncodes()
    {
        Assert.Equal(
            "AccessKeyId=testid&Action=DescribeDomainRecords&DomainName=example.com&Format=XML&SignatureMethod=HMAC-SHA1" +
            "&SignatureNonce=f59ed6a9-83fc-473b-9cc6-99c95df3856e&SignatureVersion=1.0&Timestamp=2016-03-24T16%3A41%3A54Z&Version=2015-01-09",
            AliyunDnsProvider.CanonicalQuery(AliyunDocParameters));
    }

    [Fact]
    public void Aliyun_Signature_MatchesDocumentedExample()
    {
        // Alibaba Cloud DNS API signature example (AccessKey secret "testsecret"); also verified with openssl.
        Assert.Equal("uRpHwaSEt3J+6KQD//svCh/x+pI=", AliyunDnsProvider.ComputeSignature("GET", AliyunDocParameters, "testsecret"));
    }

    [Theory]
    [InlineData("a b", "a%20b")]
    [InlineData("a*b", "a%2Ab")]
    [InlineData("a~b-_.", "a~b-_.")]
    [InlineData("/", "%2F")]
    [InlineData("é", "%C3%A9")]
    public void Aliyun_PercentEncode_Rfc3986(string input, string expected) => Assert.Equal(expected, AliyunDnsProvider.PercentEncode(input));

    [Fact]
    public void Aliyun_SignedUrl_ContainsEncodedSignature()
    {
        var url = AliyunDnsProvider.BuildSignedUrl("alidns.aliyuncs.com", "id", "secret", "DescribeDomains",
            new Dictionary<string, string> { ["PageNumber"] = "1" }, new DateTimeOffset(2024, 1, 2, 3, 4, 5, TimeSpan.Zero), "nonce");
        Assert.StartsWith("https://alidns.aliyuncs.com/?AccessKeyId=id&Action=DescribeDomains&Format=JSON&PageNumber=1", url);
        Assert.Contains("Timestamp=2024-01-02T03%3A04%3A05Z", url);
        Assert.Contains("&Signature=", url);
        Assert.DoesNotContain("+", url[url.IndexOf("&Signature=", StringComparison.Ordinal)..]);
    }

    [Fact]
    public void TransIp_SignBody_VerifiesWithPublicKey()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportPkcs8PrivateKeyPem();
        using var loaded = TransIpDnsProvider.LoadPrivateKey(pem);
        const string body = "{\"login\":\"user\",\"nonce\":\"abc\"}";
        var sig = Convert.FromBase64String(TransIpDnsProvider.SignBody(body, loaded));
        Assert.True(rsa.VerifyData(Encoding.UTF8.GetBytes(body), sig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void TransIp_LoadPrivateKey_AcceptsPkcs1Pem_AndRejectsGarbage()
    {
        using var rsa = RSA.Create(2048);
        using var loaded = TransIpDnsProvider.LoadPrivateKey(rsa.ExportRSAPrivateKeyPem());
        Assert.Equal(rsa.ExportRSAPublicKey(), loaded.ExportRSAPublicKey());
        Assert.Throws<DnsProviderException>(() => TransIpDnsProvider.LoadPrivateKey("not a key"));
    }
}
