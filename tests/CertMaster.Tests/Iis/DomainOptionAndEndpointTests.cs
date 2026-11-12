using CertMaster.Core.Iis;

namespace CertMaster.Tests.Iis;

public class DomainOptionBuilderTests
{
    [Fact]
    public void DedupesLowercasesAndKeepsOrder_FirstIsPrimary()
    {
        var options = DomainOptionBuilder.FromHosts(new[] { "WWW.Example.com", "", null, "shop.example.com", "www.example.com", " api.example.com. " });
        Assert.Equal(new[] { "www.example.com", "shop.example.com", "api.example.com" }, options.Select(o => o.Domain).ToArray());
        Assert.True(options[0].IsPrimaryDomain);
        Assert.Single(options, o => o.IsPrimaryDomain);
        Assert.All(options, o => Assert.True(o.IsSelected));
        Assert.All(options, o => Assert.Null(o.Comment));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("intranet")]
    [InlineData("server01")]
    [InlineData("myapp.local")]
    [InlineData("dev.localhost")]
    [InlineData("site.internal")]
    [InlineData("app.test")]
    [InlineData("10.0.0.5")]
    [InlineData("[::1]")]
    [InlineData("bad_name!.example.com")]
    public void NonPublicNames_AreUnselectedWithComment(string host)
    {
        var o = Assert.Single(DomainOptionBuilder.FromHosts(new[] { host }));
        Assert.False(o.IsSelected);
        Assert.False(o.IsPrimaryDomain);
        Assert.False(string.IsNullOrWhiteSpace(o.Comment));
    }

    [Fact]
    public void Primary_IsFirstPublicName()
    {
        var options = DomainOptionBuilder.FromHosts(new[] { "localhost", "intranet", "www.example.com", "example.com" });
        Assert.Equal("www.example.com", Assert.Single(options, o => o.IsPrimaryDomain).Domain);
        Assert.Equal(new[] { false, false, true, true }, options.Select(o => o.IsSelected).ToArray());
    }

    [Fact]
    public void NoPublicNames_NoPrimary()
    {
        var options = DomainOptionBuilder.FromHosts(new[] { "localhost", "server" });
        Assert.DoesNotContain(options, o => o.IsPrimaryDomain);
    }

    [Fact]
    public void WildcardHost_IsSelectableWithNote()
    {
        var o = Assert.Single(DomainOptionBuilder.FromHosts(new[] { "*.example.com" }));
        Assert.True(o.IsSelected);
        Assert.Contains("dns-01", o.Comment);
    }

    [Fact]
    public void EmptyInput_NoOptions() => Assert.Empty(DomainOptionBuilder.FromHosts(Array.Empty<string>()));
}

public class BindingEndpointTests
{
    [Theory]
    [InlineData("*:443:www.example.com", "*", 443, "www.example.com")]
    [InlineData("*:80:", "*", 80, "")]
    [InlineData("10.0.0.5:8443:", "10.0.0.5", 8443, "")]
    [InlineData("0.0.0.0:443:a.org", "*", 443, "a.org")]
    [InlineData("[::1]:443:a.org", "[::1]", 443, "a.org")]
    [InlineData("[2001:db8::1]:443:", "[2001:db8::1]", 443, "")]
    public void Parse(string info, string ip, int port, string host)
    {
        Assert.True(BindingEndpoint.TryParse(info, out var pIp, out var pPort, out var pHost));
        Assert.Equal((ip, port, host), (pIp, pPort, pHost));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("808:*")]
    [InlineData("*:abc:host")]
    [InlineData("*:70000:host")]
    [InlineData("localhost")]
    public void Parse_Invalid(string? info) => Assert.False(BindingEndpoint.TryParse(info, out _, out _, out _));

    [Fact]
    public void SameEndpoint_IgnoresHostCaseAndAnyAddressSpelling()
    {
        Assert.True(BindingEndpoint.SameEndpoint("*:443:WWW.example.com", "0.0.0.0", 443, "www.example.com"));
        Assert.False(BindingEndpoint.SameEndpoint("*:443:www.example.com", "*", 8443, "www.example.com"));
        Assert.False(BindingEndpoint.SameEndpoint("*:443:", "*", 443, "www.example.com"));
    }
}
