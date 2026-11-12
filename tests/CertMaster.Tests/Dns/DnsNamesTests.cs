using CertMaster.Core.Providers.Dns;

namespace CertMaster.Tests.Dns;

public class DnsNamesTests
{
    private static readonly List<DnsZone> Zones = new()
    {
        new("z1", "example.com"),
        new("z2", "sub.example.com"),
        new("z3", "example.co.uk"),
        new("z4", "other.org."),
        new("z5", "ample.com"),
    };

    [Theory]
    [InlineData("_acme-challenge.example.com", "z1")]
    [InlineData("_acme-challenge.www.example.com", "z1")]
    [InlineData("_acme-challenge.sub.example.com", "z2")]
    [InlineData("_acme-challenge.deep.sub.example.com", "z2")]
    [InlineData("_ACME-Challenge.Sub.Example.COM.", "z2")]
    [InlineData("_acme-challenge.example.co.uk", "z3")]
    [InlineData("_acme-challenge.other.org", "z4")]
    [InlineData("sub.example.com", "z2")]
    public void FindBestZone_UsesLongestSuffix(string record, string expectedZoneId) =>
        Assert.Equal(expectedZoneId, DnsNames.FindBestZone(Zones, record)?.ZoneId);

    [Theory]
    [InlineData("_acme-challenge.notexample.com")] // must not match "example.com" or "ample.com" by plain string suffix
    [InlineData("_acme-challenge.example.net")]
    [InlineData("_acme-challenge.co.uk")]
    public void FindBestZone_NoMatch(string record) => Assert.Null(DnsNames.FindBestZone(Zones, record));

    [Fact]
    public void FindBestZone_ExplicitZoneIdWins_WhenItContainsTheRecord()
    {
        Assert.Equal("z1", DnsNames.FindBestZone(Zones, "_acme-challenge.sub.example.com", "z1")?.ZoneId);
        Assert.Equal("z1", DnsNames.FindBestZone(Zones, "_acme-challenge.sub.example.com", "Z1")?.ZoneId);
        // zone name instead of id
        Assert.Equal("z2", DnsNames.FindBestZone(Zones, "_acme-challenge.sub.example.com", "sub.example.com")?.ZoneId);
        // explicit zone that does not hold the record
        Assert.Null(DnsNames.FindBestZone(Zones, "_acme-challenge.other.org", "z1"));
        // unknown id
        Assert.Null(DnsNames.FindBestZone(Zones, "_acme-challenge.example.com", "nope"));
    }

    [Fact]
    public void CandidateZones_LongestFirst_WithoutTld()
    {
        Assert.Equal(new[] { "_acme-challenge.www.example.co.uk", "www.example.co.uk", "example.co.uk", "co.uk" },
            DnsNames.CandidateZones("_acme-challenge.www.example.co.uk."));
        Assert.Equal(new[] { "example.com" }, DnsNames.CandidateZones("_acme-challenge.example.com", includeSelf: false));
    }

    [Theory]
    [InlineData("_acme-challenge.example.com", "example.com", "_acme-challenge")]
    [InlineData("_acme-challenge.www.example.com.", "Example.com", "_acme-challenge.www")]
    [InlineData("example.com", "example.com", "@")]
    public void RelativeName(string record, string zone, string expected) =>
        Assert.Equal(expected, DnsNames.RelativeName(record, zone));

    [Fact]
    public void RelativeName_ApexOverride_AndOutsideZoneThrows()
    {
        Assert.Equal("", DnsNames.RelativeName("example.com", "example.com", apex: ""));
        Assert.Throws<DnsProviderException>(() => DnsNames.RelativeName("_acme-challenge.example.net", "example.com"));
    }

    [Fact]
    public void SplitZone_SldAndTld()
    {
        Assert.Equal(("example", "co.uk"), DnsNames.SplitZone("Example.co.uk."));
        Assert.Equal(("example", "com"), DnsNames.SplitZone("example.com"));
    }

    [Theory]
    [InlineData("abc", "abc")]
    [InlineData("\"abc\"", "abc")]
    [InlineData("  \"abc\"  ", "abc")]
    [InlineData("\"ab\" \"cd\"", "abcd")]
    [InlineData("\"a\\\"b\"", "a\"b")]
    public void TxtUnquote(string stored, string expected) => Assert.Equal(expected, TxtValues.Unquote(stored));

    [Fact]
    public void TxtQuote_RoundTrips() => Assert.Equal("a\"b\\c", TxtValues.Unquote(TxtValues.Quote("a\"b\\c")));
}
