using CertMaster.Core.Providers.Dns;

namespace CertMaster.Tests.Dns;

/// <summary>
/// Apex and wildcard identifiers share one record name with two values: adding must keep existing values, removing must
/// take out only the given value.
/// </summary>
public class RecordSetMergeTests
{
    [Fact]
    public void Route53_Add_QuotesAndKeepsExistingValues()
    {
        var existing = new[] { "\"v=spf1 -all\"", "\"apex-token\"" };
        var result = Route53DnsProvider.AddTxtValue(existing, "wildcard-token");
        Assert.Equal(new[] { "\"v=spf1 -all\"", "\"apex-token\"", "\"wildcard-token\"" }, result);
    }

    [Fact]
    public void Route53_Add_IsIdempotent()
    {
        var existing = new[] { "\"apex-token\"" };
        Assert.Equal(existing, Route53DnsProvider.AddTxtValue(existing, "apex-token"));
        Assert.Equal(new[] { "\"first\"" }, Route53DnsProvider.AddTxtValue(null, "first"));
    }

    [Fact]
    public void Route53_Remove_OnlyOurValue()
    {
        var existing = new[] { "\"apex-token\"", "\"wildcard-token\"", "\"other\" \"split\"" };
        Assert.Equal(new[] { "\"apex-token\"", "\"other\" \"split\"" }, Route53DnsProvider.RemoveTxtValue(existing, "wildcard-token"));
        Assert.Empty(Route53DnsProvider.RemoveTxtValue(new[] { "\"apex-token\"" }, "apex-token"));
        Assert.Equal(existing, Route53DnsProvider.RemoveTxtValue(existing, "absent"));
    }

    [Fact]
    public void Route53_DecodeName()
    {
        Assert.Equal("*.example.com", Route53DnsProvider.DecodeName("\\052.example.com."));
        Assert.Equal("_acme-challenge.example.com", Route53DnsProvider.DecodeName("_acme-challenge.example.com."));
    }

    [Fact]
    public void Azure_Add_KeepsExistingRecords()
    {
        var existing = new List<IReadOnlyList<string>> { new[] { "apex-token" }, new[] { "long-part-1", "long-part-2" } };
        var result = AzureDnsProvider.AddTxtValue(existing, "wildcard-token");
        Assert.Equal(3, result.Count);
        Assert.Equal(new[] { "apex-token" }, result[0]);
        Assert.Equal(new[] { "long-part-1", "long-part-2" }, result[1]);
        Assert.Equal(new[] { "wildcard-token" }, result[2]);
    }

    [Fact]
    public void Azure_Add_IsIdempotent_ComparesJoinedStrings()
    {
        var existing = new List<IReadOnlyList<string>> { new[] { "ab", "cd" } };
        Assert.Single(AzureDnsProvider.AddTxtValue(existing, "abcd"));
        Assert.Single(AzureDnsProvider.AddTxtValue(null, "x"));
    }

    [Fact]
    public void Azure_Add_SplitsValuesLongerThan255()
    {
        var value = new string('a', 300);
        var result = AzureDnsProvider.AddTxtValue(null, value);
        Assert.Equal(new[] { 255, 45 }, result[0].Select(s => s.Length));
    }

    [Fact]
    public void Azure_Remove_OnlyOurValue()
    {
        var existing = new List<IReadOnlyList<string>> { new[] { "apex-token" }, new[] { "wildcard-token" }, new[] { "keep" } };
        var result = AzureDnsProvider.RemoveTxtValue(existing, "wildcard-token");
        Assert.Equal(new[] { "apex-token", "keep" }, result.Select(r => string.Concat(r)));
        Assert.Empty(AzureDnsProvider.RemoveTxtValue(new List<IReadOnlyList<string>> { new[] { "x" } }, "x"));
    }

    [Fact]
    public void TxtValues_AddRemove_PreserveOthers()
    {
        var stored = new[] { "\"a\"", "b" };
        Assert.Equal(new[] { "\"a\"", "b", "c" }, TxtValues.Add(stored, "c"));
        Assert.Equal(stored, TxtValues.Add(stored, "a"));
        Assert.Equal(new[] { "b" }, TxtValues.Remove(stored, "a"));
    }
}
