using CertMaster.Core.Providers.Dns;

namespace CertMaster.Tests.Dns;

public class NamecheapHostMergeTests
{
    private const string GetHostsXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
          <Errors />
          <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
          <CommandResponse Type="namecheap.domains.dns.getHosts">
            <DomainDNSGetHostsResult Domain="example.co.uk" EmailType="MX" IsUsingOurDNS="true">
              <host HostId="1" Name="@" Type="A" Address="192.0.2.10" MXPref="10" TTL="1800" />
              <host HostId="2" Name="www" Type="CNAME" Address="example.co.uk." MXPref="10" TTL="1800" />
              <host HostId="3" Name="@" Type="MX" Address="mail.example.co.uk." MXPref="20" TTL="3600" />
              <host HostId="4" Name="@" Type="TXT" Address="v=spf1 include:_spf.example.net ~all" MXPref="10" TTL="1800" />
              <host HostId="5" Name="_acme-challenge" Type="TXT" Address="apex-token" MXPref="10" TTL="60" />
            </DomainDNSGetHostsResult>
          </CommandResponse>
        </ApiResponse>
        """;

    [Fact]
    public void ParseGetHosts_ReadsAllHostsAndEmailType()
    {
        var (hosts, emailType, ours) = NamecheapHostMerge.ParseGetHosts(GetHostsXml);
        Assert.Equal(5, hosts.Count);
        Assert.Equal("MX", emailType);
        Assert.True(ours);
        Assert.Equal(new NamecheapHost("@", "MX", "mail.example.co.uk.", "20", "3600"), hosts[2]);
    }

    [Fact]
    public void ParseGetHosts_ApiErrorThrowsWithHint()
    {
        const string xml = """
            <ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
              <Errors><Error Number="1011150">Parameter RequestIP is invalid</Error></Errors>
            </ApiResponse>
            """;
        var ex = Assert.Throws<DnsProviderException>(() => NamecheapHostMerge.ParseGetHosts(xml));
        Assert.Contains("1011150", ex.Message);
        Assert.Contains("Whitelist", ex.Message);
    }

    [Fact]
    public void AddTxt_PreservesEveryExistingRecord_AndAppends()
    {
        var (hosts, _, _) = NamecheapHostMerge.ParseGetHosts(GetHostsXml);
        var merged = NamecheapHostMerge.AddTxt(hosts, "_acme-challenge", "wildcard-token");
        Assert.Equal(6, merged.Count);
        Assert.Equal(hosts, merged.Take(5)); // unchanged and in order
        Assert.Equal(new NamecheapHost("_acme-challenge", "TXT", "wildcard-token", "10", "60"), merged[5]);
    }

    [Fact]
    public void AddTxt_IsIdempotent()
    {
        var (hosts, _, _) = NamecheapHostMerge.ParseGetHosts(GetHostsXml);
        Assert.Equal(hosts, NamecheapHostMerge.AddTxt(hosts, "_ACME-challenge", "apex-token"));
    }

    [Fact]
    public void RemoveTxt_RemovesOnlyThatValue()
    {
        var (hosts, _, _) = NamecheapHostMerge.ParseGetHosts(GetHostsXml);
        var withBoth = NamecheapHostMerge.AddTxt(hosts, "_acme-challenge", "wildcard-token");
        var removed = NamecheapHostMerge.RemoveTxt(withBoth, "_acme-challenge", "wildcard-token");
        Assert.Equal(hosts, removed);
        var removedApex = NamecheapHostMerge.RemoveTxt(withBoth, "_acme-challenge", "apex-token");
        Assert.Equal(5, removedApex.Count);
        Assert.Contains(removedApex, h => h.Address == "wildcard-token");
        Assert.DoesNotContain(removedApex, h => h.Address == "apex-token");
        // SPF TXT on another name with a different value is untouched
        Assert.Contains(removedApex, h => h.Address.StartsWith("v=spf1"));
    }

    [Fact]
    public void BuildSetHostsFields_IndexesEveryHost_AndKeepsEmailType()
    {
        var (hosts, emailType, _) = NamecheapHostMerge.ParseGetHosts(GetHostsXml);
        var fields = NamecheapHostMerge.BuildSetHostsFields("example", "co.uk", hosts, emailType);
        var d = fields.ToDictionary(f => f.Key, f => f.Value);
        Assert.Equal("namecheap.domains.dns.setHosts", d["Command"]);
        Assert.Equal("example", d["SLD"]);
        Assert.Equal("co.uk", d["TLD"]);
        Assert.Equal("MX", d["EmailType"]);
        for (var i = 1; i <= hosts.Count; i++)
        {
            Assert.Equal(hosts[i - 1].Name, d["HostName" + i]);
            Assert.Equal(hosts[i - 1].Type, d["RecordType" + i]);
            Assert.Equal(hosts[i - 1].Address, d["Address" + i]);
            Assert.Equal(hosts[i - 1].MXPref, d["MXPref" + i]);
            Assert.Equal(hosts[i - 1].TTL, d["TTL" + i]);
        }
        Assert.False(d.ContainsKey("HostName" + (hosts.Count + 1)));
    }
}
