using CertMaster.Core.Providers.Dns;

namespace CertMaster.Tests.Dns;

public class DnsPropagationCheckerTests
{
    [Fact]
    public void ContainsTxtValue_JoinsCharacterStrings()
    {
        var records = new List<IEnumerable<string>> { new[] { "v=spf1 -all" }, new[] { "abc", "def" } };
        Assert.True(DnsPropagationChecker.ContainsTxtValue(records, "abcdef"));
        Assert.True(DnsPropagationChecker.ContainsTxtValue(records, "v=spf1 -all"));
        Assert.False(DnsPropagationChecker.ContainsTxtValue(records, "abc"));
        Assert.False(DnsPropagationChecker.ContainsTxtValue(records, "ABCDEF")); // ACME values are case sensitive
        Assert.False(DnsPropagationChecker.ContainsTxtValue(new List<IEnumerable<string>>(), "x"));
    }

    [Fact]
    public void Options_Defaults()
    {
        var o = new DnsPropagationOptions();
        Assert.True(o.FollowCname);
        Assert.True(o.RequireAllNameServers);
        Assert.Equal(TimeSpan.FromSeconds(5), o.PollInterval);
    }

    [Fact]
    public async Task WaitForTxtAsync_HonoursCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            DnsPropagationChecker.WaitForTxtAsync("_acme-challenge.example.invalid", "x", TimeSpan.FromSeconds(1), null, cts.Token));
    }

    /// <summary>Live DNS check; runs only when CERTMASTER_LIVE_DNS_TESTS=1 (needs network).</summary>
    [Fact]
    public async Task Live_ReturnsResultWithoutThrowing()
    {
        if (Environment.GetEnvironmentVariable("CERTMASTER_LIVE_DNS_TESTS") != "1") return;
        var r = await DnsPropagationChecker.WaitForTxtAsync("_acme-challenge.example.com", "no-such-value", TimeSpan.FromSeconds(3));
        Assert.False(r.IsVisible);
        Assert.Equal("example.com", r.Zone);
        Assert.NotEmpty(r.Servers);
    }
}
