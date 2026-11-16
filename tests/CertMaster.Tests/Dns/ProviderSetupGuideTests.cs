using System.Text.Json;
using CertMaster.Core.Providers;
using CertMaster.Core.Providers.Dns;
using CertMaster.Models;

namespace CertMaster.Tests.Dns;

/// <summary>The Route 53 setup guide shown in the editors must stay accurate: valid policy, every API action the provider calls, working links.</summary>
public class ProviderSetupGuideTests
{
    private static ChallengeProviderDefinition Route53 =>
        new ProviderRegistry().GetChallengeProviders().Single(p => p.Id == "DNS01.API.Route53");

    [Fact]
    public void Route53_PolicyIsValidJson_AndGrantsEveryActionTheProviderCalls()
    {
        using var doc = JsonDocument.Parse(Route53DnsProvider.IamPolicyJson);
        var actions = doc.RootElement.GetProperty("Statement").EnumerateArray()
            .SelectMany(s => s.GetProperty("Action").EnumerateArray().Select(a => a.GetString()))
            .ToHashSet();
        foreach (var needed in new[] { "ListHostedZones", "GetHostedZone", "ListResourceRecordSets", "ChangeResourceRecordSets", "GetChange" })
            Assert.Contains("route53:" + needed, actions);
    }

    [Fact]
    public void Route53_DefinitionCarriesTheGuide_WithPolicyCliAndHttpsLinks()
    {
        var guide = Route53.SetupGuide;
        Assert.NotNull(guide);
        Assert.NotEmpty(guide!.Steps);
        Assert.Contains(guide.Snippets, s => s.Text == Route53DnsProvider.IamPolicyJson);
        Assert.Contains(guide.Snippets, s => s.Text.Contains("Amazon.AWSCLI"));
        Assert.Contains(guide.Links, l => l.Url == "https://awscli.amazonaws.com/AWSCLIV2.msi");
        Assert.All(guide.Links, l => Assert.StartsWith("https://", l.Url));
    }

    [Fact]
    public void Route53_GuideSurvivesTheApiJsonRoundTrip()
    {
        var copy = JsonDefaults.Deserialize<List<ChallengeProviderDefinition>>(JsonDefaults.Serialize(new List<ChallengeProviderDefinition> { Route53 }))!.Single();
        Assert.Equal(Route53.SetupGuide!.Title, copy.SetupGuide?.Title);
        Assert.Equal(Route53.SetupGuide.Steps.Count, copy.SetupGuide!.Steps.Count);
        Assert.Equal(Route53.SetupGuide.Snippets.Count, copy.SetupGuide.Snippets.Count);
    }

    [Fact]
    public void Route53_HasACredentialTypeTheAddButtonCanOpen()
    {
        var type = new ProviderRegistry().GetCredentialTypes().Single(t => t.ProviderType == Route53.CredentialType);
        Assert.Contains(type.Fields, f => f.Key == "access_key");
        Assert.Contains(type.Fields, f => f.Key == "secret_key" && f.Type == OptionType.Password);
    }
}
