using System.Text.Json;
using CertMaster.Core.Providers;
using CertMaster.Core.Providers.Dns;
using CertMaster.Models;

namespace CertMaster.Tests.Dns;

public class PoshAcmeBridgeTests
{
    /// <summary>Scripts/PoshAcme from the test output folder, or from the source tree as a fallback.</summary>
    private static string ScriptsRoot()
    {
        var output = Path.Combine(AppContext.BaseDirectory, "Scripts", "PoshAcme");
        if (Directory.Exists(Path.Combine(output, "Posh-ACME", "Plugins"))) return output;
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "CertMaster.Core", "Scripts", "PoshAcme");
            if (Directory.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Scripts/PoshAcme not found");
    }

    private static PoshAcmePluginInfo Plugin(string name) =>
        PoshAcmePluginParser.Parse(name, File.ReadAllText(Path.Combine(ScriptsRoot(), "Posh-ACME", "Plugins", name + ".ps1")))
        ?? throw new InvalidOperationException("plugin did not parse");

    private static PoshAcmeParameter Param(PoshAcmePluginInfo p, string name) => p.Parameters.Single(x => x.Name == name);

    private static ProviderParameter Field(ChallengeProviderDefinition d, string key) => d.ProviderParameters.Single(x => x.Key == key);

    [Fact]
    public void Cloudflare_ParamBlock()
    {
        var p = Plugin("Cloudflare");
        Assert.Equal("dns-01", p.ChallengeType);
        Assert.True(p.HasRemoveDnsTxt);
        Assert.True(p.HasSaveDnsTxt);
        Assert.False(string.IsNullOrEmpty(p.Synopsis));

        var token = Param(p, "CFToken");
        Assert.Equal("securestring", token.Type);
        Assert.Equal(new[] { "Bearer" }, token.SetNames);
        Assert.True(token.Usages.Single().Mandatory);
        Assert.False(string.IsNullOrEmpty(token.Help));

        var email = Param(p, "CFAuthEmail");
        Assert.Equal("string", email.Type);
        Assert.Equal(new[] { "Email", "DeprecatedEmail" }, email.SetNames);

        var user = PoshAcmePluginParser.UserParameters(p).Select(x => x.Name).ToList();
        Assert.Equal(new[] { "CFAuthEmail", "CFAuthKeySecure", "CFToken" }, user); // deprecated-only and RecordName/TxtValue/ExtraParams dropped
        Assert.Equal(new[] { "Email", "Bearer" }, p.ActiveParameterSets);

        var (def, _) = PoshAcmeDnsProvider.BuildDefinition(p, "4.35.0", false);
        Assert.Equal("DNS01.PoshAcme.Cloudflare", def.Id);
        Assert.Equal("Cloudflare (via Posh-ACME)", def.Title);
        Assert.Equal("PoshAcme.Cloudflare", def.CredentialType);
        var cfToken = Field(def, "CFToken");
        Assert.True(cfToken.IsCredential);
        Assert.Equal(OptionType.Password, cfToken.Type);
        Assert.False(cfToken.IsRequired); // only required within the Bearer set
        Assert.False(Field(def, "CFAuthEmail").IsCredential);
    }

    [Fact]
    public void Route53_ParamBlock()
    {
        var p = Plugin("Route53");
        Assert.Equal("string", Param(p, "R53AccessKey").Type);
        Assert.Equal(new[] { "Keys", "DeprecatedInsecure" }, Param(p, "R53AccessKey").SetNames);
        Assert.Equal("securestring", Param(p, "R53SecretKey").Type);
        Assert.Equal("switch", Param(p, "R53UseIAMRole").Type);
        Assert.Equal(new[] { "Keys", "Profile", "IAMRole" }, p.ActiveParameterSets);

        var (def, fields) = PoshAcmeDnsProvider.BuildDefinition(p, null, false);
        var keys = def.ProviderParameters.Select(x => x.Key).ToList();
        Assert.Equal(new[] { "R53AccessKey", "R53SecretKey", "R53ProfileName", "R53UseIAMRole" }, keys);
        Assert.True(Field(def, "R53AccessKey").IsCredential);             // name contains "Key"
        Assert.Equal(OptionType.Password, Field(def, "R53AccessKey").Type);
        Assert.False(Field(def, "R53ProfileName").IsCredential);
        Assert.Equal(OptionType.Boolean, Field(def, "R53UseIAMRole").Type);
        Assert.False(Field(def, "R53UseIAMRole").IsCredential);
        Assert.Equal("switch", fields.Single(f => f.Key == "R53UseIAMRole").Kind);
    }

    [Fact]
    public void Azure_ParamBlock_RequiredValidateSetDefaultsAndPsCredential()
    {
        var p = Plugin("Azure");
        var sub = Param(p, "AZSubscriptionId");
        Assert.True(sub.MandatoryInAllSets);
        var env = Param(p, "AZEnvironment");
        Assert.Equal("AzureCloud", env.DefaultValue);
        Assert.Equal(new[] { "AzureCloud", "AzureUSGovernment", "AzureGermanCloud", "AzureChinaCloud" }, env.ValidateSet);
        Assert.Equal("pscredential", Param(p, "AZAppCred").Type);
        Assert.Equal("2021-02-01", Param(p, "AZArcAgentAPIVersion").DefaultValue);

        var (def, fields) = PoshAcmeDnsProvider.BuildDefinition(p, "4.35.0", false);
        Assert.True(Field(def, "AZSubscriptionId").IsRequired);
        Assert.False(Field(def, "AZSubscriptionId").IsCredential);
        Assert.Equal(OptionType.Select, Field(def, "AZEnvironment").Type);
        Assert.Equal("AzureCloud", Field(def, "AZEnvironment").Value);
        Assert.True(Field(def, "AZAppCred_User").IsCredential);
        Assert.Equal(OptionType.Password, Field(def, "AZAppCred_Password").Type);
        Assert.DoesNotContain(def.ProviderParameters, x => x.Key is "AZAppPasswordInsecure" or "AZPfxPass" or "RecordName" or "TxtValue" or "ExtraParams");
        Assert.Contains(def.ProviderParameters, x => x.Key == "AZPfxPassSecure" && x.IsCredential);
        Assert.Equal(2, fields.Count(f => f.ParameterName == "AZAppCred"));
    }

    [Fact]
    public void Hetzner_SecureStringRequired_WhenOnlyOneActiveSet()
    {
        var p = Plugin("Hetzner");
        var (def, _) = PoshAcmeDnsProvider.BuildDefinition(p, null, false);
        var token = Assert.Single(def.ProviderParameters);
        Assert.Equal("HetznerToken", token.Key);
        Assert.True(token.IsRequired);
        Assert.True(token.IsCredential);
        Assert.Equal(OptionType.Password, token.Type);
    }

    [Fact]
    public void SimpleDnsPlus_PsCredentialAndSwitch()
    {
        var p = Plugin("SimpleDNSPlus");
        var (def, _) = PoshAcmeDnsProvider.BuildDefinition(p, null, false);
        Assert.Equal(new[] { "SdnsApiRoot", "SdnsCred_User", "SdnsCred_Password", "SdnsIgnoreCert" }, def.ProviderParameters.Select(x => x.Key));
        Assert.True(Field(def, "SdnsApiRoot").IsRequired);
        Assert.False(Field(def, "SdnsCred_User").IsRequired);
    }

    [Fact]
    public void BuildArguments_ConvertsTypes_AndSkipsDefaultsBlanksAndOffSwitches()
    {
        var p = Plugin("Azure");
        var (_, fields) = PoshAcmeDnsProvider.BuildDefinition(p, null, false);
        var values = new Dictionary<string, string>
        {
            ["AZSubscriptionId"] = "sub-id",
            ["AZTenantId"] = "tenant",
            ["AZAppCred_User"] = "app-id",
            ["AZAppCred_Password"] = "s3cret",
            ["AZEnvironment"] = "AzureCloud",           // equals the plugin default: not passed
            ["AZArcAgentAPIVersion"] = "2021-02-01",    // equals the plugin default: must not force the IMDS set
            ["AZUseIMDS"] = "false",                    // switch off: not passed
            ["AZAccessToken"] = "",
        };
        var args = PoshAcmeDnsProvider.BuildArguments(fields, k => values.GetValueOrDefault(k));
        Assert.Equal(new[] { "AZAppCred", "AZSubscriptionId", "AZTenantId" }, args.Keys.OrderBy(k => k));
        Assert.Equal("pscredential", args["AZAppCred"]["Type"]);
        Assert.Equal("app-id", args["AZAppCred"]["User"]);
        Assert.Equal("s3cret", args["AZAppCred"]["Password"]);

        values["AZUseIMDS"] = "true";
        values["AZEnvironment"] = "AzureChinaCloud";
        args = PoshAcmeDnsProvider.BuildArguments(fields, k => values.GetValueOrDefault(k));
        Assert.Equal(true, args["AZUseIMDS"]["Value"]);
        Assert.Equal("AzureChinaCloud", args["AZEnvironment"]["Value"]);

        // JSON shape the wrapper reads
        var json = JsonSerializer.Serialize(args);
        Assert.Contains("\"Type\":\"switch\"", json);
    }

    [Fact]
    public void BuildArguments_HashtableAndArrays()
    {
        var fields = new[]
        {
            new PoshAcmeField("Map", "Map", "hashtable", null, null),
            new PoshAcmeField("List", "List", "stringarray", null, null),
            new PoshAcmeField("Count", "Count", "int", null, null),
        };
        var values = new Dictionary<string, string> { ["Map"] = "{\"a\":\"b\"}", ["List"] = "x, y;z", ["Count"] = "42" };
        var args = PoshAcmeDnsProvider.BuildArguments(fields, k => values.GetValueOrDefault(k));
        Assert.Equal(JsonValueKind.Object, ((JsonElement)args["Map"]["Value"]!).ValueKind);
        Assert.Equal(new[] { "x", "y", "z" }, (string[])args["List"]["Value"]!);
        Assert.Equal(42L, args["Count"]["Value"]);

        values["Map"] = "[1,2]";
        Assert.Throws<DnsProviderException>(() => PoshAcmeDnsProvider.BuildArguments(fields, k => values.GetValueOrDefault(k)));
    }

    [Fact]
    public void Parser_HandlesStringsCommentsAndNestedBrackets()
    {
        const string script = """
            function Get-CurrentPluginType { 'dns-01' }
            function Add-DnsTxt {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory, Position = 0)][string]$RecordName,
                    [Parameter(Mandatory, Position = 1)][string]$TxtValue,
                    # a comment with a comma, and (parens)
                    [Parameter(Mandatory)]
                    [ValidateSet('a,b', "c")]
                    [string]$Choice = 'c',
                    <# block, comment #>
                    [System.Security.SecureString]$ApiSecret,
                    [string[]]$Names = @('x', 'y'),
                    [hashtable]$Extra,
                    [int]$Port = 8080,
                    [Parameter(ValueFromRemainingArguments)]
                    $ExtraParams
                )
                $x = "string with ) and { and $($RecordName.Split(')')[0])"
                <#
                .SYNOPSIS
                    Test plugin.
                .PARAMETER Choice
                    The choice,
                    over two lines.
                #>
            }
            function Remove-DnsTxt { param($RecordName, $TxtValue) }
            """;
        var p = PoshAcmePluginParser.Parse("Test", script)!;
        Assert.Equal("dns-01", p.ChallengeType);
        Assert.False(p.HasSaveDnsTxt);
        Assert.Equal("Test plugin.", p.Synopsis);
        Assert.Equal(new[] { "RecordName", "TxtValue", "Choice", "ApiSecret", "Names", "Extra", "Port", "ExtraParams" }, p.Parameters.Select(x => x.Name));
        var choice = Param(p, "Choice");
        Assert.Equal(new[] { "a,b", "c" }, choice.ValidateSet);
        Assert.Equal("c", choice.DefaultValue);
        Assert.Equal("The choice, over two lines.", choice.Help);
        Assert.True(choice.MandatoryInAllSets);
        Assert.Equal("securestring", Param(p, "ApiSecret").Type);
        Assert.Equal("string[]", Param(p, "Names").Type);
        Assert.Null(Param(p, "Names").DefaultValue); // expression, not a literal
        Assert.Equal("8080", Param(p, "Port").DefaultValue);
        Assert.True(Param(p, "ExtraParams").ValueFromRemainingArguments);
    }

    [Fact]
    public void Source_ReturnsMoreThan50Providers_WhenFolderExists()
    {
        var root = ScriptsRoot();
        var providers = new PoshAcmeProviderSource(root, requirePowerShell: false).GetProviders().ToList();
        Assert.True(providers.Count > 50, $"only {providers.Count} providers");
        Assert.All(providers, p =>
        {
            Assert.StartsWith(PoshAcmeDnsProvider.IdPrefix, p.Definition.Id);
            Assert.EndsWith("(via Posh-ACME)", p.Definition.Title);
            Assert.Equal(ChallengeTypes.Dns01, p.Definition.ChallengeType);
            Assert.DoesNotContain(p.Definition.ProviderParameters, x => x.Key is "RecordName" or "TxtValue" or "ExtraParams");
        });
        Assert.Equal(providers.Count, providers.Select(p => p.Definition.Id).Distinct().Count());
        // natively covered, http-01, example and interactive plugins are skipped
        Assert.DoesNotContain(providers, p => p.Definition.Id is "DNS01.PoshAcme.Cloudflare" or "DNS01.PoshAcme.WebRoot" or "DNS01.PoshAcme._Example-DNS" or "DNS01.PoshAcme.Manual");
        Assert.Contains(providers, p => p.Definition.Id == "DNS01.PoshAcme.Porkbun");

        var all = new PoshAcmeProviderSource(root, requirePowerShell: false, includeNativelyCovered: true).GetProviders().ToList();
        Assert.Contains(all, p => p.Definition.Id == "DNS01.PoshAcme.Cloudflare");
        Assert.Equal(PoshAcmeProviderSource.LoadPlugins(root).Count, all.Count);
        Assert.Equal("4.35.0", PoshAcmeProviderSource.ReadModuleVersion(root));
    }

    private static DnsProviderContext Ctx(Dictionary<string, string> values) => new()
    {
        Credentials = values,
        Parameters = new Dictionary<string, string>(values, StringComparer.OrdinalIgnoreCase),
        Http = new HttpClient(),
        Paths = new CertMaster.Core.Storage.DataPaths(Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"))),
    };

    /// <summary>Runs the real wrapper in PowerShell (no network: "Test" only loads the module and plugin).</summary>
    [Fact]
    public async Task Provider_Test_LoadsPluginThroughPowerShell()
    {
        if (PowerShellLocator.Find() == null) return; // PowerShell not installed on this machine
        var provider = new PoshAcmeProviderSource(ScriptsRoot()).GetProviders().Single(p => p.Definition.Id == "DNS01.PoshAcme.Porkbun");
        var missing = await provider.TestAsync(Ctx(new()));
        Assert.False(missing.IsSuccess);
        Assert.Contains("required field", missing.Message);

        var values = provider.Definition.ProviderParameters.Where(p => p.IsRequired).ToDictionary(p => p.Key, _ => "dummy-value");
        var ok = await provider.TestAsync(Ctx(values));
        Assert.True(ok.IsSuccess, ok.Message);
    }

    /// <summary>A missing mandatory parameter is reported by PowerShell before any API call is made.</summary>
    [Fact]
    public async Task Provider_Add_ReportsPluginErrors()
    {
        if (PowerShellLocator.Find() == null) return;
        var provider = new PoshAcmeProviderSource(ScriptsRoot(), includeNativelyCovered: true).GetProviders().Single(p => p.Definition.Id == "DNS01.PoshAcme.Cloudflare");
        var result = await provider.CreateRecordAsync(Ctx(new()), "_acme-challenge.example.com", "value");
        Assert.False(result.IsSuccess);
        Assert.Contains("CFToken", result.Message);
    }

    [Fact]
    public void Source_MissingFolder_ReturnsNoProviders()
    {
        var missing = Path.Combine(Path.GetTempPath(), "certmaster-no-such-folder-" + Guid.NewGuid().ToString("N"));
        Assert.Empty(new PoshAcmeProviderSource(missing).GetProviders());
    }

    [Fact]
    public void AllBundledDnsPluginsParse()
    {
        var dir = Path.Combine(ScriptsRoot(), "Posh-ACME", "Plugins");
        foreach (var file in Directory.GetFiles(dir, "*.ps1").Where(f => !Path.GetFileName(f).StartsWith('_')))
        {
            var info = PoshAcmePluginParser.Parse(Path.GetFileNameWithoutExtension(file), File.ReadAllText(file));
            if (info?.ChallengeType != "dns-01") continue;
            Assert.True(info.HasRemoveDnsTxt, $"{file}: Remove-DnsTxt not found");
            Assert.Contains(info.Parameters, x => x.Name == "RecordName");
            Assert.Contains(info.Parameters, x => x.Name == "TxtValue");
        }
    }

    [Fact]
    public void Registry_IncludesNativeAndBridgeProviders_WithUniqueIds()
    {
        var registry = new ProviderRegistry();
        var ids = registry.DnsProviders.Select(p => p.Definition.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        foreach (var id in new[]
                 {
                     "DNS01.API.Cloudflare", "DNS01.API.GoDaddy", "DNS01.API.AcmeDns", "DNS01.Scripting", "DNS01.API.Route53", "DNS01.API.Azure",
                     "DNS01.API.DigitalOcean", "DNS01.API.DnsMadeEasy", "DNS01.API.IONOS", "DNS01.API.MSDNS", "DNS01.API.Namecheap", "DNS01.API.OVH",
                     "DNS01.API.SimpleDnsPlus", "DNS01.API.TransIP", "DNS01.API.Aliyun", "DNS01.API.Hetzner", "DNS01.API.Linode",
                 })
            Assert.Contains(id, ids);
        // PoshAcmeDnsProvider has no parameterless constructor, so it is only created through the source.
        Assert.DoesNotContain(registry.DnsProviders, p => p.GetType() == typeof(PoshAcmeDnsProvider) && p.Definition.Id == "DNS01.PoshAcme.");
        var credentialTypes = registry.GetCredentialTypes().Select(t => t.ProviderType).ToList();
        Assert.Contains("AWSRoute53", credentialTypes);
        Assert.Contains("Namecheap", credentialTypes);
        if (PowerShellLocator.Find() != null)
        {
            Assert.Contains(ids, id => id.StartsWith(PoshAcmeDnsProvider.IdPrefix));
            Assert.Contains("PoshAcme.Porkbun", credentialTypes);
        }
    }
}
