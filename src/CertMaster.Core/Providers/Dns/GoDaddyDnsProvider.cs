using System.Net.Http.Json;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

public class GoDaddyDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.godaddy.com/v1/";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.GoDaddy",
        Title = "GoDaddy DNS API",
        Description = "Validates via GoDaddy DNS using a production API key and secret.",
        HelpUrl = "https://developer.godaddy.com/keys",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 120,
        CredentialType = "GoDaddy",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_key", Name = "API Key", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "api_secret", Name = "API Secret", Type = OptionType.Password, IsRequired = true, IsCredential = true },
        }
    };

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var r = new HttpRequestMessage(m, Api + path);
        r.Headers.TryAddWithoutValidation("Authorization", $"sso-key {ctx.Cred("api_key")}:{ctx.Cred("api_secret")}");
        if (body != null) r.Content = JsonContent.Create(body);
        return r;
    }

    private static async Task<string> SendAsync(DnsProviderContext ctx, HttpRequestMessage req)
    {
        using var resp = await ctx.Http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"GoDaddy API error ({(int)resp.StatusCode}): {text}");
        return text;
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var json = await SendAsync(ctx, Req(ctx, HttpMethod.Get, "domains?statuses=ACTIVE&limit=1000"));
        return JsonDocument.Parse(json).RootElement.EnumerateArray()
            .Select(d => d.GetProperty("domain").GetString()!)
            .Select(d => new DnsZone(d, d)).ToList();
    }

    public override async Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value)
    {
        var zone = await ResolveZoneAsync(ctx, recordName);
        if (zone == null) return ActionResult.Fail($"No GoDaddy domain matches {recordName}");
        var rel = RelativeName(recordName, zone.Name);
        await SendAsync(ctx, Req(ctx, HttpMethod.Patch, $"domains/{zone.Name}/records",
            new[] { new { type = "TXT", name = rel, data = value, ttl = 600 } }));
        return ActionResult.Ok($"Created TXT {rel} in {zone.Name}");
    }

    public override async Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value)
    {
        var zone = await ResolveZoneAsync(ctx, recordName);
        if (zone == null) return ActionResult.Fail($"No GoDaddy domain matches {recordName}");
        var rel = RelativeName(recordName, zone.Name);
        // Keep any other TXT values on the same name, remove only ours.
        var existing = JsonDocument.Parse(await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"domains/{zone.Name}/records/TXT/{rel}")))
            .RootElement.EnumerateArray().Select(r => r.GetProperty("data").GetString()).Where(v => v != value).ToList();
        if (existing.Count == 0)
            await SendAsync(ctx, Req(ctx, HttpMethod.Delete, $"domains/{zone.Name}/records/TXT/{rel}"));
        else
            await SendAsync(ctx, Req(ctx, HttpMethod.Put, $"domains/{zone.Name}/records/TXT/{rel}",
                existing.Select(v => new { data = v, ttl = 600 }).ToArray()));
        return ActionResult.Ok($"Removed TXT {rel} from {zone.Name}");
    }
}
