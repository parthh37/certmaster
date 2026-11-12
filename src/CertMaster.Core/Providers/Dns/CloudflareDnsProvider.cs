using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

public class CloudflareDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.cloudflare.com/client/v4/";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Cloudflare",
        Title = "Cloudflare DNS API",
        Description = "Validates via Cloudflare DNS using a scoped API token (Zone:Read, DNS:Edit).",
        HelpUrl = "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "Cloudflare",
        ProviderParameters =
        {
            new ProviderParameter { Key = "api_token", Name = "API Token", Type = OptionType.Password, IsRequired = true, IsCredential = true },
        }
    };

    private static HttpRequestMessage Req(DnsProviderContext ctx, HttpMethod method, string path, object? body = null)
    {
        var token = ctx.Cred("api_token") ?? throw new InvalidOperationException("Cloudflare API token not set.");
        var r = new HttpRequestMessage(method, Api + path);
        r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body != null) r.Content = JsonContent.Create(body);
        return r;
    }

    private static async Task<JsonElement> SendAsync(DnsProviderContext ctx, HttpRequestMessage req)
    {
        using var resp = await ctx.Http.SendAsync(req);
        var doc = await resp.Content.ReadFromJsonAsync<JsonElement>();
        if (!resp.IsSuccessStatusCode || !doc.GetProperty("success").GetBoolean())
            throw new InvalidOperationException($"Cloudflare API error ({(int)resp.StatusCode}): {doc.GetProperty("errors")}");
        return doc;
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var zones = new List<DnsZone>();
        for (var page = 1; page < 50; page++)
        {
            var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones?per_page=50&page={page}"));
            foreach (var z in doc.GetProperty("result").EnumerateArray())
                zones.Add(new DnsZone(z.GetProperty("id").GetString()!, z.GetProperty("name").GetString()!));
            var info = doc.GetProperty("result_info");
            if (page >= info.GetProperty("total_pages").GetInt32()) break;
        }
        return zones;
    }

    public override async Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value)
    {
        var zone = await ResolveZoneAsync(ctx, recordName);
        if (zone == null) return ActionResult.Fail($"No Cloudflare zone matches {recordName}");
        await SendAsync(ctx, Req(ctx, HttpMethod.Post, $"zones/{zone.ZoneId}/dns_records",
            new { type = "TXT", name = recordName, content = value, ttl = 60 }));
        return ActionResult.Ok($"Created TXT {recordName} in zone {zone.Name}");
    }

    public override async Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value)
    {
        var zone = await ResolveZoneAsync(ctx, recordName);
        if (zone == null) return ActionResult.Fail($"No Cloudflare zone matches {recordName}");
        var doc = await SendAsync(ctx, Req(ctx, HttpMethod.Get, $"zones/{zone.ZoneId}/dns_records?type=TXT&name={Uri.EscapeDataString(recordName)}"));
        var deleted = 0;
        foreach (var rec in doc.GetProperty("result").EnumerateArray())
        {
            var content = rec.GetProperty("content").GetString()?.Trim('"');
            if (content != value) continue;
            await SendAsync(ctx, Req(ctx, HttpMethod.Delete, $"zones/{zone.ZoneId}/dns_records/{rec.GetProperty("id").GetString()}"));
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT record(s) {recordName}");
    }
}
