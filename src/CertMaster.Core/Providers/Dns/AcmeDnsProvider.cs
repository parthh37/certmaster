using System.Net.Http.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>
/// acme-dns (https://github.com/joohoi/acme-dns). On first use for a domain it registers an account and asks the
/// user to create a CNAME from _acme-challenge.domain to the returned fulldomain. Registrations are saved per domain.
/// </summary>
public class AcmeDnsProvider : DnsProviderBase
{
    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.AcmeDns",
        Title = "acme-dns",
        Description = "Delegated validation via an acme-dns server. Requires a one-time CNAME per domain.",
        HelpUrl = "https://github.com/joohoi/acme-dns",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 10,
        ProviderParameters =
        {
            new ProviderParameter { Key = "api", Name = "acme-dns API URL", Value = "https://auth.acme-dns.io", IsRequired = true },
            new ProviderParameter { Key = "allowfrom", Name = "Allow updates from (CIDR, optional)" },
        }
    };

    private record Registration(string Username, string Password, string Fulldomain, string Subdomain);

    private static string RegPath(DnsProviderContext ctx, string recordName)
    {
        var dir = ctx.Paths.Combine("acmedns");
        Directory.CreateDirectory(dir);
        var key = new string(recordName.Replace("_acme-challenge.", "").Where(c => char.IsLetterOrDigit(c) || c is '.' or '-').ToArray());
        return Path.Combine(dir, key + ".json");
    }

    public override Task<ActionResult> TestAsync(DnsProviderContext ctx) =>
        Task.FromResult(ctx.Param("api") == null ? ActionResult.Fail("acme-dns API URL is required") : ActionResult.Ok("acme-dns configured. Registration happens on first request."));

    public override async Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value)
    {
        var api = ctx.Param("api")!.TrimEnd('/');
        var regFile = RegPath(ctx, recordName);
        Registration? reg = File.Exists(regFile) ? JsonDefaults.Deserialize<Registration>(await File.ReadAllTextAsync(regFile)) : null;

        if (reg == null)
        {
            object body = ctx.Param("allowfrom") is { } allow ? new { allowfrom = new[] { allow } } : new { };
            using var resp = await ctx.Http.PostAsJsonAsync(api + "/register", body);
            resp.EnsureSuccessStatusCode();
            reg = await resp.Content.ReadFromJsonAsync<Registration>(JsonDefaults.Options)
                  ?? throw new InvalidOperationException("Invalid acme-dns registration response");
            await File.WriteAllTextAsync(regFile, JsonDefaults.Serialize(reg));
            ctx.Log?.Warn($"acme-dns registered. Create this CNAME before continuing: {recordName} CNAME {reg.Fulldomain}");
            return new ActionResult(false, $"Action required: create CNAME {recordName} -> {reg.Fulldomain}, then request again.");
        }

        var req = new HttpRequestMessage(HttpMethod.Post, api + "/update") { Content = JsonContent.Create(new { subdomain = reg.Subdomain, txt = value }) };
        req.Headers.Add("X-Api-User", reg.Username);
        req.Headers.Add("X-Api-Key", reg.Password);
        using var r = await ctx.Http.SendAsync(req);
        if (!r.IsSuccessStatusCode) return ActionResult.Fail($"acme-dns update failed: {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        return ActionResult.Ok($"acme-dns TXT updated for {reg.Fulldomain}");
    }

    // acme-dns keeps the last two TXT values; nothing to clean up.
    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) =>
        Task.FromResult(ActionResult.Ok("acme-dns: no cleanup required"));
}
