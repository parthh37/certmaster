using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>
/// acme-dns (https://github.com/joohoi/acme-dns). On first use for a domain it registers an account and asks the
/// user to create a CNAME from _acme-challenge.domain to the returned fulldomain. Registrations are saved per domain.
/// </summary>
public class AcmeDnsProvider : DnsProviderBase
{
    private const string Name = "acme-dns";

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

    /// <summary>Registration file for a record name; apex and wildcard of a domain share one registration.</summary>
    public static string RegistrationKey(string recordName)
    {
        var name = DnsNames.Normalize(recordName);
        if (name.StartsWith("_acme-challenge.", StringComparison.Ordinal)) name = name["_acme-challenge.".Length..];
        return new string(name.Where(c => char.IsLetterOrDigit(c) || c is '.' or '-').ToArray());
    }

    private static string RegPath(DnsProviderContext ctx, string recordName)
    {
        var dir = ctx.Paths.Combine("acmedns");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, RegistrationKey(recordName) + ".json");
    }

    private static string ApiUrl(DnsProviderContext ctx) =>
        (ctx.Param("api") ?? throw new DnsProviderException("acme-dns: the API URL is not set.")).TrimEnd('/');

    public override async Task<ActionResult> TestAsync(DnsProviderContext ctx)
    {
        try
        {
            var api = ApiUrl(ctx);
            using var resp = await ctx.Http.GetAsync(api + "/health");
            return resp.IsSuccessStatusCode
                ? ActionResult.Ok($"acme-dns server {api} is reachable. Registration happens on first request.")
                : ActionResult.Fail($"acme-dns server {api} answered {(int)resp.StatusCode} on /health. Check the API URL.");
        }
        catch (Exception ex) { return ActionResult.Fail(DescribeError(ex)); }
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var api = ApiUrl(ctx);
        var regFile = RegPath(ctx, recordName);
        Registration? reg = File.Exists(regFile) ? JsonDefaults.Deserialize<Registration>(await File.ReadAllTextAsync(regFile)) : null;

        if (reg == null)
        {
            object body = ctx.Param("allowfrom") is { } allow ? new { allowfrom = new[] { allow } } : new { };
            var json = await DnsHttp.SendAsync(ctx.Http, new HttpRequestMessage(HttpMethod.Post, api + "/register") { Content = DnsHttp.Json(body) }, Name);
            reg = JsonDefaults.Deserialize<Registration>(json);
            if (reg == null || string.IsNullOrEmpty(reg.Fulldomain) || string.IsNullOrEmpty(reg.Subdomain))
                throw new DnsProviderException($"acme-dns: invalid registration response from {api}: {DnsHttp.Truncate(json, 200)}");
            await File.WriteAllTextAsync(regFile, JsonDefaults.Serialize(reg));
            ctx.Log?.Warn($"acme-dns registered. Create this CNAME before continuing: {recordName} CNAME {reg.Fulldomain}");
            return new ActionResult(false, $"Action required: create CNAME {recordName} -> {reg.Fulldomain}, then request again.");
        }

        // Warn early when the delegation CNAME is missing; validation would fail otherwise.
        try
        {
            var target = await DnsPropagationChecker.ResolveCnameTargetAsync(recordName);
            if (!DnsNames.Normalize(target).Equals(DnsNames.Normalize(reg.Fulldomain), StringComparison.Ordinal))
                ctx.Log?.Warn($"acme-dns: {recordName} does not appear to CNAME to {reg.Fulldomain} (resolves to {target}). Create: {recordName} CNAME {reg.Fulldomain}");
        }
        catch { /* DNS lookup problems are not fatal here */ }

        var req = new HttpRequestMessage(HttpMethod.Post, api + "/update") { Content = DnsHttp.Json(new { subdomain = reg.Subdomain, txt = value }) };
        req.Headers.Add("X-Api-User", reg.Username);
        req.Headers.Add("X-Api-Key", reg.Password);
        try { await DnsHttp.SendAsync(ctx.Http, req, Name); }
        catch (DnsProviderException ex) when (ex.Message.Contains("401"))
        {
            throw new DnsProviderException(ex.Message + $" The saved acme-dns registration may be invalid for this server; delete {regFile} to register again (a new CNAME will then be required).", ex);
        }
        return ActionResult.Ok($"acme-dns TXT updated for {reg.Fulldomain}");
    });

    // acme-dns keeps the last two TXT values; nothing to clean up.
    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) =>
        Task.FromResult(ActionResult.Ok("acme-dns: no cleanup required"));
}
