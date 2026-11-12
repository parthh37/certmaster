using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>
/// TransIP REST API v6. Authentication: the JSON body of POST /auth is signed with the account's RSA private key
/// (SHA512, PKCS#1 v1.5) and exchanged for a short-lived JWT bearer token. Each TXT value is a separate DNS entry.
/// </summary>
public class TransIpDnsProvider : DnsProviderBase
{
    private const string Api = "https://api.transip.nl/v6/";
    private const string Name = "TransIP";
    private static readonly ConditionalWeakTable<DnsProviderContext, StrongBox<(string Token, DateTimeOffset Expires)>> Tokens = new();

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.TransIP",
        Title = "TransIP DNS API",
        Description = "Validates via TransIP DNS using your login name and an API key pair private key (PEM). Turn off the IP whitelist for the key, or keep it on and run from a whitelisted address.",
        HelpUrl = "https://api.transip.nl/rest/docs.html",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 120,
        CredentialType = "TransIP",
        ProviderParameters =
        {
            new ProviderParameter { Key = "login", Name = "Login (account name)", IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "private_key", Name = "Private Key (PEM text or file path)", Type = OptionType.MultiLineText, IsRequired = true, IsCredential = true },
            new ProviderParameter { Key = "global_key", Name = "Key is not IP-whitelisted (global key)", Type = OptionType.Boolean, Value = "true", Description = "Untick when the key pair was created with 'Only accept IP addresses from the whitelist'." },
        }
    };

    // ---------- signing (unit tested) ----------

    /// <summary>Signature header for an /auth request body: base64(RSA-SHA512-PKCS1(body)).</summary>
    public static string SignBody(string body, RSA privateKey) =>
        Convert.ToBase64String(privateKey.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));

    /// <summary>Loads an RSA key from PEM text ("BEGIN PRIVATE KEY" or "BEGIN RSA PRIVATE KEY") or from a PEM file path.</summary>
    public static RSA LoadPrivateKey(string pemOrPath)
    {
        var pem = pemOrPath.Contains("-----BEGIN", StringComparison.Ordinal) ? pemOrPath
            : File.Exists(pemOrPath.Trim()) ? File.ReadAllText(pemOrPath.Trim())
            : throw new DnsProviderException("TransIP: the private key is neither PEM text nor an existing file path.");
        var rsa = RSA.Create();
        try { rsa.ImportFromPem(pem); return rsa; }
        catch (Exception ex)
        {
            rsa.Dispose();
            throw new DnsProviderException($"TransIP: could not read the RSA private key ({ex.Message}). Paste the full key including the BEGIN/END lines.", ex);
        }
    }

    private static async Task<string> GetTokenAsync(DnsProviderContext ctx)
    {
        if (Tokens.TryGetValue(ctx, out var cached) && cached.Value.Expires > DateTimeOffset.UtcNow.AddMinutes(1)) return cached.Value.Token;
        var login = ctx.Require("login", "Login", Name);
        using var rsa = LoadPrivateKey(ctx.Require("private_key", "Private Key", Name));
        var body = DnsHttp.Serialize(new
        {
            login,
            nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            read_only = false,
            expiration_time = "30 minutes",
            label = "CertMaster-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            global_key = ctx.Flag("global_key", true),
        });
        var req = new HttpRequestMessage(HttpMethod.Post, Api + "auth") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        req.Headers.TryAddWithoutValidation("Signature", SignBody(body, rsa));
        JsonElement doc;
        try { doc = await DnsHttp.SendJsonAsync(ctx.Http, req, Name); }
        catch (DnsProviderException ex) when (ex.Message.Contains(" 401 ") || ex.Message.Contains(" 403 "))
        {
            throw new DnsProviderException(ex.Message + " Check the login name and that the private key belongs to an active TransIP API key pair (and the IP whitelist setting matches).", ex);
        }
        var token = doc.Str("token") ?? throw new DnsProviderException("TransIP: the /auth response did not contain a token.");
        Tokens.AddOrUpdate(ctx, new StrongBox<(string, DateTimeOffset)>((token, DateTimeOffset.UtcNow.AddMinutes(25))));
        return token;
    }

    private static async Task<HttpRequestMessage> Req(DnsProviderContext ctx, HttpMethod m, string path, object? body = null)
    {
        var r = new HttpRequestMessage(m, Api + path);
        r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetTokenAsync(ctx));
        if (body != null) r.Content = DnsHttp.Json(body);
        return r;
    }

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var doc = await DnsHttp.SendJsonAsync(ctx.Http, await Req(ctx, HttpMethod.Get, "domains"), Name);
        return doc.Prop("domains").Items().Select(d => d.Str("name")!).Select(n => new DnsZone(n, n)).ToList();
    }

    private static async Task<List<JsonElement>> GetTxtAsync(DnsProviderContext ctx, DnsZone zone, string rel)
    {
        var doc = await DnsHttp.SendJsonAsync(ctx.Http, await Req(ctx, HttpMethod.Get, $"domains/{zone.Name}/dns"), Name);
        return doc.Prop("dnsEntries").Items()
            .Where(e => e.Str("type") == "TXT" && string.Equals(e.Str("name"), rel, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        if ((await GetTxtAsync(ctx, zone, rel)).Any(e => TxtValues.Matches(e.Str("content"), value)))
            return ActionResult.Ok($"TXT {recordName} already has this value");
        await DnsHttp.SendAsync(ctx.Http, await Req(ctx, HttpMethod.Post, $"domains/{zone.Name}/dns",
            new { dnsEntry = new { name = rel, expire = 60, type = "TXT", content = value } }), Name);
        return ActionResult.Ok($"Created TXT {recordName} in {zone.Name}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var deleted = 0;
        foreach (var e in await GetTxtAsync(ctx, zone, rel))
        {
            if (!TxtValues.Matches(e.Str("content"), value)) continue;
            var expire = int.TryParse(e.Str("expire"), out var x) ? x : 60;
            // The entry to delete is identified by its full contents.
            await DnsHttp.SendAsync(ctx.Http, await Req(ctx, HttpMethod.Delete, $"domains/{zone.Name}/dns",
                new { dnsEntry = new { name = rel, expire, type = "TXT", content = e.Str("content") } }), Name);
            deleted++;
        }
        return ActionResult.Ok($"Deleted {deleted} TXT entr{(deleted == 1 ? "y" : "ies")} {recordName}");
    });
}
