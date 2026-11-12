using Certes;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core.Acme;

/// <summary>ACME accounts and certificate authorities.</summary>
public class AcmeService
{
    private const string AccountsCollection = "accounts";
    private const string CaCollection = "certificateauthorities";
    private readonly DocumentStore _store;
    private readonly ILogger<AcmeService> _logger;

    public AcmeService(DocumentStore store, ILogger<AcmeService> logger)
    {
        _store = store;
        _logger = logger;
    }

    public async Task<List<CertificateAuthority>> GetCertificateAuthoritiesAsync()
    {
        var custom = await _store.GetAllAsync<CertificateAuthority>(CaCollection);
        foreach (var c in custom) c.IsCustom = true;
        return CertificateAuthorities.BuiltIn.Where(b => custom.All(c => c.Id != b.Id)).Concat(custom).ToList();
    }

    public async Task<ActionResult> UpdateCertificateAuthorityAsync(CertificateAuthority ca)
    {
        if (CertificateAuthorities.BuiltIn.Any(b => b.Id == ca.Id)) return ActionResult.Fail("Built-in certificate authorities cannot be modified.");
        if (!Uri.TryCreate(ca.ProductionAPIEndpoint, UriKind.Absolute, out _)) return ActionResult.Fail("A valid ACME directory URL is required.");
        if (string.IsNullOrWhiteSpace(ca.Id)) ca.Id = Guid.NewGuid().ToString();
        ca.IsCustom = true;
        await _store.UpsertAsync(CaCollection, ca.Id, ca);
        return ActionResult.Ok("Certificate authority saved");
    }

    public Task<bool> RemoveCertificateAuthorityAsync(string id) => _store.DeleteAsync(CaCollection, id);

    public async Task<CertificateAuthority?> GetCertificateAuthorityAsync(string? id) =>
        (await GetCertificateAuthoritiesAsync()).FirstOrDefault(c => c.Id == id);

    /// <summary>Accounts without secret material.</summary>
    public async Task<List<AccountDetails>> GetAccountsAsync()
    {
        var all = await _store.GetAllAsync<AccountDetails>(AccountsCollection);
        foreach (var a in all) { a.AccountKey = null; a.EabKey = null; }
        return all;
    }

    internal async Task<AccountDetails?> GetAccountForRequestAsync(string caId, bool staging)
    {
        var all = await _store.GetAllAsync<AccountDetails>(AccountsCollection);
        return all.FirstOrDefault(a => a.CertificateAuthorityId == caId && a.IsStagingAccount == staging);
    }

    public async Task<ActionResult<AccountDetails>> AddAccountAsync(NewAccountRequest req)
    {
        var ca = await GetCertificateAuthorityAsync(req.CertificateAuthorityId);
        if (ca == null) return new ActionResult<AccountDetails> { Message = "Unknown certificate authority" };
        if (!req.AgreedToTermsAndConditions) return new ActionResult<AccountDetails> { Message = "You must agree to the CA terms and conditions." };
        if (ca.RequiresEmailAddress && string.IsNullOrWhiteSpace(req.Email)) return new ActionResult<AccountDetails> { Message = "Email address is required." };
        if (ca.RequiresExternalAccountBinding && (string.IsNullOrWhiteSpace(req.EabKeyId) || string.IsNullOrWhiteSpace(req.EabKey)))
            return new ActionResult<AccountDetails> { Message = "This CA requires External Account Binding (EAB) Key Id and HMAC Key." };

        var endpoint = req.IsStaging ? ca.StagingAPIEndpoint : ca.ProductionAPIEndpoint;
        if (string.IsNullOrEmpty(endpoint)) return new ActionResult<AccountDetails> { Message = "This CA has no " + (req.IsStaging ? "staging" : "production") + " endpoint." };

        try
        {
            var key = string.IsNullOrWhiteSpace(req.ImportedAccountKey) ? KeyFactory.NewKey(KeyAlgorithm.ES256) : KeyFactory.FromPem(req.ImportedAccountKey);
            var ctx = CreateContext(new Uri(endpoint), key, ca);
            var contact = string.IsNullOrWhiteSpace(req.Email) ? new List<string>() : new List<string> { "mailto:" + req.Email.Trim() };
            var account = string.IsNullOrWhiteSpace(req.EabKeyId)
                ? await ctx.NewAccount(contact, true, null, null, null)
                : await ctx.NewAccount(contact, true, req.EabKeyId, req.EabKey, req.EabKeyAlg ?? "HS256");

            var details = new AccountDetails
            {
                CertificateAuthorityId = ca.Id,
                IsStagingAccount = req.IsStaging,
                Email = req.Email.Trim(),
                Title = $"{ca.Title}{(req.IsStaging ? " (Staging)" : "")} - {req.Email}",
                AccountURI = account.Location?.ToString(),
                AccountKey = key.ToPem(),
                EabKeyId = req.EabKeyId,
                EabKey = req.EabKey,
                EabKeyAlg = req.EabKeyAlg,
            };

            // one account per CA + environment: replace an existing one
            var existing = await GetAccountForRequestAsync(ca.Id, req.IsStaging);
            if (existing != null) await _store.DeleteAsync(AccountsCollection, existing.StorageKey);
            await _store.UpsertAsync(AccountsCollection, details.StorageKey, details);
            _logger.LogInformation("Registered ACME account {Uri} with {Ca}", details.AccountURI, ca.Title);

            var result = JsonDefaults.Clone(details);
            result.AccountKey = null; result.EabKey = null;
            return new ActionResult<AccountDetails> { IsSuccess = true, Message = "Account registered", Result = result };
        }
        catch (AcmeRequestException ex)
        {
            return new ActionResult<AccountDetails> { Message = $"CA rejected the account registration: {ex.Error?.Detail ?? ex.Message}" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Account registration failed");
            return new ActionResult<AccountDetails> { Message = "Account registration failed: " + ex.Message };
        }
    }

    public Task<bool> RemoveAccountAsync(string storageKey) => _store.DeleteAsync(AccountsCollection, storageKey);

    internal async Task<(IAcmeContext ctx, AccountDetails account, CertificateAuthority ca)> GetContextAsync(string? caId, bool staging)
    {
        var ca = await GetCertificateAuthorityAsync(caId ?? "letsencrypt.org") ?? throw new InvalidOperationException($"Unknown certificate authority '{caId}'.");
        var account = await GetAccountForRequestAsync(ca.Id, staging)
                      ?? throw new InvalidOperationException($"No {(staging ? "staging " : "")}ACME account registered for {ca.Title}. Add one in Settings > Certificate Authorities.");
        var endpoint = staging ? ca.StagingAPIEndpoint : ca.ProductionAPIEndpoint;
        var ctx = CreateContext(new Uri(endpoint!), KeyFactory.FromPem(account.AccountKey!), ca);
        return (ctx, account, ca);
    }

    private static readonly HttpClient UntrustedTlsHttp = new(new HttpClientHandler
    {
        // Opt-in per custom CA only (test CAs like Pebble, internal CAs with private roots). Built-in CAs always validate TLS.
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
    });

    private IAcmeContext CreateContext(Uri directory, IKey key, CertificateAuthority ca)
    {
        if (ca.AllowUntrustedTls && ca.IsCustom)
        {
            _logger.LogWarning("TLS certificate validation is disabled for custom CA {Ca}", ca.Title);
            return new AcmeContext(directory, key, new Certes.Acme.AcmeHttpClient(directory, UntrustedTlsHttp));
        }
        return new AcmeContext(directory, key);
    }
}
