using CertMaster.Models;

namespace CertMaster.Core.Acme;

public static class CertificateAuthorities
{
    public static readonly List<CertificateAuthority> BuiltIn = new()
    {
        new() { Id = "letsencrypt.org", Title = "Let's Encrypt", WebsiteUrl = "https://letsencrypt.org",
            TermsAndConditionsUrl = "https://letsencrypt.org/repository/",
            ProductionAPIEndpoint = "https://acme-v02.api.letsencrypt.org/directory",
            StagingAPIEndpoint = "https://acme-staging-v02.api.letsencrypt.org/directory",
            Description = "Free, automated and open certificate authority by ISRG.", SANLimit = 100, StandardExpiryDays = 90 },
        new() { Id = "zerossl.com", Title = "ZeroSSL", WebsiteUrl = "https://zerossl.com",
            ProductionAPIEndpoint = "https://acme.zerossl.com/v2/DV90", RequiresExternalAccountBinding = true,
            EabInstructions = "Generate EAB credentials in your ZeroSSL account: Developer > EAB Credentials.",
            Description = "Free 90 day certificates. Requires External Account Binding (EAB).", StandardExpiryDays = 90 },
        new() { Id = "google.com", Title = "Google Trust Services", WebsiteUrl = "https://pki.goog",
            ProductionAPIEndpoint = "https://dv.acme-v02.api.pki.goog/directory",
            StagingAPIEndpoint = "https://dv.acme-v02.test-api.pki.goog/directory", RequiresExternalAccountBinding = true,
            EabInstructions = "Create EAB key with: gcloud publicca external-account-keys create",
            Description = "Google public CA. Requires EAB.", StandardExpiryDays = 90 },
        new() { Id = "ssl.com", Title = "SSL.com", WebsiteUrl = "https://ssl.com",
            ProductionAPIEndpoint = "https://acme.ssl.com/sslcom-dv-rsa", RequiresExternalAccountBinding = true,
            Description = "SSL.com DV certificates (RSA). Requires EAB.", StandardExpiryDays = 90 },
        new() { Id = "sectigo.com", Title = "Sectigo", WebsiteUrl = "https://sectigo.com",
            ProductionAPIEndpoint = "https://acme.sectigo.com/v2/DV", RequiresExternalAccountBinding = true,
            Description = "Sectigo DV via ACME. Requires EAB.", StandardExpiryDays = 90 },
        new() { Id = "actalis.it", Title = "Actalis", WebsiteUrl = "https://www.actalis.it",
            ProductionAPIEndpoint = "https://acme-api.actalis.com/acme/directory", RequiresExternalAccountBinding = true,
            Description = "Actalis free DV certificates. Requires EAB.", StandardExpiryDays = 90 },
    };
}
