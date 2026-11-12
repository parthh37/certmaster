using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.AppService;
using Azure.ResourceManager.AppService.Models;
using Azure.ResourceManager.Resources;
using Azure.Security.KeyVault.Certificates;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Credential type for Azure tasks: a Microsoft Entra ID app registration (service principal) with a client secret.</summary>
public class AzureCredentialTypes : ICredentialTypeSource
{
    public const string AzureServicePrincipal = "AzureServicePrincipal";

    public IEnumerable<CredentialTypeDefinition> GetCredentialTypes() => new[]
    {
        new CredentialTypeDefinition
        {
            ProviderType = AzureServicePrincipal, Title = "Azure Service Principal (tenant, client id, client secret)",
            Fields =
            {
                new ProviderParameter { Key = "tenant_id", Name = "Tenant (directory) ID", IsRequired = true, IsCredential = true },
                new ProviderParameter { Key = "client_id", Name = "Client (application) ID", IsRequired = true, IsCredential = true },
                new ProviderParameter { Key = "client_secret", Name = "Client secret", Type = OptionType.Password, IsRequired = true, IsCredential = true },
            }
        }
    };

    internal static List<ActionStep> Validate(DeploymentContext ctx)
    {
        var errors = new List<ActionStep>();
        foreach (var key in new[] { "tenant_id", "client_id", "client_secret" })
            if (ctx.Credentials.Count > 0 && string.IsNullOrWhiteSpace(ctx.Credentials.GetValueOrDefault(key)))
                errors.Add(new ActionStep($"The Azure credential is missing '{key}'", hasError: true));
        return errors;
    }

    internal static TokenCredential Create(DeploymentContext ctx) =>
        new ClientSecretCredential(ctx.Credentials["tenant_id"].Trim(), ctx.Credentials["client_id"].Trim(), ctx.Credentials["client_secret"]);
}

/// <summary>Upload the certificate to an Azure App Service and optionally bind it to a custom host name.</summary>
public partial class AzureAppServiceDeploymentTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.AzureAppService",
        Title = "Deploy to Azure App Service",
        DefaultTitle = "Deploy to Azure App Service",
        Description = "Upload the certificate (PFX) to an Azure App Service as an App Service certificate and optionally bind it (SNI SSL) to one of the app's custom host names.",
        UsageNote = "The service principal needs Contributor (or Website Contributor plus certificate write) on the resource group. The host name must already be added to the app.",
        CredentialType = AzureCredentialTypes.AzureServicePrincipal,
        ProviderParameters =
        {
            new ProviderParameter { Key = "subscriptionid", Name = "Subscription ID", IsRequired = true },
            new ProviderParameter { Key = "resourcegroup", Name = "Resource group", IsRequired = true },
            new ProviderParameter { Key = "appname", Name = "App name", IsRequired = true, Description = "The web app (site) name" },
            new ProviderParameter { Key = "hostname", Name = "Host name to bind (optional)", Description = "e.g. www.example.com. Blank = upload only." },
            new ProviderParameter { Key = "certname", Name = "Certificate resource name (optional)", Description = "Default: <app>-<thumbprint>" },
        }
    };

    [GeneratedRegex(@"^[A-Za-z0-9_\-\.\(\)]{1,90}$")] private static partial Regex ResourceGroupRegex();
    [GeneratedRegex(@"^[A-Za-z0-9\-]{1,60}$")] private static partial Regex AppNameRegex();
    [GeneratedRegex(@"^[A-Za-z0-9_\-\.]{1,260}$")] private static partial Regex CertNameRegex();

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        errors.AddRange(AzureCredentialTypes.Validate(ctx));
        if (ctx.Param("subscriptionid") is { } s && !Guid.TryParse(s, out _)) errors.Add(Error("Subscription ID must be a GUID"));
        if (ctx.Param("resourcegroup") is { } rg && !ResourceGroupRegex().IsMatch(rg)) errors.Add(Error($"Invalid resource group name '{rg}'"));
        if (ctx.Param("appname") is { } app && !AppNameRegex().IsMatch(app)) errors.Add(Error($"Invalid app name '{app}'"));
        if (ctx.Param("certname") is { } cn && !CertNameRegex().IsMatch(cn)) errors.Add(Error($"Invalid certificate name '{cn}'"));
        if (ctx.Param("hostname") is { } h && !MatchesCertificate(h, ctx.Item.GetAllDomains()))
            errors.Add(Error($"Host name {h} is not covered by the certificate's domains ({string.Join(", ", ctx.Item.GetAllDomains())})"));
    }

    /// <summary>True when the host name equals one of the domains or matches a wildcard domain one level deep.</summary>
    public static bool MatchesCertificate(string hostname, IEnumerable<string> domains)
    {
        var h = hostname.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var d in domains.Select(x => x.Trim().ToLowerInvariant()))
        {
            if (d == h) return true;
            if (d.StartsWith("*.") && h.EndsWith(d[1..]) && h.Length > d.Length - 1 && !h[..(h.Length - d.Length + 1)].Contains('.')) return true;
        }
        return false;
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var subId = ctx.Param("subscriptionid")!.Trim();
        var rgName = ctx.Param("resourcegroup")!.Trim();
        var appName = ctx.Param("appname")!.Trim();
        var hostname = ctx.Param("hostname")?.Trim();
        var certName = ctx.Param("certname") ?? $"{appName}-{ctx.Item.CertificateThumbprintHash ?? "certificate"}";
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would upload certificate '{certName}' to App Service {appName} (resource group {rgName})" + (hostname != null ? $" and bind it to {hostname} (SNI)" : ""));
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "Azure App Service deployment", async () =>
        {
            // App Service requires a password-protected PFX; protect it with a random one-time password.
            var uploadPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
            byte[] pfx;
            string thumbprint;
            using (var material = CertificateMaterial.Load(ctx.Files, lookupRootInStore: false))
            {
                pfx = material.ToPfx(uploadPassword, includeRoot: false);
                thumbprint = material.Leaf.Thumbprint;
            }

            var arm = new ArmClient(AzureCredentialTypes.Create(ctx), subId);
            var sub = arm.GetSubscriptionResource(SubscriptionResource.CreateResourceIdentifier(subId));
            ResourceGroupResource rg;
            try { rg = (await sub.GetResourceGroupAsync(rgName, ct)).Value; }
            catch (RequestFailedException ex) when (ex.Status == 404) { return Fail(ctx, $"Resource group '{rgName}' not found in subscription {subId}"); }
            WebSiteResource site;
            try { site = (await rg.GetWebSiteAsync(appName, ct)).Value; }
            catch (RequestFailedException ex) when (ex.Status == 404) { return Fail(ctx, $"App '{appName}' not found in resource group '{rgName}'"); }

            ctx.Log.Info($"Uploading certificate {thumbprint} as '{certName}' to {appName} ({site.Data.Location})");
            var data = new AppCertificateData(site.Data.Location) { PfxBlob = pfx, Password = uploadPassword, ServerFarmId = site.Data.AppServicePlanId };
            var cert = (await rg.GetAppCertificates().CreateOrUpdateAsync(WaitUntil.Completed, certName, data, ct)).Value;

            if (hostname == null) return Ok(ctx, $"Uploaded certificate '{certName}' ({thumbprint}) to App Service {appName}");

            if (site.Data.HostNames != null && !site.Data.HostNames.Contains(hostname, StringComparer.OrdinalIgnoreCase))
                return Fail(ctx, $"Certificate uploaded, but {hostname} is not a host name of {appName}. Add the custom domain to the app first.");
            ctx.Log.Info($"Binding {hostname} to certificate {thumbprint} (SNI)");
            var binding = new HostNameBindingData { SiteName = appName, SslState = HostNameBindingSslState.SniEnabled, ThumbprintString = cert.Data.ThumbprintString ?? thumbprint };
            await site.GetSiteHostNameBindings().CreateOrUpdateAsync(WaitUntil.Completed, hostname, binding, ct);
            return Ok(ctx, $"Uploaded certificate '{certName}' to {appName} and bound it to {hostname}");
        }, ct);
    }
}

/// <summary>Import the certificate into Azure Key Vault.</summary>
public partial class AzureKeyVaultDeploymentTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.AzureKeyVault",
        Title = "Deploy to Azure Key Vault",
        DefaultTitle = "Deploy to Azure Key Vault",
        Description = "Import the certificate and private key into an Azure Key Vault as a new version of a named certificate, for use by App Gateway, Front Door, App Service and other Azure services.",
        UsageNote = "The service principal needs the 'Key Vault Certificates Officer' role (RBAC vaults) or certificate import permission (access policy vaults).",
        CredentialType = AzureCredentialTypes.AzureServicePrincipal,
        ProviderParameters =
        {
            new ProviderParameter { Key = "vaulturi", Name = "Vault URI", IsRequired = true, Description = "e.g. https://my-vault.vault.azure.net/" },
            new ProviderParameter { Key = "certname", Name = "Certificate name (optional)", Description = "Letters, digits and dashes. Default: the primary domain with dots as dashes." },
        }
    };

    [GeneratedRegex("^[0-9A-Za-z-]{1,127}$")] private static partial Regex NameRegex();

    /// <summary>Default Key Vault certificate name derived from a domain: "*.example.com" → "wildcard-example-com".</summary>
    public static string DefaultName(string domain)
    {
        var d = domain.Trim().ToLowerInvariant();
        if (d.StartsWith("*.")) d = "wildcard." + d[2..];
        var name = Regex.Replace(d, "[^0-9a-z-]", "-").Trim('-');
        return name.Length > 127 ? name[..127] : name;
    }

    private static string Name(DeploymentContext ctx) => ctx.Param("certname")?.Trim() ?? DefaultName(ctx.Item.RequestConfig.PrimaryDomain);

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        errors.AddRange(AzureCredentialTypes.Validate(ctx));
        if (ctx.Param("vaulturi") is { } v && (!Uri.TryCreate(v, UriKind.Absolute, out var uri) || uri.Scheme != "https"))
            errors.Add(Error($"Vault URI must be an https address, e.g. https://my-vault.vault.azure.net/ (got {v})"));
        var name = Name(ctx);
        if (!NameRegex().IsMatch(name)) errors.Add(Error($"Invalid Key Vault certificate name '{name}': use 1-127 letters, digits and dashes"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var vault = new Uri(ctx.Param("vaulturi")!.Trim());
        var name = Name(ctx);
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would import the certificate into Key Vault {vault.Host} as '{name}'");
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "Azure Key Vault import", async () =>
        {
            var client = new CertificateClient(vault, AzureCredentialTypes.Create(ctx));
            var options = new ImportCertificateOptions(name, await File.ReadAllBytesAsync(ctx.Files.Pfx, ct)) { Password = ctx.Files.PfxPassword, Enabled = true };
            options.Tags["ManagedBy"] = "CertMaster";
            options.Tags["PrimaryDomain"] = ctx.Item.RequestConfig.PrimaryDomain;
            ctx.Log.Info($"Importing certificate into {vault.Host} as '{name}'");
            var result = (await client.ImportCertificateAsync(options, ct)).Value;
            return Ok(ctx, $"Imported certificate into Key Vault {vault.Host} as '{name}' (version {result.Properties.Version})");
        }, ct);
    }
}

/// <summary>Store the certificate as secrets in a Doppler project config.</summary>
public partial class DopplerDeploymentTask : DeploymentTaskProviderBase
{
    public const string ApiUrl = "https://api.doppler.com/v3/configs/config/secrets";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Doppler",
        Title = "Deploy to Doppler",
        DefaultTitle = "Deploy to Doppler",
        Description = "Save the certificate, private key and optionally the full chain and a base64 PFX as secrets in a Doppler project config, so apps that read their configuration from Doppler pick up renewals.",
        UsageNote = "Use a Doppler service token or personal token with write access to the config.",
        CredentialType = StandardCredentialTypes.ApiToken,
        ProviderParameters =
        {
            new ProviderParameter { Key = "project", Name = "Project", IsRequired = true },
            new ProviderParameter { Key = "config", Name = "Config", IsRequired = true, Description = "e.g. prd" },
            new ProviderParameter { Key = "certsecret", Name = "Certificate secret name", IsRequired = true, Value = "TLS_CERT" },
            new ProviderParameter { Key = "keysecret", Name = "Private key secret name", IsRequired = true, Value = "TLS_KEY" },
            new ProviderParameter { Key = "fullchainsecret", Name = "Full chain secret name (optional)" },
            new ProviderParameter { Key = "pfxsecret", Name = "PFX (base64) secret name (optional)" },
        }
    };

    [GeneratedRegex("^[A-Z_][A-Z0-9_]*$")] private static partial Regex SecretNameRegex();

    private static readonly string[] SecretParams = { "certsecret", "keysecret", "fullchainsecret", "pfxsecret" };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (ctx.Credentials.Count > 0 && string.IsNullOrWhiteSpace(ctx.Credentials.GetValueOrDefault("api_token"))) errors.Add(Error("The stored credential has no API token"));
        var names = SecretParams.Select(ctx.Param).Where(n => n != null).ToList();
        foreach (var n in names)
            if (!SecretNameRegex().IsMatch(n!)) errors.Add(Error($"Invalid Doppler secret name '{n}': use upper-case letters, digits and underscores, not starting with a digit"));
        if (names.Distinct().Count() != names.Count) errors.Add(Error("Each secret name must be different"));
    }

    /// <summary>Builds the JSON payload sent to Doppler.</summary>
    public static string BuildPayload(string project, string config, IReadOnlyDictionary<string, string> secrets) =>
        JsonSerializer.Serialize(new { project, config, secrets });

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var project = ctx.Param("project")!;
        var config = ctx.Param("config")!;
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would update secrets {string.Join(", ", SecretParams.Select(ctx.Param).Where(n => n != null))} in Doppler {project}/{config}");
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "Doppler update", async () =>
        {
            var secrets = new Dictionary<string, string>();
            using (var material = CertificateMaterial.Load(ctx.Files, lookupRootInStore: false))
            {
                secrets[ctx.Param("certsecret")!] = material.LeafPem;
                secrets[ctx.Param("keysecret")!] = material.PrivateKeyPem ?? throw new InvalidOperationException("The private key is not available.");
                if (ctx.Param("fullchainsecret") is { } fc) secrets[fc] = material.LeafAndIntermediatesPem;
            }
            if (ctx.Param("pfxsecret") is { } px) secrets[px] = Convert.ToBase64String(await File.ReadAllBytesAsync(ctx.Files.Pfx, ct));

            using var req = new HttpRequestMessage(HttpMethod.Post, ApiUrl)
            {
                Content = new StringContent(BuildPayload(project, config, secrets), Encoding.UTF8, "application/json"),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.Credentials["api_token"].Trim());
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            ctx.Log.Info($"Updating {secrets.Count} secret(s) in Doppler {project}/{config}");
            using var resp = await ctx.Http.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return Ok(ctx, $"Updated {string.Join(", ", secrets.Keys)} in Doppler {project}/{config}");
            return Fail(ctx, $"Doppler returned {(int)resp.StatusCode}: {await ReadErrorAsync(resp, ct)}" +
                             ((int)resp.StatusCode is 401 or 403 ? " Check the API token and that it can write to this config." : ""));
        }, ct);
    }

    internal static async Task<string> ReadErrorAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        var body = await resp.Content.ReadAsStringAsync(ct);
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("messages", out var m) && m.ValueKind == JsonValueKind.Array) return string.Join("; ", m.EnumerateArray().Select(x => x.ToString()));
            if (doc.RootElement.TryGetProperty("errors", out var e) && e.ValueKind == JsonValueKind.Array) return string.Join("; ", e.EnumerateArray().Select(x => x.ToString()));
        }
        catch (JsonException) { /* not JSON */ }
        return body.Length > 300 ? body[..300] : body.Length == 0 ? resp.ReasonPhrase ?? "" : body;
    }
}

/// <summary>Write the certificate to a HashiCorp Vault secret (KV engine).</summary>
public partial class HashiCorpVaultDeploymentTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.HashicorpVault",
        Title = "Deploy to HashiCorp Vault",
        DefaultTitle = "Deploy to HashiCorp Vault",
        Description = "Write the private key, certificate, intermediates and a base64 PFX to a HashiCorp Vault KV secret using a Vault token.",
        UsageNote = "For KV version 2 the path includes /data/, e.g. /v1/secret/data/example.com. The token needs create/update capability on that path.",
        CredentialType = StandardCredentialTypes.ApiToken,
        ProviderParameters =
        {
            new ProviderParameter { Key = "vaulturi", Name = "Vault URI", IsRequired = true, Description = "e.g. https://vault.example.com:8200" },
            new ProviderParameter { Key = "namespace", Name = "Namespace (optional)", Description = "Vault Enterprise / HCP namespace, e.g. admin" },
            new ProviderParameter { Key = "secretpath", Name = "Secret path", IsRequired = true, Value = "/v1/secret/data/example", Description = "API path of the secret, e.g. /v1/secret/data/example.com" },
        }
    };

    [GeneratedRegex(@"^/?v1/[A-Za-z0-9_\-\./{}]+$")] private static partial Regex PathRegex();

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (ctx.Credentials.Count > 0 && string.IsNullOrWhiteSpace(ctx.Credentials.GetValueOrDefault("api_token"))) errors.Add(Error("The stored credential has no Vault token"));
        if (ctx.Param("vaulturi") is { } v && (!Uri.TryCreate(v, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")))
            errors.Add(Error($"Vault URI must be an absolute http(s) address (got {v})"));
        if (ctx.Param("secretpath") is { } p && (!PathRegex().IsMatch(p) || p.Contains("..")))
            errors.Add(Error($"Secret path must be an API path starting with /v1/, e.g. /v1/secret/data/example (got {p})"));
    }

    public static Uri BuildUri(string vaultUri, string secretPath) => new(vaultUri.TrimEnd('/') + "/" + secretPath.TrimStart('/'));

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var uri = BuildUri(ctx.Param("vaulturi")!.Trim(), ctx.Expand(ctx.Param("secretpath")!.Trim()));
        var ns = ctx.Param("namespace");
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would write key, cert, intermediates and pfx to {uri}" + (ns != null ? $" (namespace {ns})" : ""));
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "HashiCorp Vault update", async () =>
        {
            Dictionary<string, string> data;
            using (var material = CertificateMaterial.Load(ctx.Files, lookupRootInStore: false))
            {
                data = new Dictionary<string, string>
                {
                    ["key"] = material.PrivateKeyPem ?? throw new InvalidOperationException("The private key is not available."),
                    ["cert"] = material.LeafPem,
                    ["intermediates"] = material.IntermediatesPem,
                    ["pfx"] = Convert.ToBase64String(await File.ReadAllBytesAsync(ctx.Files.Pfx, ct)),
                };
            }
            using var req = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { data }), Encoding.UTF8, "application/json"),
            };
            req.Headers.Add("X-Vault-Token", ctx.Credentials["api_token"].Trim());
            if (ns != null) req.Headers.Add("X-Vault-Namespace", ns.Trim());
            ctx.Log.Info($"Writing certificate to Vault secret {uri.AbsolutePath}");
            using var resp = await ctx.Http.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return Ok(ctx, $"Wrote certificate to Vault secret {uri.AbsolutePath}");
            return Fail(ctx, $"Vault returned {(int)resp.StatusCode}: {await DopplerDeploymentTask.ReadErrorAsync(resp, ct)}" +
                             ((int)resp.StatusCode == 403 ? " Check the token and its policy for this path." : (int)resp.StatusCode == 404 ? " Check the secret engine mount and path." : ""));
        }, ct);
    }
}
