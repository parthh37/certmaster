using CertMaster.Core.Storage;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Files produced for a managed certificate after a successful request.</summary>
public class CertificateFiles
{
    public required string Folder { get; init; }
    public string Pfx => Path.Combine(Folder, "certificate.pfx");
    public string FullChainPem => Path.Combine(Folder, "fullchain.pem");
    public string CertPem => Path.Combine(Folder, "cert.pem");
    public string ChainPem => Path.Combine(Folder, "chain.pem");
    public string KeyPem => Path.Combine(Folder, "privkey.pem");
    public string? PfxPassword { get; init; }
    public bool Exists => File.Exists(Pfx);
}

public class DeploymentContext
{
    public required ManagedCertificate Item { get; init; }
    public required DeploymentTaskConfig Task { get; init; }
    public required CertificateFiles Files { get; init; }
    public required Dictionary<string, string> Parameters { get; init; }
    public required Dictionary<string, string> Credentials { get; init; }
    public required ItemLog Log { get; init; }
    public required HttpClient Http { get; init; }
    public bool IsPreviewOnly { get; init; }
    /// <summary>Outcome of the certificate request that triggered this task (null for manual runs).</summary>
    public bool? RequestSucceeded { get; init; }
    public string? RequestMessage { get; init; }

    public string? Param(string key) => Parameters.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;

    /// <summary>Replaces {placeholders} with certificate values.</summary>
    public string Expand(string text) => text
        .Replace("{ManagedItemId}", Item.Id).Replace("{Name}", Item.Name)
        .Replace("{PrimaryDomain}", Item.RequestConfig.PrimaryDomain)
        .Replace("{Thumbprint}", Item.CertificateThumbprintHash ?? "")
        .Replace("{CertificatePath}", Item.CertificatePath ?? "")
        .Replace("{DateExpiry}", Item.DateExpiry?.ToString("O") ?? "")
        .Replace("{IsSuccess}", (RequestSucceeded ?? true).ToString().ToLowerInvariant())
        .Replace("{Message}", RequestMessage ?? "");
}

public interface IDeploymentTaskProvider
{
    DeploymentProviderDefinition Definition { get; }
    Task<List<ActionStep>> ValidateAsync(DeploymentContext ctx);
    Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct);
}

public abstract class DeploymentTaskProviderBase : IDeploymentTaskProvider
{
    public abstract DeploymentProviderDefinition Definition { get; }
    public abstract Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct);

    public virtual Task<List<ActionStep>> ValidateAsync(DeploymentContext ctx)
    {
        var errors = Definition.ProviderParameters
            .Where(p => p.IsRequired && !p.IsCredential && ctx.Param(p.Key) == null)
            .Select(p => new ActionStep($"{p.Name} is required", hasError: true)).ToList();
        if (Definition.CredentialType != null && ctx.Credentials.Count == 0)
            errors.Add(new ActionStep("A stored credential is required for this task", hasError: true));
        return Task.FromResult(errors);
    }
}
