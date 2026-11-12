using CertMaster.Core.Storage;
using CertMaster.Models;

namespace CertMaster.Core;

// Web server (IIS) integration: site discovery, binding deployment and preview.
// CONTRACT used by the agent API, desktop UI and hub. Implementation is filled in by the IIS deployment work.
public partial class CertManager
{
    /// <summary>Whether a supported local web server (IIS) is available.</summary>
    public virtual Task<ServerStatus> GetServerStatusAsync() =>
        Task.FromResult(new ServerStatus { IsIisAvailable = false, Message = "Server integration not implemented yet." });

    /// <summary>Sites on the local web server.</summary>
    public virtual Task<List<SiteInfo>> GetSitesAsync() => Task.FromResult(new List<SiteInfo>());

    /// <summary>Hostnames from a site's bindings, offered as domains for a new certificate.</summary>
    public virtual Task<List<DomainOption>> GetDomainOptionsFromSiteAsync(string siteId) => Task.FromResult(new List<DomainOption>());

    /// <summary>Describes what a request for this item would do: authorizations, CA, deployment bindings and tasks.</summary>
    public virtual async Task<List<ActionStep>> GeneratePreviewAsync(ManagedCertificate item)
    {
        var steps = new List<ActionStep>
        {
            new("Certificate Request", $"Request a certificate for: {string.Join(", ", item.GetAllDomains())}"),
        };
        steps.AddRange(await TestConfigurationAsync(item));
        return steps;
    }

    /// <summary>
    /// Applies the issued certificate to the local web server according to RequestConfig.DeploymentSiteOption.
    /// Called after a successful request and before post-request tasks. Must not throw for "nothing to do".
    /// </summary>
    internal virtual Task<ActionResult> DeployToServerAsync(ManagedCertificate item, string pfxPath, string? pfxPassword, ItemLog log, bool isPreview, CancellationToken ct) =>
        Task.FromResult(ActionResult.Ok("Server deployment not configured."));
}
