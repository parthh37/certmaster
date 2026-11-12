using System.Runtime.CompilerServices;
using CertMaster.Models;

[assembly: InternalsVisibleTo("CertMaster.Tests")]

namespace CertMaster.Core.Iis;

/// <summary>
/// Local web server integration used by CertManager (IIS on Windows). Abstracted so deployment and preview can be
/// tested without a real server.
/// </summary>
public interface IWebServerProvider
{
    /// <summary>Never throws; reports availability and a human readable message.</summary>
    Task<ServerStatus> GetStatusAsync();

    /// <summary>Sites on the server. Throws <see cref="WebServerAccessException"/> when the configuration can't be read.</summary>
    Task<List<SiteInfo>> GetSitesAsync();

    /// <summary>Sites with their http/https bindings, for the planner. Throws <see cref="WebServerAccessException"/>.</summary>
    Task<List<ServerSiteSnapshot>> GetSiteSnapshotsAsync();

    /// <summary>Applies planned binding changes using the certificate with this thumbprint from LocalMachine\{storeName}.</summary>
    Task<ActionResult> ApplyBindingActionsAsync(IReadOnlyList<BindingAction> actions, string thumbprint, string storeName, CancellationToken ct);

    /// <summary>Imports a PFX into LocalMachine\My (and intermediates into LocalMachine\CA). Result = leaf thumbprint.</summary>
    Task<ActionResult<string>> ImportCertificateAsync(string pfxPath, string? pfxPassword, string friendlyNamePrefix, CancellationToken ct);
}

/// <summary>The web server configuration could not be read or changed; Message is actionable for the user.</summary>
public class WebServerAccessException : InvalidOperationException
{
    public WebServerAccessException(string message, Exception? inner = null) : base(message, inner) { }
}
