namespace CertMaster.Models;

/// <summary>How the issued certificate is applied to local web server (IIS) bindings.</summary>
public enum DeploymentOption
{
    /// <summary>Update bindings on any site that has bindings matching the certificate domains.</summary>
    Auto,
    /// <summary>Only the site selected on the certificate (ServerSiteId).</summary>
    SingleSite,
    /// <summary>All sites, matching bindings per the binding match options.</summary>
    AllSites,
    /// <summary>Store the certificate in the machine certificate store, no binding changes.</summary>
    CertificateStoreOnly,
    /// <summary>No automatic deployment (use deployment tasks only).</summary>
    NoDeployment,
}

public enum DeploymentBindingOption
{
    /// <summary>Add or update https bindings as required.</summary>
    AddOrUpdate,
    /// <summary>Update existing https bindings only.</summary>
    UpdateOnly,
}

public enum ServerType { IIS, Apache, Nginx, Other }

/// <summary>A site hosted by a local web server.</summary>
public class SiteInfo
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public ServerType ServerType { get; set; } = ServerType.IIS;
    public string? PhysicalPath { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool HasCertificate { get; set; }
}

/// <summary>A hostname offered for selection (e.g. from a site's bindings).</summary>
public class DomainOption
{
    public string Domain { get; set; } = "";
    public bool IsPrimaryDomain { get; set; }
    public bool IsSelected { get; set; } = true;
    public bool IsManualEntry { get; set; }
    /// <summary>Note shown to the user, e.g. why this name can't be used.</summary>
    public string? Comment { get; set; }
}

/// <summary>A planned binding change produced by the deployment planner (used by Preview and by deployment).</summary>
public class BindingAction
{
    public string SiteId { get; set; } = "";
    public string SiteName { get; set; } = "";
    public bool IsNewBinding { get; set; }
    public string Protocol { get; set; } = "https";
    public string IP { get; set; } = "*";
    public int Port { get; set; } = 443;
    public string? Host { get; set; }
    public bool UseSNI { get; set; }
    public string? PreviousThumbprint { get; set; }
    public string Description { get; set; } = "";
}

public class ServerStatus
{
    public bool IsIisAvailable { get; set; }
    public string? IisVersion { get; set; }
    public string? Message { get; set; }
}
