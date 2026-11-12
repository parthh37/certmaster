namespace CertMaster.Models.Hub;

/// <summary>Command sent by the management hub to a connected agent over SignalR (client results).</summary>
public class InstanceCommand
{
    public string CommandId { get; set; } = Guid.NewGuid().ToString();
    public string CommandType { get; set; } = "";
    /// <summary>JSON payload. Shape depends on CommandType.</summary>
    public string? Payload { get; set; }
}

public class InstanceCommandResult
{
    public string CommandId { get; set; } = "";
    public bool IsSuccess { get; set; }
    public string? Message { get; set; }
    /// <summary>JSON result.</summary>
    public string? Result { get; set; }
}

public static class InstanceCommands
{
    public const string GetManagedCertificates = "GetManagedCertificates";
    public const string GetManagedCertificate = "GetManagedCertificate";
    public const string UpdateManagedCertificate = "UpdateManagedCertificate";
    public const string DeleteManagedCertificate = "DeleteManagedCertificate";
    public const string PerformRequest = "PerformRequest";
    public const string TestConfiguration = "TestConfiguration";
    public const string RevokeCertificate = "RevokeCertificate";
    public const string GetItemLog = "GetItemLog";
    public const string DownloadCertificate = "DownloadCertificate";
    public const string GetChallengeProviders = "GetChallengeProviders";
    public const string GetDeploymentProviders = "GetDeploymentProviders";
    public const string GetCredentialTypes = "GetCredentialTypes";
    public const string GetCredentials = "GetCredentials";
    public const string UpdateCredential = "UpdateCredential";
    public const string DeleteCredential = "DeleteCredential";
    public const string GetAccounts = "GetAccounts";
    public const string AddAccount = "AddAccount";
    public const string RemoveAccount = "RemoveAccount";
    public const string GetCertificateAuthorities = "GetCertificateAuthorities";
    public const string PerformRenewAll = "PerformRenewAll";
    public const string GetSystemVersion = "GetSystemVersion";
    public const string GeneratePreview = "GeneratePreview";
    public const string GetServerStatus = "GetServerStatus";
    public const string GetSites = "GetSites";
    public const string GetSiteDomains = "GetSiteDomains";
    public const string PerformDeploymentTask = "PerformDeploymentTask";
    public const string GetUpdateStatus = "GetUpdateStatus";
    public const string CheckForUpdates = "CheckForUpdates";
    public const string InstallUpdate = "InstallUpdate";
    public const string GetUpdateSettings = "GetUpdateSettings";
    public const string SetUpdateSettings = "SetUpdateSettings";
}

/// <summary>Sent by an agent when it connects to the hub.</summary>
public class InstanceRegistration
{
    public string InstanceId { get; set; } = "";
    public string Title { get; set; } = "";
    public string? OS { get; set; }
    public string? ClientVersion { get; set; }
    public string? JoiningKey { get; set; }
    public string? InstanceSecret { get; set; }
}

public class InstanceRegistrationResult
{
    public bool IsAccepted { get; set; }
    public string? Message { get; set; }
    /// <summary>Issued on first join; agent stores and uses it on later connections.</summary>
    public string? InstanceSecret { get; set; }
}

public class LoginRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class AuthResponse
{
    public string AccessToken { get; set; } = "";
    public string RefreshToken { get; set; } = "";
    public DateTimeOffset AccessTokenExpiry { get; set; }
    public string Username { get; set; } = "";
    public List<string> Roles { get; set; } = new();
}

public class RefreshRequest
{
    public string RefreshToken { get; set; } = "";
}

public class HubUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Username { get; set; } = "";
    public string? Email { get; set; }
    public string? Description { get; set; }
    public List<string> Roles { get; set; } = new();
    public bool IsEnabled { get; set; } = true;
    public DateTimeOffset DateCreated { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Write-only on create/update.</summary>
    public string? Password { get; set; }
}

public static class HubRoles
{
    public const string Administrator = "Administrator";
    public const string CertificateManager = "CertificateManager";
    public const string Viewer = "Viewer";
    public static readonly string[] All = { Administrator, CertificateManager, Viewer };
}

public class ChangePasswordRequest
{
    public string CurrentPassword { get; set; } = "";
    public string NewPassword { get; set; } = "";
}

public class JoiningKey
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Title { get; set; } = "";
    /// <summary>Only returned once, on creation.</summary>
    public string? Key { get; set; }
    public DateTimeOffset DateCreated { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? DateExpiry { get; set; }
    public bool IsRevoked { get; set; }
}

public class HubSummary
{
    public int Instances { get; set; }
    public int InstancesConnected { get; set; }
    public ManagedInstanceSummary Certificates { get; set; } = new();
    public List<Models.ManagedCertificate> UpcomingRenewals { get; set; } = new();
    public List<Models.ManagedCertificate> AttentionItems { get; set; } = new();
}

public class HubInfo
{
    public string Version { get; set; } = "";
    public string? HubTitle { get; set; } = "CertMaster Management Hub";
}
