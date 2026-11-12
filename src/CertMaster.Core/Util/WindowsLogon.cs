using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace CertMaster.Core.Util;

/// <summary>Logon types accepted by LogonUser (values match the LOGON32_LOGON_* constants).</summary>
public enum WindowsLogonType
{
    Interactive = 2,
    Network = 3,
    Batch = 4,
    Service = 5,
    NetworkCleartext = 8,
    /// <summary>Local access keeps the caller's identity; outbound network access uses the supplied credentials.</summary>
    NewCredentials = 9,
}

/// <summary>A Windows account (user + optional domain + password) used for impersonation or run-as.</summary>
public sealed record WindowsCredential(string UserName, string? Domain, string Password)
{
    /// <summary>Account name in DOMAIN\user form (or just user when no domain is known).</summary>
    public string AccountName => string.IsNullOrEmpty(Domain) ? UserName : $"{Domain}\\{UserName}";

    /// <summary>
    /// Builds a credential from stored credential values (keys: username, password, domain). Accepts "DOMAIN\user" and
    /// "user@domain" in the username field. Returns null when the username or password is missing.
    /// </summary>
    public static WindowsCredential? FromDictionary(IReadOnlyDictionary<string, string>? values)
    {
        if (values == null) return null;
        var user = values.GetValueOrDefault("username")?.Trim();
        var password = values.GetValueOrDefault("password");
        var domain = values.GetValueOrDefault("domain")?.Trim();
        if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password)) return null;

        if (string.IsNullOrEmpty(domain))
        {
            var slash = user.IndexOf('\\');
            if (slash > 0) { domain = user[..slash]; user = user[(slash + 1)..]; }
        }
        // UPN form (user@domain) is passed to LogonUser as-is with a null domain.
        return new WindowsCredential(user, string.IsNullOrEmpty(domain) ? null : domain, password);
    }
}

public static class WindowsLogon
{
    private const int LOGON32_PROVIDER_DEFAULT = 0;
    private const int LOGON32_PROVIDER_WINNT50 = 3;

    /// <summary>Parses a logon type name (interactive, network, newcredentials, batch, service). Unknown/blank/auto returns the default.</summary>
    public static WindowsLogonType Parse(string? value, WindowsLogonType defaultType) =>
        (value ?? "").Trim().ToLowerInvariant() switch
        {
            "interactive" => WindowsLogonType.Interactive,
            "network" => WindowsLogonType.Network,
            "networkcleartext" => WindowsLogonType.NetworkCleartext,
            "newcredentials" => WindowsLogonType.NewCredentials,
            "batch" => WindowsLogonType.Batch,
            "service" => WindowsLogonType.Service,
            _ => defaultType,
        };

    public static bool IsKnown(string? value) =>
        string.IsNullOrWhiteSpace(value) || value.Trim().ToLowerInvariant() is "auto" or "interactive" or "network" or "networkcleartext" or "newcredentials" or "batch" or "service";

    /// <summary>
    /// Logs the account on and returns its access token (the full, elevated token for a UAC-filtered administrator when the
    /// caller is allowed to use it). Throws <see cref="Win32Exception"/> with a readable message on failure.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static SafeAccessTokenHandle Logon(WindowsCredential credential, WindowsLogonType logonType)
    {
        var provider = logonType == WindowsLogonType.NewCredentials ? LOGON32_PROVIDER_WINNT50 : LOGON32_PROVIDER_DEFAULT;
        if (!LogonUser(credential.UserName, credential.Domain, credential.Password, (int)logonType, provider, out var token))
        {
            var err = Marshal.GetLastWin32Error();
            token.Dispose();
            var hint = err switch
            {
                1326 => "unknown user name or bad password",
                1327 => "account restriction (e.g. blank password or logon hours)",
                1385 => $"the account has not been granted the '{logonType}' logon right on this computer; try a different logon type",
                1331 => "the account is disabled",
                1909 => "the account is locked out",
                1330 => "the password has expired",
                _ => new Win32Exception(err).Message,
            };
            throw new Win32Exception(err, $"Windows logon failed for {credential.AccountName} ({logonType}): {hint}");
        }
        return PreferElevatedToken(token);
    }

    private const int TokenType = 8;
    private const int TokenImpersonationLevel = 9;
    private const int TokenElevationType = 18;
    private const int TokenLinkedToken = 19;
    private const int TokenElevationTypeLimited = 3;
    private const int TokenTypePrimary = 1;
    private const int SecurityImpersonation = 2;

    /// <summary>
    /// UAC gives an Administrators-group account a filtered (limited) token for interactive/batch logons, so "run as an
    /// admin account" would run without admin rights. When the token is limited, switch to its linked (full) token.
    /// The linked token is only usable when the caller holds SeTcbPrivilege (the LocalSystem service does); otherwise
    /// Windows returns an identification-level token, which is discarded and the original token is kept.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static SafeAccessTokenHandle PreferElevatedToken(SafeAccessTokenHandle token)
    {
        try
        {
            if (!GetTokenInformation(token, TokenElevationType, out int elevation, sizeof(int), out _) || elevation != TokenElevationTypeLimited)
                return token;
            if (!GetTokenInformation(token, TokenLinkedToken, out IntPtr linkedRaw, IntPtr.Size, out _) || linkedRaw == IntPtr.Zero)
                return token;
            var linked = new SafeAccessTokenHandle(linkedRaw);
            if (!IsUsableForImpersonation(linked))
            {
                linked.Dispose();
                return token;
            }
            token.Dispose();
            return linked;
        }
        catch
        {
            return token;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsUsableForImpersonation(SafeAccessTokenHandle token)
    {
        if (!GetTokenInformation(token, TokenType, out int type, sizeof(int), out _)) return false;
        if (type == TokenTypePrimary) return true;
        return GetTokenInformation(token, TokenImpersonationLevel, out int level, sizeof(int), out _) && level >= SecurityImpersonation;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string lpszUsername, string? lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass, out int tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle tokenHandle, int tokenInformationClass, out IntPtr tokenInformation, int tokenInformationLength, out int returnLength);
}
