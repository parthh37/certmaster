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

    /// <summary>Logs the account on and returns its access token. Throws <see cref="Win32Exception"/> with a readable message on failure.</summary>
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
        return token;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string lpszUsername, string? lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);
}
