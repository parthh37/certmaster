using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CertMaster.Core.Util;

/// <summary>Small helpers for granting an account access to a file.</summary>
[SupportedOSPlatform("windows")]
public static class FileAcl
{
    /// <summary>Resolves an account name (e.g. "NT AUTHORITY\LOCAL SERVICE", "DOMAIN\user", "IIS AppPool\Site") to its SID. Throws with a readable message when unknown.</summary>
    public static SecurityIdentifier ResolveAccount(string account)
    {
        try { return (SecurityIdentifier)new NTAccount(account.Trim()).Translate(typeof(SecurityIdentifier)); }
        catch (IdentityNotMappedException) { throw new InvalidOperationException($"Account '{account}' was not found. Use DOMAIN\\user, NT AUTHORITY\\LOCAL SERVICE, IIS AppPool\\<pool> etc."); }
    }

    /// <summary>Adds an allow rule for the account. Returns false when an equivalent rule already existed.</summary>
    public static bool Grant(string path, SecurityIdentifier sid, FileSystemRights rights)
    {
        var info = new FileInfo(path);
        var acl = info.GetAccessControl();
        var existing = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Any(r => r.IdentityReference.Equals(sid) && r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & rights) == rights);
        if (existing) return false;
        acl.AddAccessRule(new FileSystemAccessRule(sid, rights, AccessControlType.Allow));
        info.SetAccessControl(acl);
        return true;
    }

    public static bool Grant(string path, string account, FileSystemRights rights) => Grant(path, ResolveAccount(account), rights);
}
