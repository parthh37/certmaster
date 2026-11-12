namespace CertMaster.Core.Storage;

/// <summary>Resolves the application data folder (ProgramData\CertMaster on Windows).</summary>
public class DataPaths
{
    public DataPaths(string? root = null, string appFolder = "CertMaster")
    {
        Root = root
            ?? Environment.GetEnvironmentVariable("CERTMASTER_DATA")
            ?? (OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), appFolder)
                : Path.Combine("/var/lib", appFolder.ToLowerInvariant()));
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Certificates);
    }

    public string Root { get; }
    public string Logs => Path.Combine(Root, "logs");
    public string Certificates => Path.Combine(Root, "certes", "certificates");
    public string Database => Path.Combine(Root, "certmaster.db");
    public string Combine(params string[] parts) => Path.Combine(new[] { Root }.Concat(parts).ToArray());

    /// <summary>
    /// Restricts the data folder (keys, database, secrets) to SYSTEM, Administrators and the current account, removing
    /// inherited access such as the default "Users: read" on ProgramData.
    /// </summary>
    public void HardenPermissions()
    {
        if (OperatingSystem.IsWindows()) HardenWindows();
        else File.SetUnixFileMode(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void HardenWindows()
    {
        using System.Security.Principal.WindowsIdentity current = System.Security.Principal.WindowsIdentity.GetCurrent();
        var sec = new System.Security.AccessControl.DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        var inherit = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
        foreach (var sid in new[]
                 {
                     new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
                     new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
                     current.User!,
                 }.Distinct())
        {
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,
                System.Security.AccessControl.FileSystemRights.FullControl, inherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        }
        new DirectoryInfo(Root).SetAccessControl(sec);
    }
}
