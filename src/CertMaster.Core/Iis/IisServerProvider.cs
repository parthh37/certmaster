using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using CertMaster.Models;
using Microsoft.Web.Administration;
using Microsoft.Win32;

namespace CertMaster.Core.Iis;

/// <summary>IIS integration through Microsoft.Web.Administration (Windows only; needs administrative rights).</summary>
public sealed class IisServerProvider : IWebServerProvider
{
    public const string CertificateStoreName = "My";
    internal const string AdminHint =
        "Run the CertMaster agent as Administrator (or as the LocalSystem service account) so it can read and change the IIS configuration and the machine certificate store.";

    private const int E_ACCESSDENIED = unchecked((int)0x80070005);
    private const int REGDB_E_CLASSNOTREG = unchecked((int)0x80040154);
    private const int ERROR_FILE_NOT_FOUND = unchecked((int)0x80070002);
    private const int ERROR_PATH_NOT_FOUND = unchecked((int)0x80070003);

    // ---------- Status ----------

    public Task<ServerStatus> GetStatusAsync() => Task.Run(GetStatus);

    private static ServerStatus GetStatus()
    {
        if (!OperatingSystem.IsWindows()) return new ServerStatus { IsIisAvailable = false, Message = "IIS is only available on Windows." };
        try
        {
            var version = GetIisVersion();
            if (!IsW3SvcInstalled())
                return new ServerStatus { IsIisAvailable = false, IisVersion = version, Message = "IIS is not installed (the World Wide Web Publishing Service, W3SVC, was not found)." };

            var status = new ServerStatus { IsIisAvailable = true, IisVersion = version, Message = $"IIS {version ?? ""} is installed.".Replace("  ", " ") };
            try { _ = WithServerManager(sm => sm.Sites.Count); }
            catch (WebServerAccessException ex) { status.Message += " " + ex.Message; }
            return status;
        }
        catch (Exception ex)
        {
            return new ServerStatus { IsIisAvailable = false, Message = "Could not determine IIS status: " + ex.Message };
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsW3SvcInstalled()
    {
        try
        {
            using var sc = new ServiceController("W3SVC");
            _ = sc.Status; // throws InvalidOperationException when the service does not exist
            return true;
        }
        catch (InvalidOperationException) { return false; }
    }

    [SupportedOSPlatform("windows")]
    private static string? GetIisVersion()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\InetStp");
        if (key?.GetValue("MajorVersion") is not int major) return null;
        var minor = key.GetValue("MinorVersion") is int m ? m : 0;
        return $"{major}.{minor}";
    }

    // ---------- Sites ----------

    public Task<List<SiteInfo>> GetSitesAsync() => Task.Run(() =>
    {
        EnsureWindows();
        return WithServerManager(sm => sm.Sites.Select(site => new SiteInfo
        {
            Id = site.Id.ToString(CultureInfo.InvariantCulture),
            Name = site.Name,
            ServerType = ServerType.IIS,
            PhysicalPath = GetRootPhysicalPath(site),
            IsEnabled = IsStarted(site),
            HasCertificate = site.Bindings.Any(b => string.Equals(b.Protocol, "https", StringComparison.OrdinalIgnoreCase)),
        }).OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList());
    });

    public Task<List<ServerSiteSnapshot>> GetSiteSnapshotsAsync() => Task.Run(() =>
    {
        EnsureWindows();
        return WithServerManager(sm => sm.Sites.Select(site => new ServerSiteSnapshot
        {
            Id = site.Id.ToString(CultureInfo.InvariantCulture),
            Name = site.Name,
            PhysicalPath = GetRootPhysicalPath(site),
            IsStarted = IsStarted(site),
            Bindings = site.Bindings.Select(ToSnapshot).OfType<ServerBindingSnapshot>().ToList(),
        }).OrderBy(s => long.TryParse(s.Id, out var id) ? id : long.MaxValue).ToList());
    });

    private static ServerBindingSnapshot? ToSnapshot(Binding b)
    {
        var protocol = b.Protocol ?? "";
        if (!protocol.Equals("http", StringComparison.OrdinalIgnoreCase) && !protocol.Equals("https", StringComparison.OrdinalIgnoreCase)) return null;
        if (!BindingEndpoint.TryParse(b.BindingInformation, out var ip, out var port, out var host)) return null;
        var snapshot = new ServerBindingSnapshot { Protocol = protocol.ToLowerInvariant(), IP = ip, Port = port, Host = host };
        if (snapshot.IsHttps)
        {
            var hash = b.CertificateHash;
            snapshot.CertificateHash = hash is { Length: > 0 } ? Convert.ToHexString(hash) : null;
            snapshot.CertificateStoreName = b.CertificateStoreName;
            try { snapshot.SslFlags = (BindingSslFlags)(int)b.SslFlags; }
            catch (Exception) { snapshot.SslFlags = BindingSslFlags.None; } // attribute missing on very old schemas
        }
        return snapshot;
    }

    private static string? GetRootPhysicalPath(Site site)
    {
        try
        {
            var app = site.Applications["/"];
            var path = app?.VirtualDirectories["/"]?.PhysicalPath;
            return string.IsNullOrWhiteSpace(path) ? null : Environment.ExpandEnvironmentVariables(path);
        }
        catch (Exception) { return null; }
    }

    private static bool IsStarted(Site site)
    {
        // Reading State needs the WAS/W3SVC services running; fall back to the auto-start setting.
        try { return site.State is ObjectState.Started or ObjectState.Starting; }
        catch (Exception) { try { return site.ServerAutoStart; } catch (Exception) { return true; } }
    }

    // ---------- Apply bindings ----------

    public Task<ActionResult> ApplyBindingActionsAsync(IReadOnlyList<BindingAction> actions, string thumbprint, string storeName, CancellationToken ct) => Task.Run(() =>
    {
        EnsureWindows();
        if (actions.Count == 0) return ActionResult.Ok("No binding changes.");
        var hex = BindingPlanner.NormalizeThumbprint(thumbprint) ?? throw new ArgumentException("A certificate thumbprint is required.", nameof(thumbprint));
        var hash = Convert.FromHexString(hex);
        return WithServerManager(sm =>
        {
            var done = new List<string>();
            foreach (var action in actions)
            {
                ct.ThrowIfCancellationRequested();
                var site = sm.Sites.FirstOrDefault(s => s.Id.ToString(CultureInfo.InvariantCulture) == action.SiteId);
                if (site == null) return ActionResult.Fail($"Site '{action.SiteName}' (id {action.SiteId}) no longer exists; no changes were saved.");
                var info = BindingEndpoint.Format(action.IP, action.Port, action.Host);
                if (action.IsNewBinding)
                {
                    site.Bindings.Add(info, hash, storeName, action.UseSNI ? SslFlags.Sni : SslFlags.None);
                    done.Add($"added {info} to '{site.Name}'");
                }
                else
                {
                    var binding = site.Bindings.FirstOrDefault(b => string.Equals(b.Protocol, "https", StringComparison.OrdinalIgnoreCase)
                                                                    && BindingEndpoint.SameEndpoint(b.BindingInformation, action.IP, action.Port, action.Host));
                    if (binding == null) return ActionResult.Fail($"Binding {info} on site '{site.Name}' no longer exists; no changes were saved.");
                    binding.CertificateHash = hash;
                    binding.CertificateStoreName = storeName;
                    done.Add($"updated {info} on '{site.Name}'");
                }
            }
            sm.CommitChanges();
            return ActionResult.Ok("IIS bindings saved: " + string.Join("; ", done));
        });
    }, ct);

    // ---------- Certificate store ----------

    public Task<ActionResult<string>> ImportCertificateAsync(string pfxPath, string? pfxPassword, string friendlyNamePrefix, CancellationToken ct) => Task.Run(() =>
    {
        if (!OperatingSystem.IsWindows())
            return new ActionResult<string> { Message = "The Windows certificate store is only available on Windows." };
        try { return ImportWindows(pfxPath, pfxPassword, friendlyNamePrefix); }
        catch (Exception ex) when (ex is CryptographicException or UnauthorizedAccessException)
        {
            return new ActionResult<string> { Message = $"Could not import the certificate into LocalMachine\\{CertificateStoreName}: {ex.Message.TrimEnd('.')}. {AdminHint}" };
        }
    }, ct);

    [SupportedOSPlatform("windows")]
    private static ActionResult<string> ImportWindows(string pfxPath, string? pfxPassword, string friendlyNamePrefix)
    {
        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxPath, pfxPassword,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        try
        {
            var leaf = collection.FirstOrDefault(c => c.HasPrivateKey);
            if (leaf == null) return new ActionResult<string> { Message = "The PFX file does not contain a certificate with a private key." };
            leaf.FriendlyName = $"{friendlyNamePrefix} [CertMaster] {leaf.NotBefore:yyyyMMdd}";
            using (var my = new X509Store(CertificateStoreName, StoreLocation.LocalMachine))
            {
                my.Open(OpenFlags.ReadWrite);
                my.Add(leaf);
            }

            var note = "";
            try
            {
                using var ca = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                ca.Open(OpenFlags.ReadWrite);
                foreach (var issuer in collection.Where(c => !ReferenceEquals(c, leaf) && c.Subject != c.Issuer))
                    if (ca.Certificates.Find(X509FindType.FindByThumbprint, issuer.Thumbprint, false).Count == 0) ca.Add(issuer);
            }
            catch (CryptographicException ex) { note = $" (intermediate certificates not stored: {ex.Message})"; }

            return new ActionResult<string> { IsSuccess = true, Result = leaf.Thumbprint, Message = $"Imported {leaf.Thumbprint} into LocalMachine\\{CertificateStoreName}{note}" };
        }
        finally
        {
            foreach (var c in collection) c.Dispose();
        }
    }

    // ---------- Helpers ----------

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new WebServerAccessException("IIS is only available on Windows.");
    }

    private static T WithServerManager<T>(Func<ServerManager, T> action)
    {
        try
        {
            using var sm = new ServerManager();
            return action(sm);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new WebServerAccessException($"Access to the IIS configuration was denied. {AdminHint}", ex);
        }
        catch (COMException ex) when (ex.HResult == E_ACCESSDENIED)
        {
            throw new WebServerAccessException($"Access to the IIS configuration was denied. {AdminHint}", ex);
        }
        catch (COMException ex) when (ex.HResult is REGDB_E_CLASSNOTREG or ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND)
        {
            throw new WebServerAccessException("The IIS management components are not installed (enable 'IIS Management Scripts and Tools' or the IIS role).", ex);
        }
        catch (COMException ex)
        {
            throw new WebServerAccessException($"IIS configuration error (0x{ex.HResult:X8}): {ex.Message}. {AdminHint}", ex);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DllNotFoundException or TypeInitializationException)
        {
            throw new WebServerAccessException("The IIS configuration system is not available on this machine: " + ex.Message, ex);
        }
    }
}
