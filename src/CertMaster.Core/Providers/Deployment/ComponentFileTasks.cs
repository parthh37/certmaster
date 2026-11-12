using System.Text;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>
/// Base for tasks that write the certificate as separate component files (certificate, key, chain, full chain, PFX)
/// to a local folder, a Windows share or a remote host over SFTP.
/// </summary>
public abstract class ComponentFilesTaskBase : DeploymentTaskProviderBase
{
    public const string CertPath = "certpath";
    public const string KeyPath = "keypath";
    public const string FullChainPath = "fullchainpath";
    public const string ChainPath = "chainpath";
    public const string PfxPath = "pfxpath";

    private sealed record Component(string Key, string Label, bool Sensitive);

    private static readonly Component[] Components =
    {
        new(CertPath, "certificate", false),
        new(KeyPath, "private key", true),
        new(FullChainPath, "full chain", false),
        new(ChainPath, "CA chain", false),
        new(PfxPath, "PFX", true),
    };

    /// <summary>When true at least one path must be set (for tasks where every path is optional).</summary>
    protected virtual bool RequireAtLeastOne => false;

    protected static ProviderParameter PathParam(string key, string name, bool required, string example) =>
        new() { Key = key, Name = name + (required ? "" : " (optional)"), IsRequired = required, Description = "Full file path, e.g. " + example };

    protected static ProviderParameter PfxPasswordParam() => new()
    {
        Key = "pfxpasswordcredential", Name = "PFX password (stored credential key, optional)",
        Description = "Stored 'Password' credential used to protect the PFX file. Blank = the certificate's current PFX password.",
    };

    private IEnumerable<(Component c, string path)> Configured(DeploymentContext ctx) =>
        Components.Select(c => (c, path: ctx.Param(c.Key))).Where(x => x.path != null).Select(x => (x.c, ctx.Expand(x.path!)));

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        var configured = Configured(ctx).ToList();
        if (RequireAtLeastOne && configured.Count == 0) errors.Add(Error("Set at least one destination file path"));
        foreach (var (c, path) in configured)
            if (DeploymentTargets.ValidatePath(ctx, $"The {c.Label} path", path) is { } e) errors.Add(Error(e));
        var dupes = configured.GroupBy(x => x.path, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        if (dupes.Count > 0) errors.Add(Error("The same path is used for more than one file: " + string.Join(", ", dupes)));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var configured = Configured(ctx).ToList();
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would write {string.Join(", ", configured.Select(x => $"{x.c.Label} to {x.path}"))} on {DeploymentTargets.Describe(ctx)}");
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, Definition.Title, async () =>
        {
            string? password = ctx.Files.PfxPassword;
            if (configured.Any(x => x.c.Key == PfxPath))
            {
                var (pwd, err) = await CertificateExportTask.ResolvePfxPasswordAsync(ctx);
                if (err != null) return Fail(ctx, err);
                password = pwd;
            }
            using var material = CertificateMaterial.Load(ctx.Files);
            using var fs = DeploymentTargets.CreateFileSystem(ctx);
            ctx.Log.Info($"Writing {configured.Count} file(s) via {fs.Description}");
            foreach (var (c, path) in configured)
            {
                if (await fs.IsDirectoryAsync(path, ct)) return Fail(ctx, $"The {c.Label} path {path} is a folder; include a file name.");
                var content = c.Key switch
                {
                    CertPath => Encoding.ASCII.GetBytes(material.LeafPem),
                    KeyPath => Encoding.ASCII.GetBytes(material.PrivateKeyPem ?? throw new InvalidOperationException("The private key is not available.")),
                    FullChainPath => Encoding.ASCII.GetBytes(material.LeafAndIntermediatesPem),
                    ChainPath => Encoding.ASCII.GetBytes(material.IntermediatesPem),
                    _ => material.ToPfx(password),
                };
                await fs.WriteAllBytesAsync(path, content, c.Sensitive, ct);
                ctx.Log.Info($"Wrote {c.Label} to {path}");
            }
            return Ok(ctx, $"Deployed {configured.Count} file(s) ({string.Join(", ", configured.Select(x => x.c.Label))}) via {fs.Description}");
        }, ct);
    }
}

/// <summary>Apache httpd: certificate, key and optional chain / full chain files (SSLCertificateFile, SSLCertificateKeyFile, SSLCertificateChainFile).</summary>
public class ApacheDeploymentTask : ComponentFilesTaskBase
{

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Apache",
        Title = "Deploy to Apache",
        DefaultTitle = "Deploy to Apache",
        Description = "Write PEM files for Apache httpd (SSLCertificateFile, SSLCertificateKeyFile and optionally SSLCertificateChainFile or a full chain) locally, to a share, or over SSH. Reload Apache afterwards (e.g. with a Run... task).",
        SupportsRemoteTarget = true,
        SupportedTargets = new(DeploymentTargets.AllTargets),
        ProviderParameters =
        {
            PathParam(CertPath, "Certificate file", true, "/etc/ssl/example.com/cert.pem"),
            PathParam(KeyPath, "Private key file", true, "/etc/ssl/example.com/privkey.pem"),
            PathParam(FullChainPath, "Full chain file", false, "/etc/ssl/example.com/fullchain.pem"),
            PathParam(ChainPath, "CA chain file", false, "/etc/ssl/example.com/chain.pem"),
            DeploymentTargets.LogonTypeParameter(),
        }
    };
}

/// <summary>nginx: full chain + key (ssl_certificate / ssl_certificate_key), optionally the certificate and chain separately.</summary>
public class NginxDeploymentTask : ComponentFilesTaskBase
{

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Nginx",
        Title = "Deploy to nginx",
        DefaultTitle = "Deploy to nginx",
        Description = "Write PEM files for nginx: the full chain for ssl_certificate and the key for ssl_certificate_key (plus optional certificate-only and chain files). Reload nginx afterwards (e.g. 'nginx -s reload' with a Run... task).",
        SupportsRemoteTarget = true,
        SupportedTargets = new(DeploymentTargets.AllTargets),
        ProviderParameters =
        {
            PathParam(FullChainPath, "Full chain file (ssl_certificate)", true, "/etc/nginx/ssl/example.com.fullchain.pem"),
            PathParam(KeyPath, "Private key file (ssl_certificate_key)", true, "/etc/nginx/ssl/example.com.key"),
            PathParam(CertPath, "Certificate file", false, "/etc/nginx/ssl/example.com.crt"),
            PathParam(ChainPath, "CA chain file (ssl_trusted_certificate)", false, "/etc/nginx/ssl/example.com.chain.pem"),
            DeploymentTargets.LogonTypeParameter(),
        }
    };
}

/// <summary>Any server: write whichever component files are configured (PEM certificate, key, full chain, chain, PFX).</summary>
public class GenericServerDeploymentTask : ComponentFilesTaskBase
{
    protected override bool RequireAtLeastOne => true;

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.GenericServer",
        Title = "Deploy to Generic Server (multi-purpose)",
        DefaultTitle = "Deploy Certificate Files",
        Description = "Write any combination of certificate files (PEM certificate, private key, full chain, CA chain, PFX) to paths on this machine, a network share, or a remote host over SSH. Set only the paths you need.",
        SupportsRemoteTarget = true,
        SupportedTargets = new(DeploymentTargets.AllTargets),
        ProviderParameters =
        {
            PathParam(CertPath, "PEM certificate file", false, "/opt/app/tls/cert.pem"),
            PathParam(KeyPath, "PEM private key file", false, "/opt/app/tls/key.pem"),
            PathParam(FullChainPath, "PEM full chain file", false, "/opt/app/tls/fullchain.pem"),
            PathParam(ChainPath, "PEM CA chain file", false, "/opt/app/tls/chain.pem"),
            PathParam(PfxPath, "PFX file", false, "C:\\app\\tls\\certificate.pfx"),
            PfxPasswordParam(),
            DeploymentTargets.LogonTypeParameter(),
        }
    };
}

/// <summary>Apache Tomcat: copy the PFX (PKCS#12 keystore) to the path referenced by the connector's certificateKeystoreFile.</summary>
public class TomcatDeploymentTask : ComponentFilesTaskBase
{

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Tomcat",
        Title = "Deploy to Tomcat",
        DefaultTitle = "Deploy to Tomcat",
        Description = "Copy the certificate as a PKCS#12 (PFX) keystore for Tomcat's certificateKeystoreFile (certificateKeystoreType=\"PKCS12\"), locally or to a remote server. Restart Tomcat afterwards.",
        UsageNote = "The connector's certificateKeystorePassword must match the PFX password.",
        SupportsRemoteTarget = true,
        SupportedTargets = new(DeploymentTargets.AllTargets),
        ProviderParameters =
        {
            PathParam(PfxPath, "Keystore (PFX) file", true, "C:\\tomcat\\conf\\keystore.pfx or /opt/tomcat/conf/keystore.p12"),
            PfxPasswordParam(),
            DeploymentTargets.LogonTypeParameter(),
        }
    };
}

/// <summary>IIS Centralized Certificate Store: one PFX per host name (&lt;host&gt;.pfx, wildcard as _.domain.pfx).</summary>
public class CentralizedCertificateStoreTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.CCS",
        Title = "Deploy to Centralized Certificate Store (CCS)",
        DefaultTitle = "Deploy to Centralized Certificate Store",
        Description = "Copy the PFX into an IIS Centralized Certificate Store folder once per domain on the certificate, named <domain>.pfx (wildcards as _.domain.pfx). The folder can be local or a UNC share accessed with Windows credentials.",
        UsageNote = "The PFX password must match the private key password configured for the CCS in IIS.",
        SupportsRemoteTarget = true,
        SupportedTargets = new(DeploymentTargets.WindowsTargets),
        ProviderParameters =
        {
            new ProviderParameter { Key = "path", Name = "CCS folder", IsRequired = true, Description = "e.g. C:\\CCS or \\\\fileserver\\ccs" },
            new ProviderParameter { Key = "pfxpasswordcredential", Name = "PFX password (stored credential key, optional)", Description = "Stored 'Password' credential matching the CCS private key password. Blank = the certificate's current PFX password." },
            DeploymentTargets.LogonTypeParameter(),
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (DeploymentTargets.ValidatePath(ctx, "CCS folder", ctx.Param("path"), mustBeFile: false) is { } e) errors.Add(Error(e));
        try
        {
            if (CentralizedCertificateStore.GetFileNames(ctx.Item.GetAllDomains()).Count == 0) errors.Add(Error("The certificate has no domains to name CCS files after"));
        }
        catch (ArgumentException ex) { errors.Add(Error(ex.Message)); }
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var folder = ctx.Expand(ctx.Param("path")!);
        var names = CentralizedCertificateStore.GetFileNames(ctx.Item.GetAllDomains());
        var targets = names.Select(n => Path.Combine(folder, n)).ToList();
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would write {string.Join(", ", targets)} on {DeploymentTargets.Describe(ctx)}");
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "CCS deployment", async () =>
        {
            var (password, err) = await CertificateExportTask.ResolvePfxPasswordAsync(ctx);
            if (err != null) return Fail(ctx, err);
            byte[] pfx;
            using (var material = CertificateMaterial.Load(ctx.Files)) pfx = material.ToPfx(password);
            using var fs = DeploymentTargets.CreateFileSystem(ctx);
            foreach (var path in targets)
            {
                await fs.WriteAllBytesAsync(path, pfx, sensitive: true, ct);
                ctx.Log.Info($"Wrote {path}");
            }
            return Ok(ctx, $"Deployed {targets.Count} PFX file(s) to the CCS folder {folder} via {fs.Description}");
        }, ct);
    }
}
