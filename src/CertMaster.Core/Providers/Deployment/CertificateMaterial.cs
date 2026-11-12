using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Export format identifiers used by the Export Certificate task (and reused by other tasks).</summary>
public static class ExportFormats
{
    /// <summary>PFX/PKCS#12 with the private key, leaf, intermediates and root (when available).</summary>
    public const string PfxFull = "pfxfull";
    /// <summary>PEM: leaf + intermediates + root (when available) + private key.</summary>
    public const string PemFull = "pemfull";
    /// <summary>PEM: leaf + intermediates + root (when available), no key.</summary>
    public const string PemFullNoKey = "pemfullnokey";
    /// <summary>PEM: leaf certificate only.</summary>
    public const string PemCrt = "pemcrt";
    /// <summary>PEM: leaf + intermediates (no root, no key).</summary>
    public const string PemCrtPartialChain = "pemcrtpartialchain";
    /// <summary>PEM: intermediates + root when available, otherwise intermediates only.</summary>
    public const string PemChain = "pemchain";
    /// <summary>PEM: intermediates only.</summary>
    public const string PemIntermediates = "pemintermediates";
    /// <summary>PEM: private key only.</summary>
    public const string PemKey = "pemkey";

    public static readonly string[] All = { PfxFull, PemFull, PemFullNoKey, PemCrt, PemCrtPartialChain, PemChain, PemIntermediates, PemKey };

    public const string OptionsList =
        PfxFull + "=PFX (certificate, chain and private key);" +
        PemFull + "=PEM - Full chain + private key;" +
        PemFullNoKey + "=PEM - Full chain (no key);" +
        PemCrt + "=PEM - Certificate only;" +
        PemCrtPartialChain + "=PEM - Certificate + intermediates;" +
        PemChain + "=PEM - Chain (intermediates + root if available);" +
        PemIntermediates + "=PEM - Intermediates only;" +
        PemKey + "=PEM - Private key only";

    public static bool IsKnown(string? format) => format != null && All.Contains(format);
    public static bool IncludesPrivateKey(string format) => format is PfxFull or PemFull or PemKey;
}

/// <summary>
/// The issued certificate split into its parts (leaf with key, ordered intermediates, root when available), with helpers
/// that compose PEM/PFX outputs in the various formats deployment tasks need.
/// </summary>
public sealed class CertificateMaterial : IDisposable
{
    public X509Certificate2 Leaf { get; }
    /// <summary>Issuing certificates ordered from the one that signed the leaf upwards (root excluded).</summary>
    public IReadOnlyList<X509Certificate2> Intermediates { get; }
    /// <summary>Self-signed root, when included in the files or found in the local trust store.</summary>
    public X509Certificate2? Root { get; }
    public string? PrivateKeyPem { get; }

    private CertificateMaterial(X509Certificate2 leaf, List<X509Certificate2> intermediates, X509Certificate2? root, string? keyPem)
    {
        Leaf = leaf; Intermediates = intermediates; Root = root; PrivateKeyPem = keyPem;
    }

    /// <summary>Loads from the stored certificate files (PEM files preferred, PFX as fallback).</summary>
    public static CertificateMaterial Load(CertificateFiles files, bool lookupRootInStore = true)
    {
        // Every certificate object loaded here that does not end up in the result is disposed (PFX entries duplicating the PEM
        // chain, the PFX copy of the leaf, duplicates dropped by Create).
        var loaded = new List<X509Certificate2>();
        try
        {
            CertificateMaterial material;
            if (File.Exists(files.CertPem) && File.Exists(files.KeyPem))
            {
                var certPem = File.ReadAllText(files.CertPem);
                var keyPem = File.ReadAllText(files.KeyPem);
                var leaf = X509Certificate2.CreateFromPem(certPem, keyPem);
                loaded.Add(leaf);
                var others = new X509Certificate2Collection();
                if (File.Exists(files.ChainPem)) others.ImportFromPem(File.ReadAllText(files.ChainPem));
                loaded.AddRange(others);
                // the PFX may also carry a root that the PEM chain lacks
                if (File.Exists(files.Pfx))
                {
                    try
                    {
                        foreach (var c in X509CertificateLoader.LoadPkcs12CollectionFromFile(files.Pfx, files.PfxPassword, X509KeyStorageFlags.EphemeralKeySet))
                        {
                            loaded.Add(c);
                            if (!c.HasPrivateKey && others.Cast<X509Certificate2>().All(o => o.Thumbprint != c.Thumbprint)) others.Add(c);
                        }
                    }
                    catch (CryptographicException) { /* PEM files are enough */ }
                }
                material = Create(leaf, others.Cast<X509Certificate2>(), keyPem.Trim() + "\n", lookupRootInStore);
            }
            else
            {
                if (!File.Exists(files.Pfx)) throw new FileNotFoundException("Certificate files not found", files.Pfx);
                var flags = X509KeyStorageFlags.Exportable | (OperatingSystem.IsWindows() ? X509KeyStorageFlags.EphemeralKeySet : 0);
                var all = X509CertificateLoader.LoadPkcs12CollectionFromFile(files.Pfx, files.PfxPassword, flags).Cast<X509Certificate2>().ToList();
                loaded.AddRange(all);
                var leafCert = all.FirstOrDefault(c => c.HasPrivateKey) ?? throw new CryptographicException("The PFX does not contain a private key.");
                material = Create(leafCert, all.Where(c => !ReferenceEquals(c, leafCert)), null, lookupRootInStore);
            }
            foreach (var c in loaded.Where(c => !material.Holds(c))) c.Dispose();
            return material;
        }
        catch
        {
            foreach (var c in loaded) c.Dispose();
            throw;
        }
    }

    private bool Holds(X509Certificate2 c) => ReferenceEquals(c, Leaf) || ReferenceEquals(c, Root) || Intermediates.Any(i => ReferenceEquals(i, c));

    /// <summary>Builds from a leaf (with private key) and any other certificates of its chain, in any order.</summary>
    public static CertificateMaterial Create(X509Certificate2 leafWithKey, IEnumerable<X509Certificate2> chainCertificates, string? privateKeyPem = null, bool lookupRootInStore = true)
    {
        var pool = chainCertificates.Where(c => c.Thumbprint != leafWithKey.Thumbprint).GroupBy(c => c.Thumbprint).Select(g => g.First()).ToList();
        var ordered = new List<X509Certificate2>();
        X509Certificate2? root = null;
        var current = leafWithKey;
        while (!IsSelfSigned(current))
        {
            var issuer = pool.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData));
            if (issuer == null) break;
            pool.Remove(issuer);
            if (IsSelfSigned(issuer)) { root = issuer; break; }
            ordered.Add(issuer);
            current = issuer;
        }
        // keep anything unmatched (cross-signs etc.) after the ordered chain
        foreach (var extra in pool)
        {
            if (IsSelfSigned(extra)) root ??= extra;
            else ordered.Add(extra);
        }
        if (root == null && lookupRootInStore) root = FindRootInStore(leafWithKey, ordered);

        privateKeyPem ??= ExportKeyPem(leafWithKey);
        return new CertificateMaterial(leafWithKey, ordered, root, privateKeyPem);
    }

    private static bool IsSelfSigned(X509Certificate2 c) => c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData);

    private static X509Certificate2? FindRootInStore(X509Certificate2 leaf, List<X509Certificate2> intermediates)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            chain.ChainPolicy.ExtraStore.AddRange(intermediates.ToArray());
            chain.Build(leaf);
            var last = chain.ChainElements.Count > 1 ? chain.ChainElements[^1].Certificate : null;
            if (last != null && IsSelfSigned(last) && intermediates.All(i => i.Thumbprint != last.Thumbprint) && last.Thumbprint != leaf.Thumbprint)
                return X509CertificateLoader.LoadCertificate(last.RawData);
        }
        catch (CryptographicException) { /* no root available */ }
        return null;
    }

    private static string? ExportKeyPem(X509Certificate2 cert)
    {
        try
        {
            using AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)cert.GetRSAPrivateKey() ?? cert.GetECDsaPrivateKey();
            return key == null ? null : key.ExportPkcs8PrivateKeyPem() + "\n";
        }
        catch (CryptographicException) { return null; }
    }

    public static string ToPem(IEnumerable<X509Certificate2> certs)
    {
        var sb = new StringBuilder();
        foreach (var c in certs) sb.Append(PemEncoding.Write("CERTIFICATE", c.RawData)).Append('\n');
        return sb.ToString();
    }

    public string LeafPem => ToPem(new[] { Leaf });
    public string IntermediatesPem => ToPem(Intermediates);
    /// <summary>Intermediates + root when available, otherwise intermediates only.</summary>
    public string ChainPem => ToPem(Intermediates.Concat(Root is null ? Array.Empty<X509Certificate2>() : new[] { Root }));
    /// <summary>Leaf + intermediates (what most web servers call "fullchain").</summary>
    public string LeafAndIntermediatesPem => ToPem(new[] { Leaf }.Concat(Intermediates));
    /// <summary>Leaf + intermediates + root when available.</summary>
    public string FullChainPem => ToPem(new[] { Leaf }.Concat(Intermediates).Concat(Root is null ? Array.Empty<X509Certificate2>() : new[] { Root }));

    private string RequireKeyPem() => PrivateKeyPem ?? throw new CryptographicException("The private key is not available for export.");

    /// <summary>Builds a PFX containing the key, leaf, intermediates and (optionally) the root.</summary>
    public byte[] ToPfx(string? password, bool includeRoot = true)
    {
        var collection = new X509Certificate2Collection(Leaf);
        foreach (var i in Intermediates) collection.Add(i);
        if (includeRoot && Root != null) collection.Add(Root);
        return collection.Export(X509ContentType.Pkcs12, password) ?? throw new CryptographicException("PFX export returned no data.");
    }

    /// <summary>Composes the file content for one of the <see cref="ExportFormats"/>.</summary>
    public byte[] Export(string format, string? pfxPassword = null) => format switch
    {
        ExportFormats.PfxFull => ToPfx(pfxPassword),
        ExportFormats.PemFull => Encoding.ASCII.GetBytes(FullChainPem + RequireKeyPem()),
        ExportFormats.PemFullNoKey => Encoding.ASCII.GetBytes(FullChainPem),
        ExportFormats.PemCrt => Encoding.ASCII.GetBytes(LeafPem),
        ExportFormats.PemCrtPartialChain => Encoding.ASCII.GetBytes(LeafAndIntermediatesPem),
        ExportFormats.PemChain => Encoding.ASCII.GetBytes(ChainPem),
        ExportFormats.PemIntermediates => Encoding.ASCII.GetBytes(IntermediatesPem),
        ExportFormats.PemKey => Encoding.ASCII.GetBytes(RequireKeyPem()),
        _ => throw new ArgumentException($"Unknown export format '{format}'. Valid formats: {string.Join(", ", ExportFormats.All)}"),
    };

    public void Dispose()
    {
        Leaf.Dispose();
        foreach (var i in Intermediates) i.Dispose();
        Root?.Dispose();
    }
}

/// <summary>Helpers for the IIS Centralized Certificate Store naming convention.</summary>
public static class CentralizedCertificateStore
{
    /// <summary>File name IIS CCS expects for a host name: "&lt;host&gt;.pfx", with a wildcard "*." prefix written as "_.".</summary>
    public static string GetFileName(string domain)
    {
        var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.Length == 0) throw new ArgumentException("Domain is empty", nameof(domain));
        if (d.StartsWith("*.")) d = "_." + d[2..];
        if (d.Contains('*') || d.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) throw new ArgumentException($"'{domain}' cannot be used as a CCS file name");
        return d + ".pfx";
    }

    /// <summary>Distinct CCS file names for all domains of the certificate.</summary>
    public static List<string> GetFileNames(IEnumerable<string> domains) =>
        domains.Where(d => !string.IsNullOrWhiteSpace(d)).Select(GetFileName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
