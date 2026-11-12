using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertMaster.Core.Providers.Deployment;

namespace CertMaster.Tests.Deployment;

public class ExportFormatTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static List<string> Thumbprints(byte[] pem)
    {
        var col = new X509Certificate2Collection();
        col.ImportFromPem(Encoding.ASCII.GetString(pem));
        return col.Cast<X509Certificate2>().Select(c => c.Thumbprint).ToList();
    }

    private static bool HasKey(byte[] pem) => Encoding.ASCII.GetString(pem).Contains("PRIVATE KEY-----");

    [Fact]
    public void Orders_chain_and_detects_root_when_included()
    {
        using var chain = new TestChain(_dir.Combine("c"), includeRootInPfx: true);
        using var m = CertificateMaterial.Load(chain.Files, lookupRootInStore: false);
        Assert.Equal(chain.Leaf.Thumbprint, m.Leaf.Thumbprint);
        Assert.True(m.Leaf.HasPrivateKey);
        Assert.Equal(new[] { chain.Intermediate.Thumbprint }, m.Intermediates.Select(c => c.Thumbprint));
        Assert.Equal(chain.Root.Thumbprint, m.Root?.Thumbprint);
        Assert.NotNull(m.PrivateKeyPem);
    }

    [Fact]
    public void Pem_formats_with_root_available()
    {
        using var chain = new TestChain(_dir.Combine("c"), includeRootInPfx: true);
        using var m = CertificateMaterial.Load(chain.Files, lookupRootInStore: false);
        string leaf = chain.Leaf.Thumbprint, inter = chain.Intermediate.Thumbprint, root = chain.Root.Thumbprint;

        Assert.Equal(new[] { leaf, inter, root }, Thumbprints(m.Export(ExportFormats.PemFull)));
        Assert.True(HasKey(m.Export(ExportFormats.PemFull)));
        Assert.Equal(new[] { leaf, inter, root }, Thumbprints(m.Export(ExportFormats.PemFullNoKey)));
        Assert.False(HasKey(m.Export(ExportFormats.PemFullNoKey)));
        Assert.Equal(new[] { leaf }, Thumbprints(m.Export(ExportFormats.PemCrt)));
        Assert.Equal(new[] { leaf, inter }, Thumbprints(m.Export(ExportFormats.PemCrtPartialChain)));
        Assert.Equal(new[] { inter, root }, Thumbprints(m.Export(ExportFormats.PemChain)));
        Assert.Equal(new[] { inter }, Thumbprints(m.Export(ExportFormats.PemIntermediates)));
        Assert.Empty(Thumbprints(m.Export(ExportFormats.PemKey)));
        Assert.True(HasKey(m.Export(ExportFormats.PemKey)));
    }

    [Fact]
    public void Chain_falls_back_to_intermediates_without_root()
    {
        using var chain = new TestChain(_dir.Combine("c"), includeRootInPfx: false);
        using var m = CertificateMaterial.Load(chain.Files, lookupRootInStore: true); // test root is not in any trust store
        Assert.Null(m.Root);
        Assert.Equal(new[] { chain.Intermediate.Thumbprint }, Thumbprints(m.Export(ExportFormats.PemChain)));
        Assert.Equal(new[] { chain.Leaf.Thumbprint, chain.Intermediate.Thumbprint }, Thumbprints(m.Export(ExportFormats.PemFullNoKey)));
    }

    [Fact]
    public void Exported_key_matches_leaf()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        using var m = CertificateMaterial.Load(chain.Files);
        var keyPem = Encoding.ASCII.GetString(m.Export(ExportFormats.PemKey));
        using var rebuilt = X509Certificate2.CreateFromPem(File.ReadAllText(chain.Files.CertPem), keyPem);
        Assert.True(rebuilt.HasPrivateKey);
    }

    [Fact]
    public void Pfx_contains_key_and_chain_and_uses_given_password()
    {
        using var chain = new TestChain(_dir.Combine("c"), includeRootInPfx: true);
        using var m = CertificateMaterial.Load(chain.Files, lookupRootInStore: false);
        var pfx = m.Export(ExportFormats.PfxFull, "new-password");

        Assert.ThrowsAny<CryptographicException>(() => X509CertificateLoader.LoadPkcs12Collection(pfx, "test-pfx"));
        var col = X509CertificateLoader.LoadPkcs12Collection(pfx, "new-password", X509KeyStorageFlags.EphemeralKeySet);
        Assert.Equal(3, col.Count);
        Assert.True(col.Cast<X509Certificate2>().Single(c => c.Thumbprint == chain.Leaf.Thumbprint).HasPrivateKey);
    }

    [Fact]
    public void Loads_from_pfx_only_when_pem_files_are_missing()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        File.Delete(chain.Files.CertPem);
        File.Delete(chain.Files.KeyPem);
        using var m = CertificateMaterial.Load(chain.Files, lookupRootInStore: false);
        Assert.Equal(chain.Leaf.Thumbprint, m.Leaf.Thumbprint);
        Assert.Equal(new[] { chain.Intermediate.Thumbprint }, m.Intermediates.Select(c => c.Thumbprint));
        Assert.True(HasKey(m.Export(ExportFormats.PemKey)));
    }

    [Fact]
    public void Unknown_format_throws_argument_exception()
    {
        using var chain = new TestChain(_dir.Combine("c"));
        using var m = CertificateMaterial.Load(chain.Files, lookupRootInStore: false);
        Assert.Throws<ArgumentException>(() => m.Export("pemsomething"));
    }
}
