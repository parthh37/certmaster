using System.Security.Cryptography;
using System.Text;

namespace CertMaster.Core.Storage;

/// <summary>
/// Encrypts secrets at rest. Windows: DPAPI (LocalMachine scope) plus a per-install entropy file.
/// Other platforms: AES-GCM with a per-install key file readable only by the service account.
/// </summary>
public class SecretProtector
{
    private readonly byte[] _key;

    private const int KeyLength = 32;

    public SecretProtector(DataPaths paths)
    {
        var keyFile = paths.Combine("secret.key");
        if (!File.Exists(keyFile)) CreateKeyFile(keyFile);
        _key = File.ReadAllBytes(keyFile);
        // Never continue with a damaged key: secrets encrypted with it could not be read back, and replacing it would make
        // every stored secret unreadable. Fail loudly so the file can be restored.
        if (_key.Length != KeyLength)
            throw new CryptographicException($"The secret key file {keyFile} is damaged ({_key.Length} bytes, expected {KeyLength}). Restore it from a backup of the data folder; stored credentials can't be decrypted without it.");
    }

    /// <summary>Writes the new key under a temporary name and renames it, so a crash never leaves a partial key behind; a concurrent creator wins cleanly.</summary>
    private static void CreateKeyFile(string keyFile)
    {
        var tmp = keyFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(RandomNumberGenerator.GetBytes(KeyLength));
                fs.Flush(flushToDisk: true);
            }
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            try { File.Move(tmp, keyFile, overwrite: false); }
            catch (IOException) when (File.Exists(keyFile)) { /* another process created it first: use that one */ }
        }
        finally
        {
            try { File.Delete(tmp); } catch (IOException) { /* best effort */ }
        }
    }

    public string Protect(string plain)
    {
        var data = Encoding.UTF8.GetBytes(plain);
        if (OperatingSystem.IsWindows())
            return "dpapi:" + Convert.ToBase64String(ProtectedData.Protect(data, _key, DataProtectionScope.LocalMachine));

        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[data.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, data, cipher, tag);
        return "aes:" + Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());
    }

    public string Unprotect(string protectedValue)
    {
        if (protectedValue.StartsWith("dpapi:") && OperatingSystem.IsWindows())
        {
            var raw = Convert.FromBase64String(protectedValue[6..]);
            try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(raw, _key, DataProtectionScope.LocalMachine)); }
            catch (CryptographicException ex)
            {
                // DPAPI LocalMachine data is tied to this Windows installation: it fails after moving the data folder to
                // another server, restoring an image to new hardware with a new machine key, or replacing secret.key.
                throw new CryptographicException("A stored credential could not be decrypted on this server. This happens when the " +
                    "CertMaster data folder was copied from another machine or secret.key was replaced. Enter the credential again " +
                    "under Settings > Credentials. (" + ex.Message.Trim() + ")", ex);
            }
        }
        if (protectedValue.StartsWith("aes:"))
        {
            var raw = Convert.FromBase64String(protectedValue[4..]);
            var nonce = raw[..12]; var tag = raw[12..28]; var cipher = raw[28..];
            var plain = new byte[cipher.Length];
            using var aes = new AesGcm(_key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }
        throw new CryptographicException("Unsupported protected value format.");
    }
}
