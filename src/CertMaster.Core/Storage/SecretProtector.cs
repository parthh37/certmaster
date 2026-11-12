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

    public SecretProtector(DataPaths paths)
    {
        var keyFile = paths.Combine("secret.key");
        if (!File.Exists(keyFile))
        {
            File.WriteAllBytes(keyFile, RandomNumberGenerator.GetBytes(32));
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        _key = File.ReadAllBytes(keyFile);
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
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(raw, _key, DataProtectionScope.LocalMachine));
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
