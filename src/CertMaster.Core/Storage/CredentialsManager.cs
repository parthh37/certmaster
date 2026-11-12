using CertMaster.Models;

namespace CertMaster.Core.Storage;

/// <summary>Stores provider credentials with encrypted secrets. Secrets are never returned by list operations.</summary>
public class CredentialsManager
{
    private const string Collection = "credentials";
    private readonly DocumentStore _store;
    private readonly SecretProtector _protector;

    public CredentialsManager(DocumentStore store, SecretProtector protector)
    {
        _store = store;
        _protector = protector;
    }

    public async Task<List<StoredCredential>> GetCredentialsAsync()
    {
        var all = await _store.GetAllAsync<StoredCredential>(Collection);
        foreach (var c in all) c.Secret = null;
        return all;
    }

    public async Task<StoredCredential?> GetCredentialAsync(string storageKey)
    {
        var c = await _store.GetAsync<StoredCredential>(Collection, storageKey);
        if (c != null) c.Secret = null;
        return c;
    }

    /// <summary>Returns decrypted credential values as a dictionary.</summary>
    public async Task<Dictionary<string, string>> GetUnlockedCredentialsDictionaryAsync(string? storageKey)
    {
        if (string.IsNullOrEmpty(storageKey)) return new();
        var c = await _store.GetAsync<StoredCredential>(Collection, storageKey);
        if (c?.Secret == null) return new();
        var json = _protector.Unprotect(c.Secret);
        return JsonDefaults.Deserialize<Dictionary<string, string>>(json) ?? new();
    }

    /// <summary>Create or update. Secret must be a JSON object of key/value strings; when null on update the existing secret is kept.</summary>
    public async Task<StoredCredential> UpdateAsync(StoredCredential credential)
    {
        var existing = await _store.GetAsync<StoredCredential>(Collection, credential.StorageKey);
        var toStore = JsonDefaults.Clone(credential);
        if (!string.IsNullOrEmpty(credential.Secret))
        {
            // validate JSON shape
            _ = JsonDefaults.Deserialize<Dictionary<string, string>>(credential.Secret) ?? throw new ArgumentException("Secret must be a JSON object.");
            toStore.Secret = _protector.Protect(credential.Secret);
        }
        else
        {
            toStore.Secret = existing?.Secret;
        }
        if (existing != null) toStore.DateCreated = existing.DateCreated;
        await _store.UpsertAsync(Collection, toStore.StorageKey, toStore);
        toStore.Secret = null;
        return toStore;
    }

    public Task<bool> DeleteAsync(string storageKey) => _store.DeleteAsync(Collection, storageKey);
}
