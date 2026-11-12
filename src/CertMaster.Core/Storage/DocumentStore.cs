using CertMaster.Models;
using Microsoft.Data.Sqlite;

namespace CertMaster.Core.Storage;

/// <summary>
/// Minimal JSON document store on SQLite: one table per collection, (id TEXT PK, json TEXT, updated TEXT).
/// Mirrors the approach of storing whole managed items as serialized documents.
/// </summary>
public class DocumentStore
{
    private readonly string _connectionString;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly HashSet<string> _ensured = new();

    private readonly string _databasePath;

    public DocumentStore(string databasePath)
    {
        _databasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath, Cache = SqliteCacheMode.Shared, DefaultTimeout = 30, Pooling = true,
        }.ToString();
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
        cmd.ExecuteNonQuery();
        using var check = c.CreateCommand();
        check.CommandText = "PRAGMA quick_check;";
        var result = check.ExecuteScalar() as string;
        if (result != "ok") throw new InvalidOperationException($"Database integrity check failed for {databasePath}: {result}. Restore a backup from the 'backups' folder.");
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA busy_timeout=10000;";
        cmd.ExecuteNonQuery();
        return c;
    }

    /// <summary>Writes a consistent copy of the database (safe while in use) and keeps the newest <paramref name="keep"/> backups.</summary>
    public async Task<string> BackupAsync(string backupFolder, int keep = 14)
    {
        Directory.CreateDirectory(backupFolder);
        var target = Path.Combine(backupFolder, $"{Path.GetFileNameWithoutExtension(_databasePath)}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.db");
        await _lock.WaitAsync();
        try
        {
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "VACUUM INTO $path";
            cmd.Parameters.AddWithValue("$path", target);
            await cmd.ExecuteNonQueryAsync();
        }
        finally { _lock.Release(); }
        foreach (var old in new DirectoryInfo(backupFolder).GetFiles("*.db").OrderByDescending(f => f.CreationTimeUtc).Skip(keep))
            try { old.Delete(); } catch { /* ignore */ }
        return target;
    }

    private static string Table(string collection) =>
        "doc_" + new string(collection.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();

    private void Ensure(SqliteConnection c, string collection)
    {
        if (_ensured.Contains(collection)) return;
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"CREATE TABLE IF NOT EXISTS {Table(collection)} (id TEXT PRIMARY KEY, json TEXT NOT NULL, updated TEXT NOT NULL)";
        cmd.ExecuteNonQuery();
        _ensured.Add(collection);
    }

    public async Task<List<T>> GetAllAsync<T>(string collection)
    {
        await _lock.WaitAsync();
        try
        {
            using var c = Open(); Ensure(c, collection);
            using var cmd = c.CreateCommand();
            cmd.CommandText = $"SELECT json FROM {Table(collection)} ORDER BY updated";
            var list = new List<T>();
            using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync()) { var v = JsonDefaults.Deserialize<T>(r.GetString(0)); if (v != null) list.Add(v); }
            return list;
        }
        finally { _lock.Release(); }
    }

    public async Task<T?> GetAsync<T>(string collection, string id)
    {
        await _lock.WaitAsync();
        try
        {
            using var c = Open(); Ensure(c, collection);
            using var cmd = c.CreateCommand();
            cmd.CommandText = $"SELECT json FROM {Table(collection)} WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", id);
            var json = (string?)await cmd.ExecuteScalarAsync();
            return JsonDefaults.Deserialize<T>(json);
        }
        finally { _lock.Release(); }
    }

    public async Task UpsertAsync<T>(string collection, string id, T item)
    {
        await _lock.WaitAsync();
        try
        {
            using var c = Open(); Ensure(c, collection);
            using var cmd = c.CreateCommand();
            cmd.CommandText = $"INSERT INTO {Table(collection)} (id, json, updated) VALUES ($id, $json, $u) " +
                              "ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated = excluded.updated";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$json", JsonDefaults.Serialize(item));
            cmd.Parameters.AddWithValue("$u", DateTimeOffset.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
        finally { _lock.Release(); }
    }

    public async Task<bool> DeleteAsync(string collection, string id)
    {
        await _lock.WaitAsync();
        try
        {
            using var c = Open(); Ensure(c, collection);
            using var cmd = c.CreateCommand();
            cmd.CommandText = $"DELETE FROM {Table(collection)} WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", id);
            return await cmd.ExecuteNonQueryAsync() > 0;
        }
        finally { _lock.Release(); }
    }

    public async Task<T> GetSettingAsync<T>(string key) where T : new() =>
        await GetAsync<T>("settings", key) ?? new T();

    public Task SetSettingAsync<T>(string key, T value) => UpsertAsync("settings", key, value);
}
