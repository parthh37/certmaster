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

    public DocumentStore(string databasePath)
    {
        _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath, Cache = SqliteCacheMode.Shared }.ToString();
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL;";
        cmd.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        return c;
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
