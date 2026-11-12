using CertMaster.Models;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core.Storage;

/// <summary>The database file failed SQLite's integrity check.</summary>
public class DatabaseCorruptException(string message) : InvalidOperationException(message);

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
        // Private cache (the default): shared-cache mode uses table locks that busy_timeout does not wait for (SQLITE_LOCKED).
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath, DefaultTimeout = 30, Pooling = true,
        }.ToString();
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
        cmd.ExecuteNonQuery();
        using var check = c.CreateCommand();
        check.CommandText = "PRAGMA quick_check;";
        var result = check.ExecuteScalar() as string;
        if (result != "ok") throw new DatabaseCorruptException($"Database integrity check failed for {databasePath}: {result}.");
    }

    /// <summary>
    /// Opens the database; when it is damaged, moves it aside and restores the newest backup that passes the integrity check.
    /// An unattended server then keeps renewing certificates (losing only changes since that backup) instead of failing to
    /// start. With no usable backup the damaged file is left in place and this throws, so the service never starts on an
    /// empty database by accident.
    /// </summary>
    public static DocumentStore OpenWithRecovery(string databasePath, string backupFolder, ILogger? logger = null)
    {
        try { return new DocumentStore(databasePath); }
        catch (Exception ex) when (IsCorruption(ex))
        {
            logger?.LogCritical(ex, "Database {Path} is damaged; looking for a backup in {Folder}", databasePath, backupFolder);
            var backups = Directory.Exists(backupFolder)
                ? new DirectoryInfo(backupFolder).GetFiles("*.db").Where(f => f.Length > 0).OrderByDescending(f => f.LastWriteTimeUtc).ToList()
                : new List<FileInfo>();
            if (backups.Count == 0)
                throw new InvalidOperationException($"The database {databasePath} is damaged and there is no backup in {backupFolder}. Restore a copy of the file, or move it away to start with an empty configuration.", ex);

            SqliteConnection.ClearAllPools();
            var damaged = $"{databasePath}.damaged-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
            MoveDatabase(databasePath, damaged);
            foreach (var backup in backups)
            {
                try
                {
                    File.Copy(backup.FullName, databasePath, overwrite: true);
                    var store = new DocumentStore(databasePath);
                    logger?.LogCritical("Database restored from backup {Backup} (taken {Taken:u}). Changes made after that backup are lost. The damaged database was kept as {Damaged}",
                        backup.FullName, backup.LastWriteTimeUtc, damaged);
                    store.RestoredFromBackup = backup.FullName;
                    return store;
                }
                catch (Exception rex) when (IsCorruption(rex))
                {
                    logger?.LogError(rex, "Backup {Backup} is not usable either", backup.FullName);
                    SqliteConnection.ClearAllPools();
                    DeleteDatabaseFiles(databasePath);
                }
            }
            // Nothing usable: put the damaged file back so the next start fails the same way rather than starting empty.
            DeleteDatabaseFiles(databasePath);
            MoveDatabase(damaged, databasePath);
            throw new InvalidOperationException($"The database {databasePath} is damaged and none of the {backups.Count} backups in {backupFolder} could be opened.", ex);
        }
    }

    /// <summary>Backup file the database was restored from at start-up, or null.</summary>
    public string? RestoredFromBackup { get; private set; }

    private static bool IsCorruption(Exception ex) =>
        ex is DatabaseCorruptException
        || ex is SqliteException { SqliteErrorCode: 11 or 26 }; // SQLITE_CORRUPT, SQLITE_NOTADB

    private static void MoveDatabase(string from, string to)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            if (File.Exists(from + suffix)) File.Move(from + suffix, to + suffix, overwrite: true);
    }

    private static void DeleteDatabaseFiles(string path)
    {
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            try { File.Delete(path + suffix); } catch (IOException) { /* best effort */ }
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
        // Written under a temporary name and renamed when complete, so a crash or full disk never leaves a truncated file
        // that looks like the newest backup.
        var partial = target + ".partial";
        try { File.Delete(partial); } catch (IOException) { /* replaced below */ }
        await _lock.WaitAsync();
        try
        {
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "VACUUM INTO $path";
            cmd.Parameters.AddWithValue("$path", partial);
            await cmd.ExecuteNonQueryAsync();
        }
        catch
        {
            try { File.Delete(partial); } catch (IOException) { /* best effort */ }
            throw;
        }
        finally { _lock.Release(); }
        File.Move(partial, target, overwrite: true);
        // Only prune once the new backup exists; never delete the last good copies after a failed backup.
        foreach (var old in new DirectoryInfo(backupFolder).GetFiles("*.db").OrderByDescending(f => f.LastWriteTimeUtc).Skip(Math.Max(1, keep)))
            try { old.Delete(); } catch { /* ignore */ }
        foreach (var stale in new DirectoryInfo(backupFolder).GetFiles("*.partial"))
            try { stale.Delete(); } catch { /* ignore */ }
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
