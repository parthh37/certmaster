using CertMaster.Models;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core.Storage;

/// <summary>Per managed certificate request log (logs/item_{id}.log), also forwarded to the service logger.</summary>
public class ItemLog
{
    private readonly string _path;
    private readonly ILogger _logger;
    private readonly string _itemId;
    private static readonly object FileLock = new();

    public ItemLog(DataPaths paths, string itemId, ILogger logger)
    {
        _itemId = itemId;
        _path = Path.Combine(paths.Logs, $"item_{itemId}.log");
        _logger = logger;
    }

    public void Info(string message) => Write("INF", message);
    public void Warn(string message) => Write("WRN", message);
    public void Error(string message) => Write("ERR", message);

    private void Write(string level, string message)
    {
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [{level}] {message}";
        var lvl = level switch { "ERR" => LogLevel.Error, "WRN" => LogLevel.Warning, _ => LogLevel.Information };
        _logger.Log(lvl, "[{ItemId}] {Message}", _itemId, message);
        // The per-item log is a convenience copy: a locked file (antivirus, an open viewer) or a full disk must never fail
        // a certificate request. The service log above still has the line.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                lock (FileLock)
                {
                    using var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    var bytes = System.Text.Encoding.UTF8.GetBytes(line + Environment.NewLine);
                    fs.Write(bytes);
                }
                return;
            }
            catch (IOException) when (attempt < 2) { Thread.Sleep(50); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogDebug(ex, "Could not write request log {Path}", _path);
                return;
            }
        }
    }

    public static List<LogEntry> Read(DataPaths paths, string itemId, int maxLines = 1000)
    {
        var path = Path.Combine(paths.Logs, $"item_{itemId}.log");
        if (!File.Exists(path)) return new();
        try
        {
            var lines = new List<string>();
            lock (FileLock)
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs);
                while (reader.ReadLine() is { } l) lines.Add(l);
            }
            return lines.TakeLast(maxLines).Select(Parse).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new() { new LogEntry { Level = "WRN", Message = "The request log could not be read: " + ex.Message } };
        }
    }

    /// <summary>Halves request logs larger than <paramref name="maxBytes"/> (oldest lines go). Returns the files trimmed.</summary>
    public static List<string> TrimLargeLogs(DataPaths paths, long maxBytes)
    {
        var trimmed = new List<string>();
        foreach (var f in new DirectoryInfo(paths.Logs).GetFiles("item_*.log").Where(f => f.Length > maxBytes))
        {
            try
            {
                lock (FileLock)
                {
                    var lines = File.ReadAllLines(f.FullName);
                    var tmp = f.FullName + ".tmp";
                    File.WriteAllLines(tmp, lines.Skip(lines.Length / 2));
                    File.Move(tmp, f.FullName, overwrite: true);
                }
                trimmed.Add(f.Name);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* try again tomorrow */ }
        }
        return trimmed;
    }

    private static LogEntry Parse(string line)
    {
        // "2026-01-01 10:00:00.000 +00:00 [INF] message"
        var i = line.IndexOf(" [", StringComparison.Ordinal);
        if (i > 0 && line.Length > i + 6 && DateTimeOffset.TryParse(line[..i], out var ts))
            return new LogEntry { Timestamp = ts, Level = line.Substring(i + 2, 3), Message = line[(i + 7)..] };
        return new LogEntry { Message = line };
    }
}
