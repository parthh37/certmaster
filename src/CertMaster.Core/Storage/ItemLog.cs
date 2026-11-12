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
        lock (FileLock) File.AppendAllText(_path, line + Environment.NewLine);
        var lvl = level switch { "ERR" => LogLevel.Error, "WRN" => LogLevel.Warning, _ => LogLevel.Information };
        _logger.Log(lvl, "[{ItemId}] {Message}", _itemId, message);
    }

    public static List<LogEntry> Read(DataPaths paths, string itemId, int maxLines = 1000)
    {
        var path = Path.Combine(paths.Logs, $"item_{itemId}.log");
        if (!File.Exists(path)) return new();
        string[] lines;
        lock (FileLock) lines = File.ReadAllLines(path);
        return lines.TakeLast(maxLines).Select(Parse).ToList();
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
