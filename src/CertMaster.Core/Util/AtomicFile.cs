using System.Text;

namespace CertMaster.Core.Util;

/// <summary>
/// Crash-safe small settings files. A write goes to a temporary file that is flushed to disk and then swapped in, keeping
/// the previous version as <c>.bak</c>; a reader falls back to that backup when the file is missing, empty or unreadable.
/// A crash or full disk mid-write therefore never leaves an empty or truncated file in place of good settings.
/// </summary>
public static class AtomicFile
{
    public static string BackupPath(string path) => path + ".bak";
    private static string TempPath(string path) => path + ".tmp";

    public static void WriteAllText(string path, string content)
    {
        var tmp = TempPath(path);
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            var bytes = new UTF8Encoding(false).GetBytes(content);
            fs.Write(bytes);
            fs.Flush(flushToDisk: true);
        }
        if (File.Exists(path))
        {
            // Only keep a backup of a file that is worth keeping; an empty one would replace a good .bak.
            if (new FileInfo(path).Length > 0) File.Replace(tmp, path, BackupPath(path), ignoreMetadataErrors: true);
            else File.Move(tmp, path, overwrite: true);
        }
        else File.Move(tmp, path);
    }

    /// <summary>True when the file or its backup exists, i.e. there is something a failed read must not overwrite.</summary>
    public static bool Exists(string path) => File.Exists(path) || File.Exists(BackupPath(path));

    /// <summary>
    /// Reads and parses the file, falling back to the backup. <paramref name="parse"/> returns null (or throws) for content it
    /// can't use. Returns null when neither copy parses. <paramref name="fromBackup"/> is true when only the backup was usable.
    /// </summary>
    public static T? Read<T>(string path, Func<string, T?> parse, out bool fromBackup) where T : class
    {
        fromBackup = false;
        if (TryParse(path, parse) is { } value) return value;
        if (TryParse(BackupPath(path), parse) is { } backup) { fromBackup = true; return backup; }
        return null;
    }

    private static T? TryParse<T>(string file, Func<string, T?> parse) where T : class
    {
        try
        {
            if (!File.Exists(file)) return null;
            var text = File.ReadAllText(file);
            return string.IsNullOrWhiteSpace(text) ? null : parse(text);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or FormatException)
        {
            return null;
        }
    }
}
