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

    /// <summary>
    /// Replaces <paramref name="path"/> with <paramref name="content"/> without ever exposing a partial file: the data is
    /// written and flushed to a temporary file in the same folder, then renamed over the target. No backup copy is kept
    /// (use for files such as private keys that should not be duplicated). Retries briefly while another process (a
    /// backup agent, antivirus, a service reading the certificate) holds the target open.
    /// </summary>
    public static void WriteAllBytesNoBackup(string path, byte[] content)
    {
        var tmp = path + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(content);
                fs.Flush(flushToDisk: true);
            }
            for (var attempt = 1; ; attempt++)
            {
                try { File.Move(tmp, path, overwrite: true); return; }
                catch (Exception ex) when (attempt < 10 && ex is IOException or UnauthorizedAccessException) { Thread.Sleep(200 * attempt); }
            }
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (IOException) { /* best effort */ } catch (UnauthorizedAccessException) { /* best effort */ }
        }
    }

    public static void WriteAllTextNoBackup(string path, string content) => WriteAllBytesNoBackup(path, new UTF8Encoding(false).GetBytes(content));

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
