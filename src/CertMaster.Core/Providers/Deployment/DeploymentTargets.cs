using System.Net;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using CertMaster.Core.Util;
using CertMaster.Models;
using Microsoft.Win32.SafeHandles;
using Renci.SshNet;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>File operations against a deployment target (this machine, a Windows share, or a remote host over SFTP).</summary>
public interface ITargetFileSystem : IDisposable
{
    /// <summary>Human readable description used in log lines, e.g. "local (service account)" or "sftp://host:22".</summary>
    string Description { get; }
    /// <summary>Writes the file, creating parent folders as needed. <paramref name="sensitive"/> files (private keys) get owner-only permissions where the target supports it.</summary>
    Task WriteAllBytesAsync(string path, byte[] content, bool sensitive = false, CancellationToken ct = default);
    /// <summary>True when a file or directory exists at the path.</summary>
    Task<bool> ExistsAsync(string path, CancellationToken ct = default);
    Task<bool> IsDirectoryAsync(string path, CancellationToken ct = default);
}

/// <summary>Runs commands on a deployment target (this machine, as another Windows user, or over SSH).</summary>
public interface IRemoteCommandRunner : IDisposable
{
    string Description { get; }
    Task<ProcessResult> RunAsync(CommandSpec command, CancellationToken ct = default);
}

// ---------------------------------------------------------------- local

public sealed class LocalFileSystem : ITargetFileSystem
{
    private readonly Action<string>? _warn;

    /// <param name="warn">Receives non-fatal problems, e.g. a network share that would not accept restricted permissions.</param>
    public LocalFileSystem(Action<string>? warn = null) => _warn = warn;

    public string Description => "local (service account)";

    public Task WriteAllBytesAsync(string path, byte[] content, bool sensitive = false, CancellationToken ct = default) =>
        Task.Run(() => SafeFileWriter.Write(path, content, sensitive, null, _warn, ct), ct);

    public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => Task.FromResult(File.Exists(path) || Directory.Exists(path));
    public Task<bool> IsDirectoryAsync(string path, CancellationToken ct = default) => Task.FromResult(Directory.Exists(path));
    public void Dispose() { }
}

public sealed class LocalCommandRunner : IRemoteCommandRunner
{
    public string Description => "local (service account)";
    public Task<ProcessResult> RunAsync(CommandSpec command, CancellationToken ct = default) => ProcessRunner.RunAsync(command, ct);
    public void Dispose() { }
}

/// <summary>
/// Replaces files on local disks and UNC shares without exposing partial content: the data goes to a temporary file in the
/// same folder (already carrying its final permissions), is flushed, and is then renamed over the target. Readers that watch
/// the folder (IIS Centralized Certificate Store, nginx/Tomcat reloads) therefore see either the old or the new file, and a
/// failure leaves the previous file untouched.
/// </summary>
internal static class SafeFileWriter
{
    private const int ERROR_ACCESS_DENIED = unchecked((int)0x80070005);
    private const int ERROR_SHARING_VIOLATION = unchecked((int)0x80070020);
    private const int ERROR_LOCK_VIOLATION = unchecked((int)0x80070021);
    private const int MaxReplaceAttempts = 10;

    /// <summary>Temporary name used next to the target ("&lt;target&gt;.tmp-&lt;guid&gt;"); never ends in the target's extension so folder watchers ignore it.</summary>
    public static string TempPathFor(string fullPath) => fullPath + ".tmp-" + Guid.NewGuid().ToString("N");

    /// <param name="sensitive">Private keys / PFX: the file gets a protected ACL (SYSTEM, Administrators, the writing account and <paramref name="extraAccounts"/>) on Windows, mode 0600 elsewhere.</param>
    /// <param name="warn">Receives non-fatal problems (a network share that rejects the restricted ACL).</param>
    public static void Write(string path, byte[] content, bool sensitive, IReadOnlyCollection<SecurityIdentifier>? extraAccounts, Action<string>? warn, CancellationToken ct)
    {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = TempPathFor(full);
        try
        {
            using (var fs = CreateTemp(full, tmp, sensitive, extraAccounts, warn))
            {
                fs.Write(content);
                fs.Flush(flushToDisk: true);
            }
            ct.ThrowIfCancellationRequested();
            ReplaceWithRetry(tmp, full, ct);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); }
            catch (IOException) { /* best effort */ }
            catch (UnauthorizedAccessException) { /* best effort */ }
        }
    }

    /// <summary>Renames <paramref name="tmp"/> over <paramref name="target"/>, retrying while another process (a service reading the certificate, antivirus, backup) has the target open.</summary>
    internal static void ReplaceWithRetry(string tmp, string target, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try { File.Move(tmp, target, overwrite: true); return; }
            catch (Exception ex) when (attempt < MaxReplaceAttempts && IsTransient(ex))
            {
                if (ct.WaitHandle.WaitOne(200 * attempt)) ct.ThrowIfCancellationRequested();
            }
        }
    }

    // Renaming over a file that is open without FILE_SHARE_DELETE reports access denied or a sharing violation.
    private static bool IsTransient(Exception ex) =>
        ex is UnauthorizedAccessException || (ex is IOException io && io.HResult is ERROR_SHARING_VIOLATION or ERROR_LOCK_VIOLATION or ERROR_ACCESS_DENIED);

    private static FileStream CreateTemp(string target, string tmp, bool sensitive, IReadOnlyCollection<SecurityIdentifier>? extraAccounts, Action<string>? warn)
    {
        if (!OperatingSystem.IsWindows())
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (sensitive) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            return new FileStream(tmp, options);
        }

        var network = IsNetworkPath(target);
        FileSecurity? security;
        try { security = sensitive ? ProtectedFileSecurity(target, extraAccounts, network) : CustomSecurityOf(target); }
        catch (Exception ex) when (!sensitive && ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            security = null; // can't read the old file's ACL: the new file just inherits from the folder
        }
        if (security != null)
        {
            try
            {
                return new FileInfo(tmp).Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.Synchronize, FileShare.None, 4096, FileOptions.None, security);
            }
            catch (Exception ex) when ((network || !sensitive) && ex is UnauthorizedAccessException or IOException or PrivilegeNotHeldException or NotSupportedException or InvalidOperationException)
            {
                // Some file servers (NAS, Samba, restricted share permissions) refuse explicit ACLs; the file then inherits the share folder's permissions.
                warn?.Invoke(sensitive
                    ? $"Could not restrict permissions on {target} ({ex.Message.Trim()}); the file inherits the folder's permissions. Restrict access to that folder on the file server."
                    : $"Could not keep the existing permissions of {target} ({ex.Message.Trim()}); the file inherits the folder's permissions.");
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
        return new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
    }

    /// <summary>True for UNC paths and mapped network drives.</summary>
    internal static bool IsNetworkPath(string fullPath)
    {
        if (fullPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal) || fullPath.StartsWith(@"\\.\", StringComparison.Ordinal)) return false;
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal)) return true;
        try { return Path.GetPathRoot(fullPath) is { Length: > 0 } root && new DriveInfo(root).DriveType == DriveType.Network; }
        catch (Exception) { return false; }
    }

    /// <summary>
    /// Protected (non-inheriting) ACL for private key files: full control for SYSTEM, Administrators, the current account and
    /// <paramref name="extraAccounts"/>. Explicit grants an administrator added to the file being replaced (e.g. read access
    /// for a service account) are kept; inherited access such as BUILTIN\Users read is not. On network paths the file owner
    /// (OWNER RIGHTS) also keeps full control, because the account the file server sees may not be resolvable here.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static FileSecurity ProtectedFileSecurity(string target, IReadOnlyCollection<SecurityIdentifier>? extraAccounts, bool includeOwnerRights)
    {
        var sids = new List<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
        };
        using (var current = WindowsIdentity.GetCurrent()) if (current.User != null) sids.Add(current.User);
        if (extraAccounts != null) sids.AddRange(extraAccounts);
        if (includeOwnerRights) sids.Add(new SecurityIdentifier("S-1-3-4"));

        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in sids.Distinct())
            sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        foreach (var rule in ExplicitRules(target))
            if (rule.AccessControlType == AccessControlType.Deny || !sids.Contains((SecurityIdentifier)rule.IdentityReference))
                sec.AddAccessRule(rule);
        return sec;
    }

    /// <summary>The explicit ACL of an existing target (non-sensitive files), or null when it only inherits from its folder.</summary>
    [SupportedOSPlatform("windows")]
    private static FileSecurity? CustomSecurityOf(string target)
    {
        if (!File.Exists(target)) return null;
        var existing = new FileInfo(target).GetAccessControl(AccessControlSections.Access);
        var rules = ExplicitRules(existing);
        if (!existing.AreAccessRulesProtected && rules.Count == 0) return null;
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(existing.AreAccessRulesProtected, preserveInheritance: false);
        foreach (var rule in rules) sec.AddAccessRule(rule);
        return sec;
    }

    [SupportedOSPlatform("windows")]
    private static List<FileSystemAccessRule> ExplicitRules(string target)
    {
        try { return File.Exists(target) ? ExplicitRules(new FileInfo(target).GetAccessControl(AccessControlSections.Access)) : new(); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException) { return new(); }
    }

    [SupportedOSPlatform("windows")]
    private static List<FileSystemAccessRule> ExplicitRules(FileSecurity security) =>
        security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(r => new FileSystemAccessRule(r.IdentityReference, r.FileSystemRights, InheritanceFlags.None, PropagationFlags.None, r.AccessControlType))
            .ToList();
}

// ---------------------------------------------------------------- Windows impersonation (local as user / UNC)

/// <summary>Performs file operations while impersonating a Windows account (LogonUser + WindowsIdentity.RunImpersonated).</summary>
[SupportedOSPlatform("windows")]
public sealed class ImpersonatedFileSystem : ITargetFileSystem
{
    private readonly WindowsCredential _credential;
    private readonly WindowsLogonType _logonType;
    private readonly Action<string>? _warn;
    private SafeAccessTokenHandle? _token;
    private SecurityIdentifier[]? _accountSids;

    public ImpersonatedFileSystem(WindowsCredential credential, WindowsLogonType logonType, Action<string>? warn = null)
    {
        _credential = credential;
        _logonType = logonType;
        _warn = warn;
    }

    public string Description => $"as {_credential.AccountName} ({_logonType})";

    private T Run<T>(Func<T> action)
    {
        _token ??= WindowsLogon.Logon(_credential, _logonType);
        return WindowsIdentity.RunImpersonated(_token, action);
    }

    /// <summary>
    /// The credential's account, so it keeps access to the restricted files it writes. With NewCredentials logons the local
    /// identity stays the service account while the file server sees this account. Empty when the name can't be resolved here.
    /// </summary>
    private SecurityIdentifier[] AccountSids()
    {
        if (_accountSids != null) return _accountSids;
        try { _accountSids = new[] { (SecurityIdentifier)new NTAccount(_credential.AccountName).Translate(typeof(SecurityIdentifier)) }; }
        catch (Exception) { _accountSids = Array.Empty<SecurityIdentifier>(); }
        return _accountSids;
    }

    public Task WriteAllBytesAsync(string path, byte[] content, bool sensitive = false, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            var extra = sensitive ? AccountSids() : null;
            return Run(() => { SafeFileWriter.Write(path, content, sensitive, extra, _warn, ct); return true; });
        }, ct);

    public Task<bool> ExistsAsync(string path, CancellationToken ct = default) => Task.Run(() => Run(() => File.Exists(path) || Directory.Exists(path)), ct);
    public Task<bool> IsDirectoryAsync(string path, CancellationToken ct = default) => Task.Run(() => Run(() => Directory.Exists(path)), ct);
    public void Dispose() => _token?.Dispose();
}

public sealed class LocalAsUserCommandRunner : IRemoteCommandRunner
{
    private readonly WindowsCredential _credential;
    private readonly WindowsLogonType _logonType;

    public LocalAsUserCommandRunner(WindowsCredential credential, WindowsLogonType logonType)
    {
        _credential = credential;
        _logonType = logonType;
    }

    public string Description => $"local as {_credential.AccountName} ({_logonType})";
    public Task<ProcessResult> RunAsync(CommandSpec command, CancellationToken ct = default) => ProcessRunner.RunAsUserAsync(command, _credential, _logonType, ct);
    public void Dispose() { }
}

// ---------------------------------------------------------------- SSH / SFTP

/// <summary>Connection settings for an SSH target, built from DeploymentTaskConfig.TargetHost and an SSH stored credential.</summary>
public sealed class SshTargetSettings
{
    public required string Host { get; init; }
    public int Port { get; init; } = 22;
    public required string UserName { get; init; }
    public string? Password { get; init; }
    public string? PrivateKeyPath { get; init; }
    public string? PrivateKeyPassphrase { get; init; }
    /// <summary>Optional expected host key fingerprint (SHA256 base64, as shown by ssh-keygen -l, with or without the "SHA256:" prefix).</summary>
    public string? HostKeyFingerprint { get; init; }

    public string Description => $"{UserName}@{Host}:{Port}";

    public ConnectionInfo CreateConnectionInfo()
    {
        var methods = new List<AuthenticationMethod>();
        if (!string.IsNullOrEmpty(PrivateKeyPath))
        {
            var key = string.IsNullOrEmpty(PrivateKeyPassphrase) ? new PrivateKeyFile(PrivateKeyPath) : new PrivateKeyFile(PrivateKeyPath, PrivateKeyPassphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(UserName, key));
        }
        if (!string.IsNullOrEmpty(Password)) methods.Add(new PasswordAuthenticationMethod(UserName, Password));
        return new ConnectionInfo(Host, Port, UserName, methods.ToArray()) { Timeout = TimeSpan.FromSeconds(30) };
    }

    internal void AttachHostKeyCheck(BaseClient client, Action<string>? log)
    {
        client.HostKeyReceived += (_, e) =>
        {
            var actual = e.FingerPrintSHA256;
            if (!string.IsNullOrWhiteSpace(HostKeyFingerprint))
            {
                var expected = HostKeyFingerprint.Trim();
                if (expected.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)) expected = expected[7..];
                e.CanTrust = string.Equals(expected.TrimEnd('='), actual.TrimEnd('='), StringComparison.Ordinal);
                if (!e.CanTrust) log?.Invoke($"SSH host key for {Host} (SHA256:{actual}) does not match the expected fingerprint; connection refused.");
            }
            else
            {
                e.CanTrust = true;
                log?.Invoke($"SSH host key for {Host}: {e.HostKeyName} SHA256:{actual} (not pinned)");
            }
        };
    }
}

public sealed class SftpFileSystem : ITargetFileSystem
{
    private readonly SshTargetSettings _settings;
    private readonly Action<string>? _log;
    private SftpClient? _client;

    public SftpFileSystem(SshTargetSettings settings, Action<string>? log = null)
    {
        _settings = settings;
        _log = log;
    }

    public string Description => "sftp://" + _settings.Description;

    private async Task<SftpClient> ClientAsync(CancellationToken ct)
    {
        if (_client is { IsConnected: true }) return _client;
        _client?.Dispose();
        _client = new SftpClient(_settings.CreateConnectionInfo());
        _settings.AttachHostKeyCheck(_client, _log);
        await _client.ConnectAsync(ct);
        return _client;
    }

    public static string NormalizePath(string path) => path.Replace('\\', '/');

    public async Task WriteAllBytesAsync(string path, byte[] content, bool sensitive = false, CancellationToken ct = default)
    {
        var client = await ClientAsync(ct);
        path = NormalizePath(path);
        var slash = path.LastIndexOf('/');
        if (slash > 0) await EnsureDirectoryAsync(client, path[..slash], ct);
        var existing = await TryGetAttributesAsync(client, path, ct);

        // Upload to a temporary name and rename it over the target, so services never read a half-written file and a failed
        // upload leaves the previous file in place.
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var replaced = false;
        try
        {
            await using (var stream = await client.OpenAsync(tmp, FileMode.CreateNew, FileAccess.Write, ct))
            {
                // restrict the still-empty file before any key material is written to it
                if (sensitive) TrySetMode(client, tmp, 600, path); // SSH.NET reads the digits as octal (rw-------)
                await stream.WriteAsync(content, ct);
                await stream.FlushAsync(ct);
            }
            if (!sensitive && existing != null) CopyModeAndGroup(client, existing, tmp, path);
            Replace(client, tmp, path, existing != null);
            replaced = true;
        }
        finally
        {
            if (!replaced)
            {
                try { client.DeleteFile(tmp); }
                catch (Exception) { /* best effort; it may never have been created */ }
            }
        }
    }

    private static async Task<Renci.SshNet.Sftp.SftpFileAttributes?> TryGetAttributesAsync(SftpClient client, string path, CancellationToken ct)
    {
        try { return await client.GetAttributesAsync(path, ct); }
        catch (Renci.SshNet.Common.SftpPathNotFoundException) { return null; }
    }

    private void TrySetMode(SftpClient client, string path, short octalDigits, string target)
    {
        try { client.ChangePermissions(path, octalDigits); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log?.Invoke($"Could not set permissions {octalDigits} on {target}: {ex.Message}"); }
    }

    /// <summary>The replaced file's mode and group carry over to the new one (e.g. a certificate readable by an ssl-cert group).</summary>
    private void CopyModeAndGroup(SftpClient client, Renci.SshNet.Sftp.SftpFileAttributes existing, string tmp, string target)
    {
        TrySetMode(client, tmp, ModeDigits(existing), target);
        try
        {
            var attrs = client.GetAttributes(tmp);
            if (attrs.GroupId == existing.GroupId) return;
            attrs.GroupId = existing.GroupId;
            client.SetAttributes(tmp, attrs);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log?.Invoke($"Could not keep the group of {target}: {ex.Message}"); }
    }

    /// <summary>Permission bits in the "octal digits as a decimal number" form SSH.NET's ChangePermissions expects (e.g. 644).</summary>
    internal static short ModeDigits(Renci.SshNet.Sftp.SftpFileAttributes a)
    {
        static int Digit(bool r, bool w, bool x) => (r ? 4 : 0) + (w ? 2 : 0) + (x ? 1 : 0);
        return (short)(Digit(a.OwnerCanRead, a.OwnerCanWrite, a.OwnerCanExecute) * 100
                       + Digit(a.GroupCanRead, a.GroupCanWrite, a.GroupCanExecute) * 10
                       + Digit(a.OthersCanRead, a.OthersCanWrite, a.OthersCanExecute));
    }

    private void Replace(SftpClient client, string tmp, string path, bool targetExists)
    {
        try
        {
            client.RenameFile(tmp, path, isPosix: true); // posix-rename@openssh.com replaces the target atomically
            return;
        }
        catch (NotSupportedException) { /* server without the extension */ }
        // A plain SFTP rename fails when the target exists, so remove it first (a brief window without the file).
        if (targetExists)
        {
            try { client.DeleteFile(path); }
            catch (Renci.SshNet.Common.SftpPathNotFoundException) { /* already gone */ }
        }
        client.RenameFile(tmp, path);
        _log?.Invoke($"The SFTP server does not support posix-rename; replaced {path} with delete + rename.");
    }

    private static async Task EnsureDirectoryAsync(SftpClient client, string dir, CancellationToken ct)
    {
        var parts = dir.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var current = dir.StartsWith('/') ? "" : ".";
        foreach (var part in parts)
        {
            current = current == "" ? "/" + part : current + "/" + part;
            if (current.Length == 3 && current[2] == ':') continue; // Windows OpenSSH drive "/C:"
            if (!await client.ExistsAsync(current, ct)) await client.CreateDirectoryAsync(current, ct);
        }
    }

    public async Task<bool> ExistsAsync(string path, CancellationToken ct = default) => await (await ClientAsync(ct)).ExistsAsync(NormalizePath(path), ct);

    public async Task<bool> IsDirectoryAsync(string path, CancellationToken ct = default)
    {
        var client = await ClientAsync(ct);
        path = NormalizePath(path);
        return await client.ExistsAsync(path, ct) && (await client.GetAttributesAsync(path, ct)).IsDirectory;
    }

    public void Dispose() => _client?.Dispose();
}

public sealed class SshCommandRunner : IRemoteCommandRunner
{
    private readonly SshTargetSettings _settings;
    private readonly Action<string>? _log;
    private SshClient? _client;

    public SshCommandRunner(SshTargetSettings settings, Action<string>? log = null)
    {
        _settings = settings;
        _log = log;
    }

    public string Description => "ssh://" + _settings.Description;

    /// <summary>Builds the shell command line sent to the remote host.</summary>
    public static string BuildRemoteCommand(CommandSpec command)
    {
        var line = command.Program.Contains(' ') && !command.Program.StartsWith('"') && !command.Program.StartsWith('\'')
            ? ProcessRunner.QuotePosixArgument(command.Program) : command.Program;
        if (command.RawArguments != null) { if (command.RawArguments.Length > 0) line += " " + command.RawArguments; }
        else if (command.Arguments.Count > 0) line += " " + string.Join(' ', command.Arguments.Select(ProcessRunner.QuotePosixArgument));
        if (command.Environment is { Count: > 0 })
            line = string.Concat(command.Environment.Select(kv => $"export {kv.Key}={ProcessRunner.QuotePosixArgument(kv.Value)}; ")) + line;
        if (!string.IsNullOrWhiteSpace(command.WorkingDirectory))
            line = $"cd {ProcessRunner.QuotePosixArgument(command.WorkingDirectory)} && " + line;
        if (command.Detached)
            line = $"nohup sh -c {ProcessRunner.QuotePosixArgument(line)} >/dev/null 2>&1 &";
        return line;
    }

    public async Task<ProcessResult> RunAsync(CommandSpec command, CancellationToken ct = default)
    {
        if (_client is not { IsConnected: true })
        {
            _client?.Dispose();
            _client = new SshClient(_settings.CreateConnectionInfo());
            _settings.AttachHostKeyCheck(_client, _log);
            await _client.ConnectAsync(ct);
        }
        using var cmd = _client.CreateCommand(BuildRemoteCommand(command));
        cmd.CommandTimeout = command.Timeout;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(command.Timeout);
        try { await cmd.ExecuteAsync(cts.Token); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); } // the caller cancelled (matches ProcessRunner)
        catch (OperationCanceledException) { return new ProcessResult(-1, cmd.Result ?? "", "Timed out after " + command.Timeout); }
        catch (Renci.SshNet.Common.SshOperationTimeoutException) { return new ProcessResult(-1, cmd.Result ?? "", "Timed out after " + command.Timeout); }
        object? exit = cmd.ExitStatus;
        return new ProcessResult(exit is int code ? code : -1, cmd.Result ?? "", cmd.Error ?? "");
    }

    public void Dispose() => _client?.Dispose();
}

// ---------------------------------------------------------------- factory / validation

/// <summary>Creates file systems and command runners for the target selected on a deployment task.</summary>
public static class DeploymentTargets
{
    /// <summary>Common parameter: how to log on with Windows credentials (UNC share / local as user targets).</summary>
    public static ProviderParameter LogonTypeParameter() => new()
    {
        Key = "logontype", Name = "Windows logon type", Type = OptionType.Select, Value = "auto",
        Description = "Used with Windows credentials. Auto = NewCredentials for network shares, Interactive for local-as-user.",
        OptionsList = "auto=Auto;newcredentials=New Credentials (network access only);interactive=Interactive;network=Network;batch=Batch;service=Service",
    };

    public static readonly List<DeploymentContextType> AllTargets = new()
        { DeploymentContextType.LocalAsService, DeploymentContextType.LocalAsUser, DeploymentContextType.WindowsNetwork, DeploymentContextType.SSH };

    public static readonly List<DeploymentContextType> WindowsTargets = new()
        { DeploymentContextType.LocalAsService, DeploymentContextType.LocalAsUser, DeploymentContextType.WindowsNetwork };

    /// <summary>Parses "host", "host:port", "[ipv6]" or "[ipv6]:port".</summary>
    public static bool TryParseHost(string? value, out string host, out int port, int defaultPort = 22)
    {
        host = ""; port = defaultPort;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var v = value.Trim();
        if (v.Contains("://")) return false;
        if (v.StartsWith('['))
        {
            var end = v.IndexOf(']');
            if (end < 2) return false;
            host = v[1..end];
            var rest = v[(end + 1)..];
            if (rest.Length == 0) return IPAddress.TryParse(host, out _);
            return rest.StartsWith(':') && int.TryParse(rest[1..], out port) && port is > 0 and < 65536 && IPAddress.TryParse(host, out _);
        }
        var colons = v.Count(c => c == ':');
        if (colons > 1) { host = v; return IPAddress.TryParse(v, out _); } // bare IPv6
        if (colons == 1)
        {
            var i = v.IndexOf(':');
            host = v[..i];
            if (!int.TryParse(v[(i + 1)..], out port) || port is <= 0 or > 65535) return false;
        }
        else host = v;
        return host.Length > 0 && Uri.CheckHostName(host) != UriHostNameType.Unknown;
    }

    public static WindowsLogonType ResolveLogonType(DeploymentContext ctx) =>
        WindowsLogon.Parse(ctx.Param("logontype"),
            ctx.TargetType == DeploymentContextType.WindowsNetwork ? WindowsLogonType.NewCredentials : WindowsLogonType.Interactive);

    public static SshTargetSettings GetSshSettings(DeploymentContext ctx)
    {
        if (!TryParseHost(ctx.TargetHost, out var host, out var port))
            throw new InvalidOperationException($"Invalid SSH target host '{ctx.TargetHost}'. Use host or host:port.");
        var c = ctx.Credentials;
        var user = c.GetValueOrDefault("username");
        if (string.IsNullOrWhiteSpace(user)) throw new InvalidOperationException("The SSH credential has no username.");
        return new SshTargetSettings
        {
            Host = host, Port = port, UserName = user.Trim(),
            Password = c.GetValueOrDefault("password"),
            PrivateKeyPath = c.GetValueOrDefault("privatekey"),
            PrivateKeyPassphrase = c.GetValueOrDefault("key_passphrase"),
            HostKeyFingerprint = c.GetValueOrDefault("host_fingerprint") ?? ctx.Param("sshhostkey"),
        };
    }

    /// <summary>Creates the file system for the task's target. Caller disposes.</summary>
    public static ITargetFileSystem CreateFileSystem(DeploymentContext ctx)
    {
        switch (ctx.TargetType)
        {
            case DeploymentContextType.SSH:
                return new SftpFileSystem(GetSshSettings(ctx), ctx.Log.Info);
            case DeploymentContextType.LocalAsUser:
            case DeploymentContextType.WindowsNetwork:
                var cred = WindowsCredential.FromDictionary(ctx.Credentials);
                if (cred == null)
                {
                    if (ctx.TargetType == DeploymentContextType.LocalAsUser) throw new InvalidOperationException("A Windows credential (username and password) is required to run as a user.");
                    return new LocalFileSystem(ctx.Log.Warn); // UNC path accessed with the service account
                }
                if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows credentials can only be used on Windows.");
                return new ImpersonatedFileSystem(cred, ResolveLogonType(ctx), ctx.Log.Warn);
            default:
                return new LocalFileSystem(ctx.Log.Warn);
        }
    }

    /// <summary>Creates the command runner for the task's target. Caller disposes.</summary>
    public static IRemoteCommandRunner CreateCommandRunner(DeploymentContext ctx)
    {
        switch (ctx.TargetType)
        {
            case DeploymentContextType.SSH:
                return new SshCommandRunner(GetSshSettings(ctx), ctx.Log.Info);
            case DeploymentContextType.LocalAsUser:
                var cred = WindowsCredential.FromDictionary(ctx.Credentials)
                           ?? throw new InvalidOperationException("A Windows credential (username and password) is required to run as a user.");
                return new LocalAsUserCommandRunner(cred, ResolveLogonType(ctx));
            case DeploymentContextType.WindowsNetwork:
                throw new InvalidOperationException("Commands cannot be run against a Windows network share target. Use Local (as user) or SSH.");
            default:
                return new LocalCommandRunner();
        }
    }

    /// <summary>Describes the target for preview/log messages without connecting.</summary>
    public static string Describe(DeploymentContext ctx) => ctx.TargetType switch
    {
        DeploymentContextType.SSH => $"SSH host {ctx.TargetHost}",
        DeploymentContextType.LocalAsUser => $"this machine as {WindowsCredential.FromDictionary(ctx.Credentials)?.AccountName ?? "(no user)"}",
        DeploymentContextType.WindowsNetwork => WindowsCredential.FromDictionary(ctx.Credentials) is { } c ? $"network path as {c.AccountName}" : "network path (service account)",
        _ => "this machine (service account)",
    };

    /// <summary>Validates the selected target type, host and credentials against what the task supports.</summary>
    public static List<ActionStep> Validate(DeploymentProviderDefinition def, DeploymentContext ctx)
    {
        var errors = new List<ActionStep>();
        if (!def.SupportedTargets.Contains(ctx.TargetType))
        {
            errors.Add(new ActionStep($"{def.Title} cannot run against a {ctx.TargetType} target. Supported: {string.Join(", ", def.SupportedTargets)}", hasError: true));
            return errors;
        }
        switch (ctx.TargetType)
        {
            case DeploymentContextType.SSH:
                if (!TryParseHost(ctx.TargetHost, out _, out _))
                    errors.Add(new ActionStep(string.IsNullOrWhiteSpace(ctx.TargetHost) ? "Target host is required for SSH targets" : $"Invalid SSH target host '{ctx.TargetHost}' (use host or host:port)", hasError: true));
                if (string.IsNullOrWhiteSpace(ctx.Credentials.GetValueOrDefault("username")))
                    errors.Add(new ActionStep("An SSH credential with a username is required", hasError: true));
                else if (string.IsNullOrEmpty(ctx.Credentials.GetValueOrDefault("password")) && string.IsNullOrWhiteSpace(ctx.Credentials.GetValueOrDefault("privatekey")))
                    errors.Add(new ActionStep("The SSH credential needs a password or a private key file", hasError: true));
                else if (ctx.Credentials.GetValueOrDefault("privatekey") is { Length: > 0 } key && !File.Exists(key))
                    errors.Add(new ActionStep($"SSH private key file not found: {key}", hasError: true));
                break;
            case DeploymentContextType.LocalAsUser:
                if (WindowsCredential.FromDictionary(ctx.Credentials) == null)
                    errors.Add(new ActionStep("A Windows credential (username and password) is required to run as a user", hasError: true));
                if (!OperatingSystem.IsWindows()) errors.Add(new ActionStep("Running as a Windows user is only supported on Windows", hasError: true));
                break;
            case DeploymentContextType.WindowsNetwork:
                if (ctx.Credentials.Count > 0 && WindowsCredential.FromDictionary(ctx.Credentials) == null)
                    errors.Add(new ActionStep("The Windows credential must include a username and password", hasError: true));
                break;
        }
        if ((ctx.TargetType is DeploymentContextType.LocalAsUser or DeploymentContextType.WindowsNetwork) && !WindowsLogon.IsKnown(ctx.Param("logontype")))
            errors.Add(new ActionStep($"Unknown Windows logon type '{ctx.Param("logontype")}'", hasError: true));
        return errors;
    }

    /// <summary>
    /// Validates a destination path for the target. Local/Windows targets need a fully qualified path (C:\... or \\server\share\...);
    /// SSH targets accept any non-empty path. Returns null when valid.
    /// </summary>
    public static string? ValidatePath(DeploymentContext ctx, string label, string? path, bool mustBeFile = true)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        if (path.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0) return $"{label} contains invalid characters";
        if (mustBeFile && (path.EndsWith('/') || path.EndsWith('\\'))) return $"{label} must be a file path, not a folder: {path}";
        if (ctx.TargetType == DeploymentContextType.SSH) return null;
        if (!Path.IsPathFullyQualified(path)) return $"{label} must be a full path (e.g. C:\\certs\\file or \\\\server\\share\\file): {path}";
        if (Path.GetFileName(path).IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return $"{label} has an invalid file name: {path}";
        return null;
    }
}
