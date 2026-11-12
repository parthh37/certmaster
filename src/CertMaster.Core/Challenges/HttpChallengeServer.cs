using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core.Challenges;

/// <summary>
/// Built-in http-01 responder. Uses HttpListener (http.sys on Windows) so it can share port 80 with IIS by
/// registering only the /.well-known/acme-challenge/ path. Started on demand while challenges are pending.
/// </summary>
public class HttpChallengeServer : IDisposable
{
    private readonly ILogger<HttpChallengeServer> _logger;
    private readonly ConcurrentDictionary<string, string> _responses = new();
    private HttpListener? _listener;
    private string? _prefix;
    private int _users;
    private readonly object _sync = new();

    public HttpChallengeServer(ILogger<HttpChallengeServer> logger) => _logger = logger;

    public bool IsRunning => _listener?.IsListening == true;

    /// <summary>Begin a challenge session. Returns false if the listener could not be started (e.g. no permission).</summary>
    public bool Start(string prefix, out string? error)
    {
        error = null;
        lock (_sync)
        {
            _users++;
            if (IsRunning && _prefix == prefix) return true;
            try
            {
                _listener?.Close();
                _listener = new HttpListener();
                _listener.Prefixes.Add(prefix.EndsWith('/') ? prefix : prefix + "/");
                _listener.Start();
                _prefix = prefix;
                _ = Task.Run(() => Loop(_listener));
                _logger.LogInformation("HTTP challenge server listening on {Prefix}", prefix);
                return true;
            }
            catch (Exception ex)
            {
                _users--;
                _listener = null;
                error = ex.Message;
                _logger.LogWarning("HTTP challenge server could not start on {Prefix}: {Error}", prefix, ex.Message);
                return false;
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            if (--_users > 0) return;
            _users = 0;
            try { _listener?.Stop(); _listener?.Close(); } catch { /* ignore */ }
            _listener = null;
            _logger.LogInformation("HTTP challenge server stopped");
        }
    }

    public void AddResponse(string token, string keyAuthorization) => _responses[token] = keyAuthorization;
    public void RemoveResponse(string token) => _responses.TryRemove(token, out _);
    public IReadOnlyDictionary<string, string> CurrentResponses => _responses;

    private async Task Loop(HttpListener listener)
    {
        while (listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await listener.GetContextAsync(); }
            catch { break; }
            try
            {
                var token = ctx.Request.Url?.Segments.LastOrDefault()?.Trim('/') ?? "";
                if (_responses.TryGetValue(token, out var value))
                {
                    var bytes = Encoding.ASCII.GetBytes(value);
                    ctx.Response.ContentType = "text/plain";
                    ctx.Response.StatusCode = 200;
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                    _logger.LogInformation("Served http-01 challenge {Token} to {Remote}", token, ctx.Request.RemoteEndPoint);
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "Challenge response error"); }
            finally { try { ctx.Response.Close(); } catch { /* ignore */ } }
        }
    }

    public void Dispose()
    {
        try { _listener?.Close(); } catch { /* ignore */ }
    }

    /// <summary>Writes the challenge file to a web root (file based http-01) with an IIS web.config for extensionless files.</summary>
    public static string WriteChallengeFile(string webRoot, string token, string keyAuthorization)
    {
        var dir = Path.Combine(webRoot, ".well-known", "acme-challenge");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, token);
        File.WriteAllText(path, keyAuthorization, new UTF8Encoding(false));
        var webConfig = Path.Combine(dir, "web.config");
        if (!File.Exists(webConfig))
        {
            File.WriteAllText(webConfig,
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <staticContent>\n" +
                "      <remove fileExtension=\".\" />\n      <mimeMap fileExtension=\".\" mimeType=\"text/plain\" />\n" +
                "    </staticContent>\n    <handlers>\n      <clear />\n      <add name=\"StaticFile\" path=\"*\" verb=\"*\" modules=\"StaticFileModule\" resourceType=\"Either\" requireAccess=\"Read\" />\n" +
                "    </handlers>\n  </system.webServer>\n</configuration>\n");
        }
        return path;
    }
}
