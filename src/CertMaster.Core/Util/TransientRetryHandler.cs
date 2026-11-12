using System.Net;

namespace CertMaster.Core.Util;

/// <summary>
/// Retries transient HTTP failures for the engine's shared HttpClient (DNS provider APIs, webhooks, deployment targets),
/// so one 502 or rate-limit response from a DNS API doesn't fail a renewal and push it into hours of back-off.
/// <list type="bullet">
/// <item>Connection failures (no response received) and 429: retried for every method, the server did not process them.</item>
/// <item>408/500/502/503/504: retried only for idempotent methods (GET, HEAD, PUT, DELETE, OPTIONS); a POST that failed
/// with a 5xx may have been applied, and re-sending could create a duplicate record.</item>
/// </list>
/// Honours Retry-After (capped), uses jittered exponential back-off and never retries after the caller cancelled.
/// Request bodies used by the providers are buffered (StringContent / ByteArrayContent), so they can be re-sent.
/// </summary>
public sealed class TransientRetryHandler : DelegatingHandler
{
    private readonly int _maxAttempts;
    private readonly TimeSpan _maxDelay;

    public TransientRetryHandler(HttpMessageHandler inner, int maxAttempts = 3, TimeSpan? maxDelay = null) : base(inner)
    {
        _maxAttempts = Math.Max(1, maxAttempts);
        _maxDelay = maxDelay ?? TimeSpan.FromSeconds(15);
    }

    /// <summary>A pooled handler that picks up DNS changes (connections recycled every 5 minutes) and uses the default proxy.</summary>
    public static HttpClient CreateClient(TimeSpan timeout) =>
        new(new TransientRetryHandler(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.All,
        })) { Timeout = timeout };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            HttpResponseMessage? response = null;
            try
            {
                response = await base.SendAsync(request, ct);
                if (attempt >= _maxAttempts || !ShouldRetry(request.Method, response.StatusCode)) return response;
            }
            catch (HttpRequestException) when (attempt < _maxAttempts && !ct.IsCancellationRequested)
            {
                // no response: connection refused/reset, DNS failure, TLS handshake failure
            }

            var delay = RetryDelay(response, attempt);
            response?.Dispose();
            await Task.Delay(delay, ct);
        }
    }

    internal static bool ShouldRetry(HttpMethod method, HttpStatusCode status)
    {
        if (status == HttpStatusCode.TooManyRequests) return true;
        var transient = status is HttpStatusCode.RequestTimeout or HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;
        return transient && IsIdempotent(method);
    }

    private static bool IsIdempotent(HttpMethod m) =>
        m == HttpMethod.Get || m == HttpMethod.Head || m == HttpMethod.Put || m == HttpMethod.Delete || m == HttpMethod.Options;

    private TimeSpan RetryDelay(HttpResponseMessage? response, int attempt)
    {
        var retryAfter = response?.Headers.RetryAfter;
        TimeSpan? server = retryAfter?.Delta ?? (retryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
        var backoff = TimeSpan.FromSeconds(Math.Pow(2, attempt) * (0.8 + Random.Shared.NextDouble() * 0.4)); // ~2, 4, 8 s
        var delay = server is { } s && s > backoff ? s : backoff;
        return delay > _maxDelay ? _maxDelay : delay < TimeSpan.Zero ? TimeSpan.Zero : delay;
    }
}
