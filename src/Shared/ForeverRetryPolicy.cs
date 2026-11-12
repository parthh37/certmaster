using Microsoft.AspNetCore.SignalR.Client;

namespace CertMaster.Hosting;

/// <summary>
/// SignalR reconnect policy that never gives up (the default stops after four attempts, about 42 s). Delays grow
/// 0, 2, 4, 8 ... seconds up to <see cref="MaxDelay"/>, with ±20% jitter so many agents don't reconnect to a restarted
/// hub in the same instant. Linked into the agent service and the desktop client.
/// </summary>
internal sealed class ForeverRetryPolicy : IRetryPolicy
{
    public static readonly TimeSpan MaxDelay = TimeSpan.FromMinutes(2);

    public TimeSpan? NextRetryDelay(RetryContext retryContext) => Delay(retryContext.PreviousRetryCount);

    public static TimeSpan Delay(long attempt)
    {
        if (attempt <= 0) return TimeSpan.Zero;
        var seconds = Math.Min(Math.Pow(2, Math.Min(attempt, 10)), MaxDelay.TotalSeconds);
        return TimeSpan.FromSeconds(seconds * (0.8 + Random.Shared.NextDouble() * 0.4));
    }
}
