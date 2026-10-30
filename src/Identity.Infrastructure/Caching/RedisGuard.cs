using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Identity.Infrastructure.Caching;

/// <summary>
/// Redis is an accelerator and a shared counter here, never the source of truth: when it is down, callers get a
/// documented fallback instead of an exception (no 500s on login/refresh). Disconnected = fallback immediately,
/// without waiting for timeouts. Logged at most once a minute per feature, so an outage does not flood the logs.
/// </summary>
internal static class RedisGuard
{
    private static readonly TimeSpan LogInterval = TimeSpan.FromMinutes(1);
    private static readonly Dictionary<string, DateTime> LastLogged = [];

    public static async Task<T> RunAsync<T>(
        IConnectionMultiplexer redis, ILogger logger, string feature, T fallback, Func<IDatabase, Task<T>> operation)
    {
        if (!redis.IsConnected)
        {
            Warn(logger, feature, null);
            return fallback;
        }

        try
        {
            return await operation(redis.GetDatabase());
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException)
        {
            Warn(logger, feature, ex);
            return fallback;
        }
    }

    public static Task RunAsync(IConnectionMultiplexer redis, ILogger logger, string feature, Func<IDatabase, Task> operation) =>
        RunAsync(redis, logger, feature, true, async db =>
        {
            await operation(db);
            return true;
        });

    private static void Warn(ILogger logger, string feature, Exception? ex)
    {
        lock (LastLogged)
        {
            var now = DateTime.UtcNow;
            if (LastLogged.TryGetValue(feature, out var last) && now - last < LogInterval) return;
            LastLogged[feature] = now;
        }
        logger.LogWarning(ex, "Redis unavailable: {Feature} degraded (see RedisGuard)", feature);
    }
}
