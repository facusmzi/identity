using System.Threading.RateLimiting;
using StackExchange.Redis;

namespace Identity.Api.Extensions;

/// <summary>
/// Fixed-window limiter whose counter lives in Redis, so every API instance shares it (one INCR per request, made
/// atomic with its expiry by a tiny Lua script). If Redis is unavailable it falls back to a per-instance in-memory
/// limiter with the same settings: limits get looser across instances, but never disappear and never fail requests.
/// </summary>
public sealed class RedisFixedWindowRateLimiter(
    IConnectionMultiplexer redis, string partitionKey, int permitLimit, TimeSpan window, TimeProvider clock) : RateLimiter
{
    private const string Script =
        "local c = redis.call('INCR', KEYS[1]) if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end return c";

    private readonly FixedWindowRateLimiter _fallback = new(new FixedWindowRateLimiterOptions
    {
        PermitLimit = permitLimit,
        Window = window,
        QueueLimit = 0,
    });

    private long _lastUsedTicks = clock.GetUtcNow().UtcTicks;

    public override TimeSpan? IdleDuration => clock.GetUtcNow() - new DateTimeOffset(Interlocked.Read(ref _lastUsedTicks), TimeSpan.Zero);

    public override RateLimiterStatistics? GetStatistics() => _fallback.GetStatistics();

    /// <summary>
    /// The ASP.NET middleware tries this synchronous path FIRST and only calls <see cref="AcquireAsyncCore"/> when it
    /// fails. Granting here from the local counter would let every instance approve its first N requests without
    /// ever touching Redis (a bug the Postgres suite caught). So while Redis is up this always declines, which sends
    /// the request to the async path that counts in Redis; only during an outage does it answer locally.
    /// </summary>
    protected override RateLimitLease AttemptAcquireCore(int permitCount) =>
        redis.IsConnected ? Lease.Declined : _fallback.AttemptAcquire(permitCount);

    protected override async ValueTask<RateLimitLease> AcquireAsyncCore(int permitCount, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        Interlocked.Exchange(ref _lastUsedTicks, now.UtcTicks);
        if (!redis.IsConnected) return await _fallback.AcquireAsync(permitCount, cancellationToken);

        var windowMs = (long)window.TotalMilliseconds;
        var nowMs = now.ToUnixTimeMilliseconds();
        RedisKey key = $"identity:rl:{partitionKey}:{nowMs / windowMs}";
        try
        {
            var count = (long)await redis.GetDatabase().ScriptEvaluateAsync(Script, [key], [windowMs]);
            return count <= permitLimit
                ? Lease.Acquired
                : new Lease(false, TimeSpan.FromMilliseconds(windowMs - nowMs % windowMs));
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException)
        {
            return await _fallback.AcquireAsync(permitCount, cancellationToken);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _fallback.Dispose();
        base.Dispose(disposing);
    }

    private sealed class Lease(bool acquired, TimeSpan? retryAfter) : RateLimitLease
    {
        public static readonly Lease Acquired = new(true, null);
        public static readonly Lease Declined = new(false, null);

        public override bool IsAcquired => acquired;

        public override IEnumerable<string> MetadataNames => retryAfter is null ? [] : [MetadataName.RetryAfter.Name];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            metadata = metadataName == MetadataName.RetryAfter.Name ? retryAfter : null;
            return metadata is not null;
        }
    }
}
