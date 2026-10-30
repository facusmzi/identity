using System.Text.Json;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using Identity.Application.Abstractions.Security;
using Identity.Application.Services;

namespace Identity.Infrastructure.Caching;

/// <summary>
/// Redis-backed <see cref="ISessionCache"/>. One round trip per authenticated request (MGET of the entry and the
/// user's generation). When Redis is unavailable it degrades to "always miss" without waiting for timeouts.
/// </summary>
public sealed class RedisSessionCache(IConnectionMultiplexer redis, ILogger<RedisSessionCache> logger) : ISessionCache
{
    /// <summary>Returned as generation when Redis failed: tells SetAsync not to write anything.</summary>
    private const long Unavailable = -1;

    // Must outlive any entry (entries live seconds); after it expires the generation restarts at 0, which is
    // safe because every entry tagged with an older generation is long gone by then.
    private static readonly TimeSpan GenerationTtl = TimeSpan.FromDays(1);

    private static RedisKey EntryKey(Guid sessionId) => $"identity:session:{sessionId:N}";
    private static RedisKey GenerationKey(Guid userId) => $"identity:session-gen:{userId:N}";

    public async Task<(SessionPrincipal? Principal, long Generation)> GetAsync(Guid sessionId, Guid userId, CancellationToken ct = default)
    {
        if (!redis.IsConnected) return (null, Unavailable);
        try
        {
            var values = await redis.GetDatabase().StringGetAsync([EntryKey(sessionId), GenerationKey(userId)]);
            var generation = values[1].HasValue ? (long)values[1] : 0;
            if (!values[0].HasValue) return (null, generation);

            var entry = JsonSerializer.Deserialize<CachedSession>(values[0].ToString());
            return entry is not null && entry.Generation == generation ? (entry.Principal, generation) : (null, generation);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Session cache read failed; validating against the database");
            return (null, Unavailable);
        }
    }

    public async Task SetAsync(SessionPrincipal principal, long generation, TimeSpan ttl, CancellationToken ct = default)
    {
        if (generation == Unavailable || ttl <= TimeSpan.Zero || !redis.IsConnected) return;
        try
        {
            var json = JsonSerializer.Serialize(new CachedSession(principal, generation));
            await redis.GetDatabase().StringSetAsync(EntryKey(principal.SessionId), json, ttl);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Session cache write failed");
        }
    }

    public async Task InvalidateUserAsync(Guid userId, CancellationToken ct = default)
    {
        if (!redis.IsConnected)
        {
            // Nothing can be bumped; whatever is still cached expires within Auth:SessionCacheSeconds.
            logger.LogError("Session cache invalidation skipped for user {UserId}: Redis is not connected", userId);
            return;
        }
        try
        {
            var db = redis.GetDatabase();
            await db.StringIncrementAsync(GenerationKey(userId));
            await db.KeyExpireAsync(GenerationKey(userId), GenerationTtl);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            // The change is already committed; cached sessions of this user may live up to Auth:SessionCacheSeconds.
            logger.LogError(ex, "Session cache invalidation failed for user {UserId}", userId);
        }
    }

    private static bool IsRedisFailure(Exception ex) => ex is RedisException or TimeoutException;

    private sealed record CachedSession(SessionPrincipal Principal, long Generation);
}
