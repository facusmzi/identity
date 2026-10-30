using System.Text.Json;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using Identity.Application.Abstractions.Security;
using Identity.Application.Dtos;

namespace Identity.Infrastructure.Caching;

/// <summary>
/// Grace window for concurrent refreshes. If Redis is down the window simply does not exist: refreshing still
/// works, but of several simultaneous refreshes with the same token only one wins and the others get a 401
/// (never a revocation, see AuthService). Safe, just less forgiving.
/// </summary>
public sealed class RedisRefreshGraceStore(IConnectionMultiplexer redis, ILogger<RedisRefreshGraceStore> logger) : IRefreshGraceStore
{
    private const string Feature = "refresh grace window";

    private static string Key(string oldHash) => $"identity:refresh-grace:{oldHash}";

    public Task<AuthTokensResponse?> GetAsync(string oldRefreshTokenHash, CancellationToken ct = default) =>
        RedisGuard.RunAsync<AuthTokensResponse?>(redis, logger, Feature, null, async db =>
        {
            var value = await db.StringGetAsync(Key(oldRefreshTokenHash));
            return value.IsNullOrEmpty ? null : JsonSerializer.Deserialize<AuthTokensResponse>(value.ToString());
        });

    public Task SetAsync(string oldRefreshTokenHash, AuthTokensResponse tokens, TimeSpan ttl, CancellationToken ct = default) =>
        RedisGuard.RunAsync(redis, logger, Feature, db => db.StringSetAsync(Key(oldRefreshTokenHash), JsonSerializer.Serialize(tokens), ttl));
}
