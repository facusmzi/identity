using System.Text.Json;
using StackExchange.Redis;
using Identity.Application.Abstractions.Security;
using Identity.Application.Dtos;

namespace Identity.Infrastructure.Caching;

public sealed class RedisRefreshGraceStore(IConnectionMultiplexer redis) : IRefreshGraceStore
{
    private static string Key(string oldHash) => $"identity:refresh-grace:{oldHash}";

    public async Task<AuthTokensResponse?> GetAsync(string oldRefreshTokenHash, CancellationToken ct = default)
    {
        var value = await redis.GetDatabase().StringGetAsync(Key(oldRefreshTokenHash));
        return value.IsNullOrEmpty ? null : JsonSerializer.Deserialize<AuthTokensResponse>(value.ToString());
    }

    public Task SetAsync(string oldRefreshTokenHash, AuthTokensResponse tokens, TimeSpan ttl, CancellationToken ct = default) =>
        redis.GetDatabase().StringSetAsync(Key(oldRefreshTokenHash), JsonSerializer.Serialize(tokens), ttl);
}
