using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Identity.Application.Abstractions.Security;
using Identity.Application.Options;

namespace Identity.Infrastructure.Caching;

public sealed class RedisLoginThrottle(IConnectionMultiplexer redis, IOptions<AuthOptions> options) : ILoginThrottle
{
    private readonly AuthOptions _opt = options.Value;

    // Emails are hashed so Redis never holds personal data.
    private static string Id(string email) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(email)));
    private static RedisKey FailuresKey(string email) => $"identity:login-fail:{Id(email)}";
    private static RedisKey LockKey(string email) => $"identity:login-lock:{Id(email)}";

    public async Task<TimeSpan?> GetLockoutAsync(string email, CancellationToken ct = default) =>
        await redis.GetDatabase().KeyTimeToLiveAsync(LockKey(email));

    public async Task RegisterFailureAsync(string email, CancellationToken ct = default)
    {
        var db = redis.GetDatabase();
        var failures = await db.StringIncrementAsync(FailuresKey(email));
        if (failures == 1)
            await db.KeyExpireAsync(FailuresKey(email), TimeSpan.FromMinutes(_opt.LoginFailureWindowMinutes));

        if (failures >= _opt.LoginMaxFailures)
        {
            await db.StringSetAsync(LockKey(email), "1", TimeSpan.FromMinutes(_opt.LoginLockoutMinutes));
            await db.KeyDeleteAsync(FailuresKey(email));
        }
    }

    public Task ResetAsync(string email, CancellationToken ct = default) =>
        redis.GetDatabase().KeyDeleteAsync([FailuresKey(email), LockKey(email)]);
}
