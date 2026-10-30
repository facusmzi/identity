using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Identity.Application.Abstractions.Security;
using Identity.Application.Options;

namespace Identity.Infrastructure.Caching;

/// <summary>
/// Per-account lockout shared by every instance. If Redis is down it fails OPEN (nobody is locked, failures are not
/// counted): the per-IP rate limit and Argon2's cost still slow attackers down, and the alternative would be locking
/// every user out of the service.
/// </summary>
public sealed class RedisLoginThrottle(IConnectionMultiplexer redis, IOptions<AuthOptions> options, ILogger<RedisLoginThrottle> logger)
    : ILoginThrottle
{
    private const string Feature = "account lockout";
    private readonly AuthOptions _opt = options.Value;

    // Emails are hashed so Redis never holds personal data.
    private static string Id(string email) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(email)));
    private static RedisKey FailuresKey(string email) => $"identity:login-fail:{Id(email)}";
    private static RedisKey LockKey(string email) => $"identity:login-lock:{Id(email)}";

    public Task<TimeSpan?> GetLockoutAsync(string email, CancellationToken ct = default) =>
        RedisGuard.RunAsync<TimeSpan?>(redis, logger, Feature, null, db => db.KeyTimeToLiveAsync(LockKey(email)));

    public Task<bool> RegisterFailureAsync(string email, CancellationToken ct = default) =>
        RedisGuard.RunAsync(redis, logger, Feature, false, async db =>
        {
            var failures = await db.StringIncrementAsync(FailuresKey(email));
            if (failures == 1)
                await db.KeyExpireAsync(FailuresKey(email), TimeSpan.FromMinutes(_opt.LoginFailureWindowMinutes));

            if (failures < _opt.LoginMaxFailures) return false;

            await db.StringSetAsync(LockKey(email), "1", TimeSpan.FromMinutes(_opt.LoginLockoutMinutes));
            await db.KeyDeleteAsync(FailuresKey(email));
            return true;
        });

    public Task ResetAsync(string email, CancellationToken ct = default) =>
        RedisGuard.RunAsync(redis, logger, Feature, db => db.KeyDeleteAsync([FailuresKey(email), LockKey(email)]));
}
