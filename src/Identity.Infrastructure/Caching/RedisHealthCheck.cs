using Microsoft.Extensions.Diagnostics.HealthChecks;
using StackExchange.Redis;

namespace Identity.Infrastructure.Caching;

public sealed class RedisHealthCheck(IConnectionMultiplexer redis) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            var latency = await redis.GetDatabase().PingAsync();
            return HealthCheckResult.Healthy($"ping {latency.TotalMilliseconds:F0} ms");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Redis unreachable", ex);
        }
    }
}
