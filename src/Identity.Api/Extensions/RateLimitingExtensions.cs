using System.Threading.RateLimiting;
using StackExchange.Redis;

namespace Identity.Api.Extensions;

public static class RateLimitingExtensions
{
    /// <summary>Register / resend-verification / forgot-password: 5 requests per minute per IP.</summary>
    public const string Strict = "auth-strict";

    /// <summary>Login / refresh / verify / reset / MFA / introspection: 10 requests per minute per IP.</summary>
    public const string Default = "auth";

    /// <summary>
    /// Per-IP limits counted in Redis (RateLimiting:Distributed, default true), so they hold across instances;
    /// with Redis down each instance counts on its own. Rejections answer 429 with Retry-After.
    /// </summary>
    public static IServiceCollection AddAuthRateLimiting(this IServiceCollection services, IConfiguration _)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = (context, _) =>
            {
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();
                return ValueTask.CompletedTask;
            };
            options.AddPolicy(Strict, ctx => PerIp(ctx, Strict, "RateLimiting:StrictPermitLimit", 5));
            options.AddPolicy(Default, ctx => PerIp(ctx, Default, "RateLimiting:PermitLimit", 10));
        });
        return services;
    }

    // Settings are read from the final configuration (not at registration time), once per partition.
    private static RateLimitPartition<string> PerIp(HttpContext ctx, string policy, string limitKey, int defaultLimit)
    {
        var config = ctx.RequestServices.GetRequiredService<IConfiguration>();
        var limit = config.GetValue(limitKey, defaultLimit);
        var distributed = config.GetValue("RateLimiting:Distributed", true);
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var window = TimeSpan.FromMinutes(1);
        if (!distributed)
            return RateLimitPartition.GetFixedWindowLimiter(ip,
                _ => new FixedWindowRateLimiterOptions { PermitLimit = limit, Window = window, QueueLimit = 0 });

        var services = ctx.RequestServices;
        return RateLimitPartition.Get(ip, key => new RedisFixedWindowRateLimiter(
            services.GetRequiredService<IConnectionMultiplexer>(), $"{policy}:{key}", limit, window,
            services.GetRequiredService<TimeProvider>()));
    }
}
