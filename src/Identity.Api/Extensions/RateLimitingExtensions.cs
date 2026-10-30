using System.Threading.RateLimiting;

namespace Identity.Api.Extensions;

public static class RateLimitingExtensions
{
    /// <summary>Register / resend-verification: 5 requests per minute per IP.</summary>
    public const string Strict = "auth-strict";

    /// <summary>Login / refresh: 10 requests per minute per IP.</summary>
    public const string Default = "auth";

    public static IServiceCollection AddAuthRateLimiting(this IServiceCollection services, IConfiguration config)
    {
        var strictLimit = config.GetValue("RateLimiting:StrictPermitLimit", 5);
        var defaultLimit = config.GetValue("RateLimiting:PermitLimit", 10);

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(Strict, ctx => PerIp(ctx, strictLimit));
            options.AddPolicy(Default, ctx => PerIp(ctx, defaultLimit));
        });
        return services;
    }

    private static RateLimitPartition<string> PerIp(HttpContext ctx, int limit) =>
        RateLimitPartition.GetFixedWindowLimiter(
            ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = limit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
}
