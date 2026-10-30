using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Identity.Infrastructure.Caching;
using Identity.Infrastructure.Persistence;

namespace Identity.Api.Extensions;

public static class OperationsExtensions
{
    public const string CorsPolicy = "frontend";
    private const string ReadyTag = "ready";

    /// <summary>
    /// /health/live: the process is up (no dependencies, for restarts).
    /// /health/ready: Postgres and Redis answer (for load balancers / readiness probes).
    /// </summary>
    public static IServiceCollection AddIdentityHealthChecks(this IServiceCollection services)
    {
        services.AddHealthChecks()
            .AddDbContextCheck<AppDbContext>("postgres", tags: [ReadyTag])
            .AddCheck<RedisHealthCheck>("redis", tags: [ReadyTag]);
        return services;
    }

    public static void MapIdentityHealthChecks(this IEndpointRouteBuilder app)
    {
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains(ReadyTag) });
    }

    /// <summary>
    /// Cross-origin access only for the origins in Cors:AllowedOrigins (none by default). Tokens travel in the
    /// Authorization header and request bodies, never in cookies, so credentials are not allowed.
    /// </summary>
    public static IServiceCollection AddFrontendCors(this IServiceCollection services, IConfiguration config)
    {
        var origins = config.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
        services.AddCors(options => options.AddPolicy(CorsPolicy, policy =>
        {
            if (origins.Length == 0) return;
            policy.WithOrigins(origins)
                .WithMethods("GET", "POST", "DELETE")
                .WithHeaders("Authorization", "Content-Type")
                .WithExposedHeaders("Retry-After")
                .SetPreflightMaxAge(TimeSpan.FromHours(1));
        }));
        return services;
    }

    /// <summary>One JSON object per log line outside Development, with scopes (request id, trace id).</summary>
    public static ILoggingBuilder AddStructuredLogging(this ILoggingBuilder logging, IHostEnvironment env)
    {
        if (env.IsDevelopment()) return logging;

        logging.ClearProviders();
        logging.AddJsonConsole(o =>
        {
            o.IncludeScopes = true;
            o.UseUtcTimestamp = true;
            o.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
        });
        return logging;
    }
}
