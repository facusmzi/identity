using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using Identity.Application.Abstractions.Messaging;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Infrastructure.Caching;
using Identity.Infrastructure.Maintenance;
using Identity.Infrastructure.Messaging;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Persistence.Interceptors;
using Identity.Infrastructure.Persistence.Repositories;
using Identity.Infrastructure.Security;

namespace Identity.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.Configure<JwtOptions>(config.GetSection(JwtOptions.Section));
        services.Configure<PasswordHashingOptions>(config.GetSection(PasswordHashingOptions.Section));
        services.Configure<SmtpOptions>(config.GetSection(SmtpOptions.Section));
        services.Configure<OutboxOptions>(config.GetSection(OutboxOptions.Section));
        services.Configure<RetentionOptions>(config.GetSection(RetentionOptions.Section));
        services.Configure<SecretEncryptionOptions>(config.GetSection(SecretEncryptionOptions.Section));
        services.Configure<HibpClientOptions>(config.GetSection(HibpClientOptions.Section));

        // Persistence
        services.AddSingleton<AuditAndSoftDeleteInterceptor>();
        services.AddDbContext<AppDbContext>((sp, options) => options
            .UseNpgsql(config.GetConnectionString("Postgres"))
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(sp.GetRequiredService<AuditAndSoftDeleteInterceptor>()));
        services.AddScoped<IUnitOfWork>(sp => sp.GetRequiredService<AppDbContext>());
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<ISessionRepository, SessionRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IMfaRepository, MfaRepository>();
        services.AddScoped<AuditLogRepository>();
        services.AddScoped<IAuditLogRepository>(sp => sp.GetRequiredService<AuditLogRepository>());

        // Security
        services.AddSingleton<SigningKeyProvider>();
        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.AddSingleton<ITokenService, JwtTokenService>();
        services.AddSingleton<ISecretProtector, AesGcmSecretProtector>();

        // Have I Been Pwned: short timeout, retries and a circuit breaker; failures become "Unavailable".
        var hibp = services.AddHttpClient<IPasswordBreachChecker, HibpPasswordBreachChecker>((sp, client) =>
            {
                client.BaseAddress = new Uri(sp.GetRequiredService<IOptions<HibpClientOptions>>().Value.BaseUrl);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Identity-Service/1.0");
            })
            .AddStandardResilienceHandler();
        services.AddOptions<HttpStandardResilienceOptions>(hibp.PipelineName).Configure<IOptions<HibpClientOptions>>((o, h) =>
        {
            var timeout = TimeSpan.FromSeconds(Math.Max(1, h.Value.TimeoutSeconds));
            o.AttemptTimeout.Timeout = timeout;
            o.TotalRequestTimeout.Timeout = timeout * 2;
            o.CircuitBreaker.SamplingDuration = timeout * 4;
        });

        // Redis (not aborting on connect failure lets the API start and report it through /health/ready)
        services.AddSingleton<IConnectionMultiplexer>(_ =>
        {
            var options = ConfigurationOptions.Parse(config.GetConnectionString("Redis") ?? "localhost:6379");
            options.AbortOnConnectFail = false;
            return ConnectionMultiplexer.Connect(options);
        });
        services.AddSingleton<IRefreshGraceStore, RedisRefreshGraceStore>();
        services.AddSingleton<ILoginThrottle, RedisLoginThrottle>();
        services.AddSingleton<ISessionCache, RedisSessionCache>();

        // Email: transactional outbox + background delivery
        if (string.IsNullOrWhiteSpace(config[$"{SmtpOptions.Section}:Host"]))
            services.AddSingleton<IEmailTransport, LoggingEmailSender>();
        else
            services.AddSingleton<IEmailTransport, SmtpEmailSender>();
        services.AddScoped<IEmailOutbox, EfEmailOutbox>();
        services.AddScoped<OutboxProcessor>();
        services.AddHostedService<OutboxDispatcher>();

        // Account events for client webhooks: same outbox pattern, signed HMAC-SHA256.
        services.AddSingleton<OutboxBacklog>();
        services.AddScoped<IAccountEvents, EfAccountEvents>();
        services.AddScoped<WebhookProcessor>();
        services.AddHttpClient(WebhookProcessor.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10));
        services.AddHostedService<WebhookDispatcher>();

        // Retention
        services.AddScoped<RetentionCleanup>();
        services.AddHostedService<RetentionCleanupService>();

        return services;
    }
}
