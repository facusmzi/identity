using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
        services.AddScoped<AuditLogRepository>();
        services.AddScoped<IAuditLogRepository>(sp => sp.GetRequiredService<AuditLogRepository>());

        // Security
        services.AddSingleton<SigningKeyProvider>();
        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.AddSingleton<ITokenService, JwtTokenService>();

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

        // Retention
        services.AddScoped<RetentionCleanup>();
        services.AddHostedService<RetentionCleanupService>();

        return services;
    }
}
