using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;
using Identity.Application.Abstractions.Messaging;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Infrastructure.Caching;
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

        // Security
        services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.AddSingleton<ITokenService, JwtTokenService>();

        // Redis
        services.AddSingleton<IConnectionMultiplexer>(_ =>
            ConnectionMultiplexer.Connect(config.GetConnectionString("Redis") ?? "localhost:6379"));
        services.AddSingleton<IRefreshGraceStore, RedisRefreshGraceStore>();
        services.AddSingleton<ILoginThrottle, RedisLoginThrottle>();

        // Email
        if (string.IsNullOrWhiteSpace(config[$"{SmtpOptions.Section}:Host"]))
            services.AddSingleton(sp => new EmailTransport(ActivatorUtilities.CreateInstance<LoggingEmailSender>(sp)));
        else
            services.AddSingleton(sp => new EmailTransport(ActivatorUtilities.CreateInstance<SmtpEmailSender>(sp)));
        services.AddSingleton<EmailQueue>();
        services.AddSingleton<IEmailSender, QueuedEmailSender>();
        services.AddHostedService<EmailDispatcher>();

        return services;
    }
}
