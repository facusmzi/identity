using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Identity.Application.Options;
using Identity.Application.Services;

namespace Identity.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services, IConfiguration config)
    {
        services.Configure<AuthOptions>(config.GetSection(AuthOptions.Section));
        services.Configure<MfaOptions>(config.GetSection(MfaOptions.Section));
        services.Configure<BreachCheckOptions>(config.GetSection(BreachCheckOptions.Section));
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuthService>();
        services.AddScoped<SessionService>();
        services.AddScoped<AdminService>();
        services.AddScoped<AuditTrail>();
        services.AddScoped<PasswordPolicy>();
        services.AddScoped<SecondFactor>();
        services.AddScoped<MfaService>();
        services.AddSingleton<ClientRegistry>();
        services.AddSingleton<IdentityMetrics>();
        services.AddScoped<IntrospectionService>();
        return services;
    }
}
