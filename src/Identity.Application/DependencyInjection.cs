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
        services.AddSingleton(TimeProvider.System);
        services.AddScoped<AuthService>();
        services.AddScoped<SessionService>();
        services.AddScoped<AdminService>();
        return services;
    }
}
