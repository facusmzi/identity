using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.HttpOverrides;
using Identity.Application.Dtos;

namespace Identity.Api.Extensions;

public static class SecurityConfigurationExtensions
{
    private static readonly string[] DevSecretMarkers = ["dev-only", "change-me", "changeme", "secret-secret"];

    /// <summary>
    /// Refuses to start outside Development/Testing with settings that are only acceptable locally:
    /// a placeholder JWT secret, no SMTP (codes would end up in the logs) or a weak seeded admin password.
    /// </summary>
    public static void ValidateSecurityConfiguration(this IConfiguration config, IHostEnvironment env)
    {
        if (env.IsDevelopment() || env.IsEnvironment("Testing")) return;

        var errors = new List<string>();

        var secret = config["Jwt:Secret"] ?? "";
        if (DevSecretMarkers.Any(m => secret.Contains(m, StringComparison.OrdinalIgnoreCase)))
            errors.Add("Jwt:Secret looks like a development placeholder; generate a random one (e.g. `openssl rand -base64 48`).");

        if (string.IsNullOrWhiteSpace(config["Smtp:Host"]))
            errors.Add("Smtp:Host is empty; verification codes and reset tokens would only be written to the logs.");

        var adminPassword = config["Seed:AdminPassword"];
        if (!string.IsNullOrEmpty(adminPassword)
            && (adminPassword.Length < 12 || adminPassword == "Admin12345" || !Regex.IsMatch(adminPassword, PasswordRules.Pattern)))
            errors.Add("Seed:AdminPassword is too weak for this environment (min 12 chars, upper, lower and a digit), or leave Seed empty.");

        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"Insecure configuration for environment '{env.EnvironmentName}':\n - " + string.Join("\n - ", errors));
    }

    /// <summary>
    /// Trusts X-Forwarded-For/Proto only from the proxies listed in ForwardedHeaders:KnownProxies / KnownNetworks.
    /// With none configured the headers are ignored, so clients cannot spoof their IP to dodge the rate limiter.
    /// </summary>
    public static IServiceCollection AddTrustedProxies(this IServiceCollection services, IConfiguration config)
    {
        var proxies = config.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
        var networks = config.GetSection("ForwardedHeaders:KnownNetworks").Get<string[]>() ?? [];

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = config.GetValue("ForwardedHeaders:ForwardLimit", 1);
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();
            foreach (var proxy in proxies) options.KnownProxies.Add(IPAddress.Parse(proxy));
            foreach (var network in networks) options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
        });
        return services;
    }

    public static bool HasTrustedProxies(this IConfiguration config) =>
        config.GetSection("ForwardedHeaders:KnownProxies").GetChildren().Any()
        || config.GetSection("ForwardedHeaders:KnownNetworks").GetChildren().Any();
}
