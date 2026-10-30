using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.HttpOverrides;
using Identity.Application.Dtos;

namespace Identity.Api.Extensions;

public static class SecurityConfigurationExtensions
{
    /// <summary>
    /// Refuses to start outside Development/Testing with settings that are only acceptable locally:
    /// no configured signing key, no SMTP (codes would end up in the logs) or a weak seeded admin password.
    /// </summary>
    public static void ValidateSecurityConfiguration(this IConfiguration config, IHostEnvironment env)
    {
        if (env.IsDevelopment() || env.IsEnvironment("Testing")) return;

        var errors = new List<string>();

        var hasSigningKey = config.GetSection("Jwt:SigningKeys").GetChildren()
            .Any(k => !string.IsNullOrWhiteSpace(k["PrivateKeyPem"]) || !string.IsNullOrWhiteSpace(k["PrivateKeyPath"]));
        if (!hasSigningKey)
            errors.Add("Jwt:SigningKeys is empty; provide an RSA private key (PEM) via Jwt__SigningKeys__0__PrivateKeyPath "
                       + "(e.g. `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out jwt.pem`).");

        var hasEncryptionKey = config.GetSection("SecretEncryption:Keys").GetChildren()
            .Any(k => !string.IsNullOrWhiteSpace(k["Key"]));
        if (!hasEncryptionKey)
            errors.Add("SecretEncryption:Keys is empty; it encrypts the TOTP secrets. Provide SecretEncryption__Keys__0__KeyId and "
                       + "SecretEncryption__Keys__0__Key (32 random bytes, base64: `openssl rand -base64 32`).");

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
