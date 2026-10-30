using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Identity.Api.Extensions;
using Identity.Application.Common;
using Identity.Infrastructure.Security;

namespace Identity.Tests;

public sealed class SecurityConfigurationTests
{
    private static readonly Dictionary<string, string?> SafeProduction = new()
    {
        ["Jwt:SigningKeys:0:PrivateKeyPath"] = "/run/secrets/jwt.pem",
        ["SecretEncryption:Keys:0:KeyId"] = "k1",
        ["SecretEncryption:Keys:0:Key"] = "q8J3v0YkzP5mH1sW2xR7tN4bC6dF9gL0aE3uI8oKx1Y=",
        ["Smtp:Host"] = "smtp.example.com",
        ["Seed:AdminPassword"] = "",
    };

    private static void Validate(Dictionary<string, string?> values, string environment = "Production") =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build()
            .ValidateSecurityConfiguration(new TestEnvironment(environment));

    [Fact]
    public void Safe_production_config_starts() => Validate(SafeProduction);

    [Theory]
    [InlineData("Jwt:SigningKeys:0:PrivateKeyPath", "", "Jwt:SigningKeys")]
    [InlineData("Smtp:Host", "", "Smtp:Host")]
    [InlineData("Seed:AdminPassword", "Admin12345", "Seed:AdminPassword")]
    [InlineData("Seed:AdminPassword", "short1A", "Seed:AdminPassword")]
    public void Unsafe_production_config_refuses_to_start(string key, string value, string expectedInMessage)
    {
        var config = new Dictionary<string, string?>(SafeProduction) { [key] = value };
        var ex = Assert.Throws<InvalidOperationException>(() => Validate(config));
        Assert.Contains(expectedInMessage, ex.Message);
    }

    [Fact]
    public void Development_allows_local_defaults() =>
        Validate(new() { ["Seed:AdminPassword"] = "Admin12345" }, "Development");

    [Fact]
    public void Signing_key_is_required_outside_development() =>
        Assert.Throws<InvalidOperationException>(() =>
            new SigningKeyProvider(Options.Create(new JwtOptions()), new TestEnvironment("Production")));

    [Fact]
    public void Weak_signing_key_is_rejected()
    {
        var weakPem = System.Security.Cryptography.RSA.Create(1024).ExportPkcs8PrivateKeyPem();
        var options = Options.Create(new JwtOptions { SigningKeys = [new SigningKeyOptions { PrivateKeyPem = weakPem }] });
        Assert.Throws<InvalidOperationException>(() => new SigningKeyProvider(options, new TestEnvironment("Production")));
    }

    [Fact]
    public async Task Hasher_returns_503_instead_of_queueing_forever()
    {
        using var hasher = new Argon2PasswordHasher(Options.Create(new PasswordHashingOptions
        {
            MemoryKb = 65536, Iterations = 3, Parallelism = 1, MaxConcurrent = 1, QueueTimeoutSeconds = 0,
        }));

        var first = hasher.HashAsync("Passw0rd!"); // takes the only slot
        await Assert.ThrowsAsync<ServiceUnavailableException>(() => hasher.HashAsync("Passw0rd!"));
        Assert.True(await hasher.VerifyAsync("Passw0rd!", await first));
    }

    private sealed class TestEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "Identity.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
