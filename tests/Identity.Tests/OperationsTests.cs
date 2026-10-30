using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Tests;

public sealed class OperationsTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Another_service_can_validate_tokens_with_only_the_jwks()
    {
        var (_, tokens) = await factory.CreateVerifiedUserAsync(NewEmail());
        var client = factory.CreateClient();

        var jwksJson = await client.GetStringAsync("/.well-known/jwks.json");
        Assert.DoesNotContain("\"d\"", jwksJson); // public halves only
        var jwks = new JsonWebKeySet(jwksJson);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(tokens.AccessToken, new TokenValidationParameters
        {
            ValidIssuer = "identity",
            ValidAudience = "identity",
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        });
        Assert.True(result.IsValid, result.Exception?.Message);

        var discovery = await client.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration");
        Assert.EndsWith("/.well-known/jwks.json", discovery.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task Tokens_signed_with_another_key_are_rejected()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var forged = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "identity",
            Audience = "identity",
            Claims = new Dictionary<string, object> { ["sub"] = Guid.NewGuid().ToString(), ["sid"] = Guid.NewGuid().ToString(), ["typ"] = "access" },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
        });

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", forged);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Liveness_probe_does_not_depend_on_infrastructure()
    {
        var res = await factory.CreateClient().GetAsync("/health/live");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task Cors_is_closed_by_default_and_open_only_to_configured_origins()
    {
        var closed = await Preflight(factory.CreateClient());
        Assert.False(closed.Headers.Contains("Access-Control-Allow-Origin"));

        using var withCors = factory.WithWebHostBuilder(b => b.UseSetting("Cors:AllowedOrigins:0", "https://app.example.com"));
        var open = await Preflight(withCors.CreateClient());
        Assert.Equal("https://app.example.com", open.Headers.GetValues("Access-Control-Allow-Origin").Single());
    }

    private static Task<HttpResponseMessage> Preflight(HttpClient client)
    {
        var req = new HttpRequestMessage(HttpMethod.Options, "/auth/login");
        req.Headers.Add("Origin", "https://app.example.com");
        req.Headers.Add("Access-Control-Request-Method", "POST");
        return client.SendAsync(req);
    }
}
