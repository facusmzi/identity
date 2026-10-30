using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Identity.Application.Dtos;
using Identity.Application.Security;
using Identity.Application.Services;

namespace Identity.Tests;

public sealed class ClientAndIntrospectionTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private const string Password = "Passw0rd!";

    private static string NewEmail() => $"client-{Guid.NewGuid():N}@test.local";

    private async Task<(string Email, AuthTokensResponse Tokens)> LoginAsync(string? clientId)
    {
        var email = NewEmail();
        await factory.CreateVerifiedUserAsync(email, Password);
        var res = await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = Password, clientId });
        res.EnsureSuccessStatusCode();
        return (email, (await res.Content.ReadFromJsonAsync<AuthTokensResponse>())!);
    }

    private async Task<HttpResponseMessage> IntrospectAsync(string token, string clientId = TestHostFactory.StoreClientId,
        string secret = TestHostFactory.StoreSecret)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/auth/introspect") { Content = JsonContent.Create(new { token }) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{secret}")));
        return await factory.CreateClient().SendAsync(req);
    }

    [Fact]
    public async Task Each_client_gets_tokens_for_its_own_audience_and_keeps_it_on_refresh()
    {
        var (_, store) = await LoginAsync(TestHostFactory.StoreClientId);
        Assert.Equal([TestHostFactory.StoreAudience], MfaTests.TokenClaims(store.AccessToken, "aud"));

        var client = factory.CreateClient();
        var refreshed = await RefreshReuseTests.Refresh(client, store.RefreshToken);
        Assert.Equal([TestHostFactory.StoreAudience], MfaTests.TokenClaims(refreshed.AccessToken, "aud"));

        // This service still accepts it.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);

        var (_, noClient) = await LoginAsync(null);
        Assert.Equal(["identity"], MfaTests.TokenClaims(noClient.AccessToken, "aud"));
    }

    [Fact]
    public async Task Unknown_clients_are_rejected_at_login()
    {
        var email = NewEmail();
        await factory.CreateVerifiedUserAsync(email, Password);
        var res = await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = Password, clientId = "nope" });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Contains("UNKNOWN_CLIENT", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_client_survives_the_mfa_step()
    {
        var email = NewEmail();
        var (owner, _) = await factory.CreateVerifiedUserAsync(email, Password);
        var setup = await (await owner.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        await owner.PostAsJsonAsync("/auth/mfa/enable", new { code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow)) });

        var client = factory.CreateClient();
        var first = await (await client.PostAsJsonAsync("/auth/login", new { email, password = Password, clientId = "mobile" }))
            .Content.ReadFromJsonAsync<LoginResponse>();
        var second = await (await client.PostAsJsonAsync("/auth/login/mfa",
                new { mfaToken = first!.MfaToken, code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow) + 1) }))
            .Content.ReadFromJsonAsync<AuthTokensResponse>();

        Assert.Equal(["mobile-api"], MfaTests.TokenClaims(second!.AccessToken, "aud"));
    }

    [Fact]
    public async Task Introspection_reports_live_sessions_and_sees_revocations_at_once()
    {
        var (email, tokens) = await LoginAsync(TestHostFactory.StoreClientId);

        var active = await (await IntrospectAsync(tokens.AccessToken)).Content.ReadFromJsonAsync<IntrospectionResponse>();
        Assert.True(active!.Active);
        Assert.Equal(TestHostFactory.StoreAudience, active.Aud);
        Assert.Contains("User", active.Roles!);
        Assert.True(active.Exp > DateTimeOffset.UtcNow.ToUnixTimeSeconds());

        // Logout everywhere: the JWT is still unexpired, but introspection knows better.
        var owner = factory.CreateClient();
        await IdentityFactory.LoginAsync(owner, email, Password);
        await owner.PostAsync("/auth/logout-all", null);

        var after = await (await IntrospectAsync(tokens.AccessToken)).Content.ReadFromJsonAsync<IntrospectionResponse>();
        Assert.False(after!.Active);
        Assert.Null(after.Sub);
    }

    [Fact]
    public async Task Clients_only_see_their_own_tokens_and_must_authenticate()
    {
        var (_, mobile) = await LoginAsync("mobile");
        var foreign = await (await IntrospectAsync(mobile.AccessToken)).Content.ReadFromJsonAsync<IntrospectionResponse>();
        Assert.False(foreign!.Active);

        var garbage = await (await IntrospectAsync("not.a.jwt")).Content.ReadFromJsonAsync<IntrospectionResponse>();
        Assert.False(garbage!.Active);

        var badSecret = await IntrospectAsync(mobile.AccessToken, secret: "wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, badSecret.StatusCode);
        Assert.Equal("Basic", badSecret.Headers.WwwAuthenticate.Single().Scheme);

        // A public client (no secret) cannot introspect at all.
        Assert.Equal(HttpStatusCode.Unauthorized, (await IntrospectAsync(mobile.AccessToken, "mobile", "")).StatusCode);
        var none = await factory.CreateClient().PostAsJsonAsync("/auth/introspect", new { token = mobile.AccessToken });
        Assert.Equal(HttpStatusCode.Unauthorized, none.StatusCode);
    }
}
