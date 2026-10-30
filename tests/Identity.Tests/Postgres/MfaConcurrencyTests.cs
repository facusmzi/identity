using System.Net;
using System.Net.Http.Json;
using Identity.Application.Dtos;
using Identity.Application.Security;

namespace Identity.Tests.Postgres;

/// <summary>"Each code works once" must hold when the same code arrives on several requests at the same time.</summary>
[Collection(PostgresCollection.Name)]
[Trait("Category", "Postgres")]
public sealed class MfaConcurrencyTests(PostgresFixture fixture)
{
    private static string NewEmail() => $"pg-mfa-{Guid.NewGuid():N}@test.local";

    private static async Task<(byte[] Secret, IReadOnlyList<string> Codes)> EnableAsync(TestHostFactory factory, string email)
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(email);
        var setup = await (await client.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        var enable = await client.PostAsJsonAsync("/auth/mfa/enable", new { code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow)) });
        return (secret, (await enable.Content.ReadFromJsonAsync<RecoveryCodesResponse>())!.RecoveryCodes);
    }

    private static async Task<List<string>> ChallengesAsync(TestHostFactory factory, string email, int count)
    {
        var tokens = new List<string>();
        for (var i = 0; i < count; i++)
        {
            var res = await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" });
            tokens.Add((await res.Content.ReadFromJsonAsync<LoginResponse>())!.MfaToken!);
        }
        return tokens;
    }

    [SkippableFact]
    public async Task The_same_totp_code_on_parallel_logins_succeeds_exactly_once()
    {
        var factory = fixture.Require();
        var email = NewEmail();
        var (secret, _) = await EnableAsync(factory, email);
        var code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow) + 1);
        var challenges = await ChallengesAsync(factory, email, 8);

        var results = await Task.WhenAll(challenges.Select(t =>
            factory.CreateClient().PostAsJsonAsync("/auth/login/mfa", new { mfaToken = t, code })));

        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.All(results.Where(r => r.StatusCode != HttpStatusCode.OK), r => Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode));
    }

    [SkippableFact]
    public async Task The_same_recovery_code_on_parallel_logins_succeeds_exactly_once()
    {
        var factory = fixture.Require();
        var email = NewEmail();
        var (_, codes) = await EnableAsync(factory, email);
        var challenges = await ChallengesAsync(factory, email, 8);

        var results = await Task.WhenAll(challenges.Select(t =>
            factory.CreateClient().PostAsJsonAsync("/auth/login/mfa", new { mfaToken = t, recoveryCode = codes[0] })));

        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
    }
}
