using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Dtos;
using Identity.Application.Security;
using Identity.Infrastructure.Security;

namespace Identity.Tests;

public sealed class MfaTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private const string Password = "Passw0rd!";

    private static string NewEmail() => $"mfa-{Guid.NewGuid():N}@test.local";

    /// <summary>
    /// Codes for the current step are consumed by "enable"; tests use the next step, which the one-step drift
    /// window accepts, so they never need to wait 30 s.
    /// </summary>
    private static string CodeAt(byte[] secret, int stepsFromNow) =>
        Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow) + stepsFromNow);

    private async Task<(HttpClient Client, byte[] Secret, IReadOnlyList<string> RecoveryCodes)> EnableMfaAsync(string email)
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(email, Password);
        var setup = await (await client.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        Assert.Contains("otpauth://totp/", setup.OtpAuthUri);

        var enable = await client.PostAsJsonAsync("/auth/mfa/enable", new { code = CodeAt(secret, 0) });
        Assert.Equal(HttpStatusCode.OK, enable.StatusCode);
        var codes = (await enable.Content.ReadFromJsonAsync<RecoveryCodesResponse>())!.RecoveryCodes;
        return (client, secret, codes);
    }

    private static async Task<LoginResponse> PasswordStepAsync(HttpClient client, string email)
    {
        var res = await client.PostAsJsonAsync("/auth/login", new { email, password = Password });
        res.EnsureSuccessStatusCode();
        return (await res.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    [Fact]
    public async Task Login_requires_the_second_factor_and_marks_the_token()
    {
        var email = NewEmail();
        var (_, secret, codes) = await EnableMfaAsync(email);
        Assert.Equal(10, codes.Count);

        var client = factory.CreateClient();
        var first = await PasswordStepAsync(client, email);
        Assert.True(first.MfaRequired);
        Assert.Null(first.AccessToken);
        Assert.NotNull(first.MfaToken);

        var second = await client.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = first.MfaToken, code = CodeAt(secret, 1) });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var tokens = (await second.Content.ReadFromJsonAsync<AuthTokensResponse>())!;

        Assert.Contains("mfa", Claims(tokens.AccessToken, "amr"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.True((await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.MfaEnabled);

        // The challenge is single-use.
        var again = await client.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = first.MfaToken, code = CodeAt(secret, 1) });
        Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode);
    }

    [Fact]
    public async Task A_totp_code_cannot_be_replayed_even_within_its_window()
    {
        var email = NewEmail();
        var (_, secret, _) = await EnableMfaAsync(email);
        var code = CodeAt(secret, 1);

        var a = factory.CreateClient();
        var firstLogin = await PasswordStepAsync(a, email);
        Assert.Equal(HttpStatusCode.OK,
            (await a.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = firstLogin.MfaToken, code })).StatusCode);

        // Same code, fresh challenge (e.g. an attacker who sniffed it): rejected.
        var b = factory.CreateClient();
        var secondLogin = await PasswordStepAsync(b, email);
        var replay = await b.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = secondLogin.MfaToken, code });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Contains("MFA_INVALID", await replay.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Recovery_codes_work_once_and_trigger_a_notice()
    {
        var email = NewEmail();
        var (_, _, codes) = await EnableMfaAsync(email);
        var client = factory.CreateClient();

        var login = await PasswordStepAsync(client, email);
        var ok = await client.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = login.MfaToken, recoveryCode = codes[0].ToUpperInvariant() });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var relogin = await PasswordStepAsync(client, email);
        var reuse = await client.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = relogin.MfaToken, recoveryCode = codes[0] });
        Assert.Equal(HttpStatusCode.Unauthorized, reuse.StatusCode);

        await factory.DispatchEmailsAsync();
        Assert.Contains("A recovery code was used", factory.Emails.NoticesFor(email));
        Assert.Contains("Two-factor authentication enabled", factory.Emails.NoticesFor(email));
    }

    [Fact]
    public async Task A_challenge_dies_after_too_many_wrong_codes()
    {
        var email = NewEmail();
        var (_, secret, _) = await EnableMfaAsync(email);
        var client = factory.CreateClient();
        var login = await PasswordStepAsync(client, email);

        for (var i = 0; i < 5; i++)
            await client.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = login.MfaToken, code = "000000" == CodeAt(secret, 1) ? "111111" : "000000" });

        var correct = await client.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = login.MfaToken, code = CodeAt(secret, 1) });
        Assert.Equal(HttpStatusCode.Unauthorized, correct.StatusCode);
    }

    [Fact]
    public async Task Enabling_revokes_other_sessions_and_the_secret_is_stored_encrypted()
    {
        var email = NewEmail();
        var other = factory.CreateClient();
        var (client, _) = await factory.CreateVerifiedUserAsync(email, Password);
        await IdentityFactory.LoginAsync(other, email, Password);

        var setup = await (await client.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        await client.PostAsJsonAsync("/auth/mfa/enable", new { code = CodeAt(secret, 0) });

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/auth/me")).StatusCode);

        var stored = await factory.WithDbAsync(db => db.Users.SingleAsync(u => u.Email == email));
        Assert.StartsWith("v1.", stored.MfaSecretEncrypted);
        Assert.DoesNotContain(setup.Secret.Replace(" ", ""), stored.MfaSecretEncrypted!, StringComparison.OrdinalIgnoreCase);
        Assert.Null(stored.MfaPendingSecretEncrypted);
        Assert.Equal(10, await factory.WithDbAsync(db => db.MfaRecoveryCodes.CountAsync(c => c.UserId == stored.Id)));
        Assert.DoesNotContain(await factory.WithDbAsync(db => db.MfaRecoveryCodes.Select(c => c.CodeHash).ToListAsync()),
            h => h.Contains('-'));
    }

    [Fact]
    public async Task Disabling_needs_password_and_a_code_then_login_is_single_step_again()
    {
        var email = NewEmail();
        var (client, secret, _) = await EnableMfaAsync(email);

        var noPassword = await client.PostAsJsonAsync("/auth/mfa/disable", new { password = "Wrong123x", code = CodeAt(secret, 1) });
        Assert.Equal(HttpStatusCode.BadRequest, noPassword.StatusCode);

        var disable = await client.PostAsJsonAsync("/auth/mfa/disable", new { password = Password, code = CodeAt(secret, 1) });
        Assert.Equal(HttpStatusCode.NoContent, disable.StatusCode);

        var login = await PasswordStepAsync(factory.CreateClient(), email);
        Assert.False(login.MfaRequired);
        Assert.NotNull(login.AccessToken);
        Assert.Equal(0, await factory.WithDbAsync(db => db.MfaRecoveryCodes.CountAsync(c => c.User.Email == email)));
    }

    [Fact]
    public async Task Wrong_codes_in_management_count_towards_the_lockout()
    {
        var email = NewEmail();
        var (client, _, _) = await EnableMfaAsync(email);

        for (var i = 0; i < 10; i++)
            await client.PostAsJsonAsync("/auth/mfa/recovery-codes", new { code = "000000" });

        var locked = await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
    }

    private static IReadOnlyList<string> Claims(string jwt, string name)
    {
        var payload = JsonDocument.Parse(Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(jwt.Split('.')[1])).RootElement;
        if (!payload.TryGetProperty(name, out var value)) return [];
        return value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Select(v => v.GetString()!).ToList() : [value.GetString()!];
    }

    internal static IReadOnlyList<string> TokenClaims(string jwt, string name) => Claims(jwt, name);
}
