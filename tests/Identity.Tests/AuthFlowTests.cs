using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Dtos;

namespace Identity.Tests;

public sealed class AuthFlowTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Register_verify_login_me_refresh_logout()
    {
        var email = NewEmail();
        var client = factory.CreateClient();

        var register = await client.PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.Accepted, register.StatusCode);

        var unverified = await client.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.Forbidden, unverified.StatusCode);
        Assert.Contains("EMAIL_NOT_VERIFIED", await unverified.Content.ReadAsStringAsync());

        var verify = await client.PostAsJsonAsync("/auth/verify-email",
            new { email, code = await factory.LastCodeAsync(email), password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);

        var tokens = await IdentityFactory.LoginAsync(client, email, "Passw0rd!");

        var me = await client.GetFromJsonAsync<UserResponse>("/auth/me");
        Assert.Equal(email, me!.Email);
        Assert.True(me.EmailVerified);
        Assert.Equal(["User"], me.Roles);

        // Rotation + grace period: replaying the old refresh token returns the same new pair.
        var refreshed = await Refresh(client, tokens.RefreshToken);
        Assert.NotEqual(tokens.RefreshToken, refreshed.RefreshToken);
        var replay = await Refresh(client, tokens.RefreshToken);
        Assert.Equal(refreshed.RefreshToken, replay.RefreshToken);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", refreshed.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/logout", null)).StatusCode);

        // Revocation is effective immediately even though the JWT is not expired yet.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Register_does_not_reveal_existing_accounts()
    {
        var taken = NewEmail();
        await factory.CreateVerifiedUserAsync(taken);
        var client = factory.CreateClient();

        var forTaken = await client.PostAsJsonAsync("/auth/register", new { email = taken.ToUpperInvariant(), password = "Other123x" });
        var forNew = await client.PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "Other123x" });

        Assert.Equal(forNew.StatusCode, forTaken.StatusCode);
        Assert.Equal(await forNew.Content.ReadAsStringAsync(), await forTaken.Content.ReadAsStringAsync());
        Assert.Equal(1, await factory.WithDbAsync(db => db.Users.CountAsync(u => u.Email == taken)));

        // ...and the original password still works: a verified account is never touched.
        await IdentityFactory.LoginAsync(client, taken, "Passw0rd!");
    }

    [Fact]
    public async Task Resend_and_verify_do_not_reveal_existing_accounts()
    {
        var client = factory.CreateClient();
        var verified = NewEmail();
        await factory.CreateVerifiedUserAsync(verified);
        var unknown = NewEmail();

        var resendVerified = await client.PostAsJsonAsync("/auth/resend-verification", new { email = verified });
        var resendUnknown = await client.PostAsJsonAsync("/auth/resend-verification", new { email = unknown });
        Assert.Equal(HttpStatusCode.OK, resendVerified.StatusCode);
        Assert.Equal(await resendUnknown.Content.ReadAsStringAsync(), await resendVerified.Content.ReadAsStringAsync());

        var verifyVerified = await client.PostAsJsonAsync("/auth/verify-email", new { email = verified, code = "123456", password = "Passw0rd!" });
        var verifyUnknown = await client.PostAsJsonAsync("/auth/verify-email", new { email = unknown, code = "123456", password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.BadRequest, verifyVerified.StatusCode);
        Assert.Equal(verifyUnknown.StatusCode, verifyVerified.StatusCode);
        Assert.Equal(await ProblemOf(verifyUnknown), await ProblemOf(verifyVerified));
    }

    // Problem details minus traceId, which differs per request.
    private static async Task<string> ProblemOf(HttpResponseMessage res)
    {
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        return $"{doc.RootElement.GetProperty("title")}|{doc.RootElement.GetProperty("code")}";
    }

    [Fact]
    public async Task Pre_registered_email_cannot_be_hijacked()
    {
        var email = NewEmail();
        var attacker = factory.CreateClient();
        var victim = factory.CreateClient();

        // The attacker registers the victim's email first, with a password they know.
        await attacker.PostAsJsonAsync("/auth/register", new { email, password = "Attack3r!" });

        // The victim registers later: their password replaces the attacker's and a new code is sent.
        await victim.PostAsJsonAsync("/auth/register", new { email, password = "Victim123" });
        var code = await factory.LastCodeAsync(email);

        // Verifying needs the password chosen at registration, so only the latest registrant can do it.
        var withAttackerPassword = await victim.PostAsJsonAsync("/auth/verify-email", new { email, code, password = "Attack3r!" });
        Assert.Equal(HttpStatusCode.BadRequest, withAttackerPassword.StatusCode);
        var ok = await victim.PostAsJsonAsync("/auth/verify-email", new { email, code, password = "Victim123" });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await attacker.PostAsJsonAsync("/auth/login", new { email, password = "Attack3r!" })).StatusCode);
        await IdentityFactory.LoginAsync(victim, email, "Victim123");
    }

    [Fact]
    public async Task Weak_password_fails_validation()
    {
        var res = await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Verification_attempts_are_locked_and_resending_does_not_reset_them()
    {
        var email = NewEmail();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });
        var code = await factory.LastCodeAsync(email);
        var wrong = code == "000000" ? "111111" : "000000";

        for (var i = 0; i < 10; i++)
            await client.PostAsJsonAsync("/auth/verify-email", new { email, code = wrong, password = "Passw0rd!" });

        var res = await client.PostAsJsonAsync("/auth/verify-email", new { email, code, password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.TooManyRequests, res.StatusCode);
        Assert.True(res.Headers.RetryAfter is not null);

        // Asking for a new code does not reset the counter, so resending cannot be used to brute-force it.
        await client.PostAsJsonAsync("/auth/resend-verification", new { email });
        var stillLocked = await client.PostAsJsonAsync("/auth/verify-email",
            new { email, code = await factory.LastCodeAsync(email), password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.TooManyRequests, stillLocked.StatusCode);
    }

    [Fact]
    public async Task Verification_emails_are_capped_per_window()
    {
        var email = NewEmail();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" }); // send #1

        for (var i = 0; i < 6; i++) // #2..#5 are sent, the rest silently dropped
            Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/auth/resend-verification", new { email })).StatusCode);

        Assert.Equal(5, await factory.CodesSentToAsync(email));
    }

    [Fact]
    public async Task Account_is_locked_after_repeated_failed_logins()
    {
        var email = NewEmail();
        var (_, _) = await factory.CreateVerifiedUserAsync(email);
        var client = factory.CreateClient();

        for (var i = 0; i < 10; i++)
            Assert.Equal(HttpStatusCode.Unauthorized,
                (await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" })).StatusCode);

        // Even the right password is refused while locked.
        var locked = await client.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
        Assert.Contains("ACCOUNT_LOCKED", await locked.Content.ReadAsStringAsync());
        Assert.True(locked.Headers.RetryAfter is not null);
    }

    [Fact]
    public async Task Unknown_emails_lock_the_same_way()
    {
        var email = NewEmail();
        var client = factory.CreateClient();
        for (var i = 0; i < 10; i++)
            await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" });

        var res = await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" });
        Assert.Equal(HttpStatusCode.TooManyRequests, res.StatusCode);
    }

    [Fact]
    public async Task Sessions_list_and_change_password_revokes_other_sessions()
    {
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);
        var other = factory.CreateClient();
        await IdentityFactory.LoginAsync(other, email, "Passw0rd!");

        var sessions = await client.GetFromJsonAsync<List<SessionResponse>>("/sessions");
        Assert.Equal(2, sessions!.Count);
        Assert.Single(sessions, s => s.Current);

        var change = await client.PostAsJsonAsync("/auth/change-password", new { oldPassword = "Passw0rd!", newPassword = "NewPassw0rd" });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await other.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" })).StatusCode);
    }

    [Fact]
    public async Task Deleting_account_is_logical_and_frees_the_email()
    {
        var email = NewEmail();
        var (client, tokens) = await factory.CreateVerifiedUserAsync(email);

        var delete = new HttpRequestMessage(HttpMethod.Delete, "/auth/me") { Content = JsonContent.Create(new { password = "Passw0rd!" }) };
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(delete)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken + "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await client.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" })).StatusCode);

        // The row is still there, only marked as deleted.
        var rows = await factory.WithDbAsync(db => db.Users.IgnoreQueryFilters().Where(u => u.Email == email).ToListAsync());
        Assert.Single(rows);
        Assert.NotNull(rows[0].DeletedAt);

        // The filtered unique index lets the same email register again.
        var again = await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.Accepted, again.StatusCode);
        Assert.Equal(2, await factory.WithDbAsync(db => db.Users.IgnoreQueryFilters().CountAsync(u => u.Email == email)));
    }

    private static async Task<AuthTokensResponse> Refresh(HttpClient client, string refreshToken)
    {
        var res = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken });
        res.EnsureSuccessStatusCode();
        return (await res.Content.ReadFromJsonAsync<AuthTokensResponse>())!;
    }
}
