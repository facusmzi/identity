using System.Net;
using System.Net.Http.Json;

namespace Identity.Tests;

public sealed class PasswordResetTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Unknown_email_gets_the_same_response_and_no_email()
    {
        var email = NewEmail();
        var res = await factory.CreateClient().PostAsJsonAsync("/auth/forgot-password", new { email });

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Null(factory.Emails.LastResetTokenFor(email));
    }

    [Fact]
    public async Task Reset_changes_password_revokes_sessions_and_is_single_use()
    {
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);
        var anon = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/auth/forgot-password", new { email })).StatusCode);
        var token = factory.Emails.LastResetTokenFor(email)!;

        var wrong = await anon.PostAsJsonAsync("/auth/reset-password", new { email, token = token + "x", newPassword = "Reset123x" });
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);

        var reset = await anon.PostAsJsonAsync("/auth/reset-password", new { email, token, newPassword = "Reset123x" });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" })).StatusCode);
        await IdentityFactory.LoginAsync(anon, email, "Reset123x");

        var reuse = await anon.PostAsJsonAsync("/auth/reset-password", new { email, token, newPassword = "Another123x" });
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
    }

    [Fact]
    public async Task Reset_verifies_an_unverified_email()
    {
        // e.g. someone registered the victim's email first; the real owner takes it back via reset.
        var email = NewEmail();
        var client = factory.CreateClient();
        await client.PostAsJsonAsync("/auth/register", new { email, password = "Squatter1x" });

        await client.PostAsJsonAsync("/auth/forgot-password", new { email });
        var token = factory.Emails.LastResetTokenFor(email)!;
        await client.PostAsJsonAsync("/auth/reset-password", new { email, token, newPassword = "Owner123x" });

        await IdentityFactory.LoginAsync(client, email, "Owner123x");
    }

    [Fact]
    public async Task Huge_password_is_rejected_before_hashing()
    {
        var res = await factory.CreateClient().PostAsJsonAsync("/auth/login",
            new { email = NewEmail(), password = new string('a', 100_000) });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }
}
