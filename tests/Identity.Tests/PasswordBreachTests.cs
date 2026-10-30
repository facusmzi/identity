using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;

namespace Identity.Tests;

public sealed class PasswordBreachTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"hibp-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Breached_passwords_are_rejected_without_revealing_whether_the_email_exists()
    {
        var existing = NewEmail();
        await factory.CreateVerifiedUserAsync(existing);
        var client = factory.CreateClient();

        var forExisting = await client.PostAsJsonAsync("/auth/register", new { email = existing, password = "Password123" });
        var forNew = await client.PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "Password123" });

        Assert.Equal(HttpStatusCode.BadRequest, forNew.StatusCode);
        Assert.Equal(forNew.StatusCode, forExisting.StatusCode);
        Assert.Contains("PASSWORD_BREACHED", await forNew.Content.ReadAsStringAsync());
        Assert.Contains("PASSWORD_BREACHED", await forExisting.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Changing_or_resetting_to_a_breached_password_is_rejected()
    {
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);

        var change = await client.PostAsJsonAsync("/auth/change-password", new { oldPassword = "Passw0rd!", newPassword = "Qwerty12345" });
        Assert.Contains("PASSWORD_BREACHED", await change.Content.ReadAsStringAsync());

        await client.PostAsJsonAsync("/auth/forgot-password", new { email });
        var token = (await factory.LastResetTokenAsync(email))!;
        var reset = await client.PostAsJsonAsync("/auth/reset-password", new { email, token, newPassword = "Password123" });
        Assert.Contains("PASSWORD_BREACHED", await reset.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Password_equal_to_the_email_is_rejected()
    {
        var res = await factory.CreateClient().PostAsJsonAsync("/auth/register",
            new { email = "user1pass@test.local", password = "User1pass@test.local" });
        Assert.Contains("PASSWORD_EQUALS_EMAIL", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task When_the_service_is_down_fail_open_accepts_and_audits_fail_closed_rejects()
    {
        factory.Breaches.Unavailable = true;
        try
        {
            var email = NewEmail();
            var open = await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });
            Assert.Equal(HttpStatusCode.Accepted, open.StatusCode);
            Assert.True(await factory.WithDbAsync(db => db.AuditEntries.AnyAsync(e => e.Action == "password.breach_check_unavailable")));

            using var closed = factory.WithWebHostBuilder(b => b.UseSetting("Hibp:FailOpen", "false"));
            var rejected = await closed.CreateClient().PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "Passw0rd!" });
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.Contains("PASSWORD_CHECK_UNAVAILABLE", await rejected.Content.ReadAsStringAsync());
        }
        finally
        {
            factory.Breaches.Unavailable = false;
        }
    }
}
