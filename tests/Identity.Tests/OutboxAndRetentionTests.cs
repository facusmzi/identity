using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Identity.Application.Common;
using Identity.Domain.Entities;
using Identity.Infrastructure.Maintenance;

namespace Identity.Tests;

public sealed class OutboxAndRetentionTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Delivered_emails_do_not_keep_the_code_in_the_database()
    {
        var email = NewEmail();
        await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });

        var pending = await factory.WithDbAsync(db => db.OutboxEmails.SingleAsync(m => m.To == email));
        Assert.NotNull(pending.Payload);
        Assert.Null(pending.SentAt);

        await factory.DispatchEmailsAsync();

        var sent = await factory.WithDbAsync(db => db.OutboxEmails.SingleAsync(m => m.To == email));
        Assert.NotNull(sent.SentAt);
        Assert.Null(sent.Payload);
    }

    [Fact]
    public async Task Failed_delivery_is_retried_later_instead_of_lost()
    {
        var email = NewEmail();
        await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });

        factory.Emails.FailWith = new InvalidOperationException("SMTP down");
        try
        {
            await factory.DispatchEmailsAsync();
        }
        finally
        {
            factory.Emails.FailWith = null;
        }

        var failed = await factory.WithDbAsync(db => db.OutboxEmails.SingleAsync(m => m.To == email));
        Assert.Equal(1, failed.Attempts);
        Assert.Equal("SMTP down", failed.LastError);
        Assert.Null(failed.SentAt);
        Assert.NotNull(failed.Payload);
        Assert.True(failed.NextAttemptAt > DateTime.UtcNow);

        // Not due yet, so not resent immediately.
        await factory.DispatchEmailsAsync();
        Assert.Equal(0, factory.Emails.CodesSentTo(email));
    }

    [Fact]
    public async Task Unique_index_violations_surface_as_a_typed_exception()
    {
        var email = NewEmail();
        await factory.CreateVerifiedUserAsync(email);

        await Assert.ThrowsAsync<UniqueConstraintViolationException>(() => factory.WithDbAsync(async db =>
        {
            db.Users.Add(new User { Email = email });
            return await db.SaveChangesAsync();
        }));
    }

    [Fact]
    public async Task Retention_cleanup_purges_only_old_data()
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        await client.PostAsync("/auth/logout", null);
        var (_, live) = await factory.CreateVerifiedUserAsync(NewEmail());

        // Age everything ended by 31 days (retention is 30).
        await factory.WithDbAsync(db => db.Sessions.Where(s => s.RevokedAt != null)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, DateTime.UtcNow.AddDays(-31))));
        var revokedBefore = await factory.WithDbAsync(db => db.Sessions.CountAsync(s => s.RevokedAt != null));
        Assert.True(revokedBefore > 0);

        await factory.WithScopeAsync(sp => sp.GetRequiredService<RetentionCleanup>().RunAsync());

        Assert.Equal(0, await factory.WithDbAsync(db => db.Sessions.CountAsync(s => s.RevokedAt != null)));
        Assert.True(await factory.WithDbAsync(db => db.Sessions.AnyAsync(s => s.RevokedAt == null)));
        Assert.NotNull(live.AccessToken);
    }
}
