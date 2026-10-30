using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Dtos;
using Identity.Infrastructure.Messaging;

namespace Identity.Tests;

public sealed class WebhookTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"hook-{Guid.NewGuid():N}@test.local";

    private async Task<HttpClient> AdminAsync()
    {
        var client = factory.CreateClient();
        await IdentityFactory.LoginAsync(client, IdentityFactory.AdminEmail, IdentityFactory.AdminPassword);
        return client;
    }

    private async Task<Guid> NewUserAsync()
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        return (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
    }

    private IReadOnlyList<(string Type, Guid UserId, Dictionary<string, string> Headers, string Body)> EventsFor(Guid userId) =>
        factory.Webhooks.Received
            .Select(r => (Doc: JsonDocument.Parse(r.Body).RootElement, r.Headers, r.Body))
            .Where(r => r.Doc.GetProperty("data").GetProperty("userId").GetGuid() == userId)
            .Select(r => (r.Doc.GetProperty("type").GetString()!, userId, r.Headers, r.Body))
            .ToList();

    [Fact]
    public async Task Admin_actions_reach_the_store_signed()
    {
        var admin = await AdminAsync();
        var userId = await NewUserAsync();

        await admin.PostAsync($"/admin/users/{userId}/lock", null);
        await admin.PostAsync($"/admin/users/{userId}/unlock", null);
        await admin.DeleteAsync($"/admin/users/{userId}");
        await admin.PostAsync($"/admin/users/{userId}/restore", null);
        await factory.DispatchWebhooksAsync();

        var events = EventsFor(userId);
        Assert.Equal(["user.locked", "user.unlocked", "user.deleted", "user.restored"], events.Select(e => e.Type));

        foreach (var e in events)
        {
            // Exactly what the receiving backend should do to trust the call.
            var signature = e.Headers["Identity-Signature"].Split(',').ToDictionary(p => p.Split('=')[0], p => p.Split('=')[1]);
            Assert.Equal(WebhookProcessor.Sign(IdentityFactory.StoreWebhookSecret, long.Parse(signature["t"]), e.Body), signature["v1"]);
            Assert.NotEqual(WebhookProcessor.Sign("another-secret", long.Parse(signature["t"]), e.Body), signature["v1"]);
            Assert.Equal(e.Type, e.Headers["Identity-Event-Type"]);
            Assert.DoesNotContain("@", e.Body); // ids only, no personal data
        }
    }

    [Fact]
    public async Task Deleting_your_own_account_is_announced_too()
    {
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);
        var userId = (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;

        await client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "/auth/me") { Content = JsonContent.Create(new { password = "Passw0rd!" }) });
        await factory.DispatchWebhooksAsync();

        Assert.Equal(["user.deleted"], EventsFor(userId).Select(e => e.Type));
    }

    [Fact]
    public async Task Rejected_actions_announce_nothing_and_failed_deliveries_are_retried()
    {
        var admin = await AdminAsync();
        var adminId = (await admin.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/admin/users/{adminId}/lock", null)).StatusCode);
        await factory.DispatchWebhooksAsync();
        Assert.Empty(EventsFor(adminId));

        var userId = await NewUserAsync();
        factory.Webhooks.FailNext = 1;
        await admin.PostAsync($"/admin/users/{userId}/lock", null);
        await factory.DispatchWebhooksAsync();

        Assert.Empty(EventsFor(userId));
        var pending = await factory.WithDbAsync(db => db.OutboxWebhooks.SingleAsync(w => w.Payload.Contains(userId.ToString())));
        Assert.Equal(1, pending.Attempts);
        Assert.Null(pending.SentAt);
        Assert.Contains("500", pending.LastError);
    }
}
