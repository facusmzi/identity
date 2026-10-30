using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Common;
using Identity.Application.Dtos;

namespace Identity.Tests;

public sealed class AdminTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    private async Task<HttpClient> AdminClientAsync()
    {
        var client = factory.CreateClient();
        await IdentityFactory.LoginAsync(client, IdentityFactory.AdminEmail, IdentityFactory.AdminPassword);
        return client;
    }

    [Fact]
    public async Task Admins_must_be_demoted_before_deletion_and_everything_is_audited()
    {
        var admin = await AdminClientAsync();
        var adminId = (await admin.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        var (target, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        var targetId = (await target.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;

        await admin.PostAsJsonAsync($"/admin/users/{targetId}/roles", new { role = "Admin" });

        var blocked = await admin.DeleteAsync($"/admin/users/{targetId}");
        Assert.Equal(HttpStatusCode.BadRequest, blocked.StatusCode);
        Assert.Contains("TARGET_IS_ADMIN", await blocked.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync($"/admin/users/{targetId}/roles/Admin")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/admin/users/{targetId}")).StatusCode);

        var audit = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"/admin/audit?userId={targetId}&pageSize=100");
        var adminActions = audit!.Items.Where(e => e.Action.StartsWith("admin.")).ToList();
        Assert.Equal(["admin.user_deleted", "admin.role_removed", "admin.role_assigned"], adminActions.Select(e => e.Action));
        Assert.All(adminActions, e => Assert.Equal(adminId, e.ActorUserId));
        Assert.Contains(audit.Items, e => e.Action == "login.succeeded" && e.TargetUserId == targetId);
    }

    [Fact]
    public async Task Failed_logins_are_audited_without_secrets()
    {
        var email = NewEmail();
        var (user, _) = await factory.CreateVerifiedUserAsync(email);
        var userId = (await user.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" });

        var admin = await AdminClientAsync();
        var audit = await admin.GetFromJsonAsync<PagedResult<AuditEntryResponse>>($"/admin/audit?userId={userId}&action=login.failed");
        var entry = Assert.Single(audit!.Items);
        Assert.Null(entry.ActorUserId);
        Assert.DoesNotContain("Wrong123x", entry.Details ?? "");
    }

    [Fact]
    public async Task The_last_admin_cannot_delete_their_own_account()
    {
        using var isolated = new IdentityFactory(); // own database: exactly one admin
        var admin = isolated.CreateClient();
        await IdentityFactory.LoginAsync(admin, IdentityFactory.AdminEmail, IdentityFactory.AdminPassword);

        var req = new HttpRequestMessage(HttpMethod.Delete, "/auth/me") { Content = JsonContent.Create(new { password = IdentityFactory.AdminPassword }) };
        var res = await admin.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
        Assert.Contains("LAST_ADMIN", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Regular_user_cannot_access_admin()
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/admin/users")).StatusCode);
    }

    [Fact]
    public async Task Role_changes_apply_without_new_login()
    {
        var admin = await AdminClientAsync();
        var (user, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        var me = await user.GetFromJsonAsync<UserResponse>("/auth/me");

        var assign = await admin.PostAsJsonAsync($"/admin/users/{me!.Id}/roles", new { role = "Admin" });
        Assert.Equal(HttpStatusCode.OK, assign.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/admin/roles")).StatusCode);

        var remove = await admin.DeleteAsync($"/admin/users/{me.Id}/roles/Admin");
        Assert.Equal(HttpStatusCode.OK, remove.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync("/admin/roles")).StatusCode);

        // The removed user_roles row was logically deleted, not physically.
        var links = await factory.WithDbAsync(db => db.UserRoles.IgnoreQueryFilters().Where(ur => ur.UserId == me.Id).ToListAsync());
        Assert.Equal(2, links.Count);
        Assert.Single(links, l => l.DeletedAt != null);

        // Re-assigning after a soft-deleted link works thanks to the filtered unique index.
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync($"/admin/users/{me.Id}/roles", new { role = "Admin" })).StatusCode);
    }

    [Fact]
    public async Task Admin_soft_deletes_and_restores_user()
    {
        var admin = await AdminClientAsync();
        var email = NewEmail();
        var (user, _) = await factory.CreateVerifiedUserAsync(email);
        var me = await user.GetFromJsonAsync<UserResponse>("/auth/me");

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/admin/users/{me!.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.GetAsync("/auth/me")).StatusCode);

        var active = await admin.GetFromJsonAsync<PagedResult<AdminUserResponse>>("/admin/users?pageSize=100");
        Assert.DoesNotContain(active!.Items, u => u.Id == me.Id);

        var all = await admin.GetFromJsonAsync<PagedResult<AdminUserResponse>>("/admin/users?pageSize=100&includeDeleted=true");
        Assert.Contains(all!.Items, u => u.Id == me.Id && u.DeletedAt != null);

        var restored = await admin.PostAsync($"/admin/users/{me.Id}/restore", null);
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
        Assert.Null((await restored.Content.ReadFromJsonAsync<AdminUserResponse>())!.DeletedAt);

        // Sessions were revoked on delete, so the user must log in again.
        await IdentityFactory.LoginAsync(user, email, "Passw0rd!");
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Restore_conflicts_when_email_was_reused()
    {
        var admin = await AdminClientAsync();
        var email = NewEmail();
        var (user, _) = await factory.CreateVerifiedUserAsync(email);
        var me = await user.GetFromJsonAsync<UserResponse>("/auth/me");

        await admin.DeleteAsync($"/admin/users/{me!.Id}");
        await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });

        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync($"/admin/users/{me.Id}/restore", null)).StatusCode);
    }
}
