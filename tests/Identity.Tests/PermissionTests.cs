using System.Net;
using System.Net.Http.Json;
using Identity.Application.Dtos;
using Identity.Domain.Authorization;

namespace Identity.Tests;

public sealed class PermissionTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"perm-{Guid.NewGuid():N}@test.local";
    private static string NewRole(string prefix) => $"{prefix}{Guid.NewGuid():N}"[..20];

    private async Task<HttpClient> AdminAsync()
    {
        var client = factory.CreateClient();
        await IdentityFactory.LoginAsync(client, IdentityFactory.AdminEmail, IdentityFactory.AdminPassword);
        return client;
    }

    private async Task CreateRoleAsync(HttpClient admin, string name, params string[] permissions) =>
        Assert.Equal(HttpStatusCode.Created,
            (await admin.PostAsJsonAsync("/admin/roles", new { name, permissions })).StatusCode);

    private async Task<(HttpClient Client, Guid Id)> UserWithRoleAsync(HttpClient admin, string role)
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        var id = (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync($"/admin/users/{id}/roles", new { role })).StatusCode);
        return (client, id);
    }

    [Fact]
    public async Task Each_endpoint_requires_its_own_permission()
    {
        var admin = await AdminAsync();
        var role = NewRole("Support");
        await CreateRoleAsync(admin, role, Permissions.UsersRead);
        var (support, _) = await UserWithRoleAsync(admin, role);

        Assert.Equal(HttpStatusCode.OK, (await support.GetAsync("/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await support.GetAsync("/admin/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await support.DeleteAsync($"/admin/users/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal([Permissions.UsersRead], (await support.GetFromJsonAsync<UserResponse>("/auth/me"))!.Permissions);
    }

    [Fact]
    public async Task Nobody_can_grant_what_they_do_not_have()
    {
        var admin = await AdminAsync();
        var delegator = NewRole("Delegator");
        await CreateRoleAsync(admin, delegator, Permissions.RolesAssign, Permissions.RolesManage);
        var (client, selfId) = await UserWithRoleAsync(admin, delegator);

        // Promote themselves to Admin (which implies every permission): refused.
        var toAdmin = await client.PostAsJsonAsync($"/admin/users/{selfId}/roles", new { role = "Admin" });
        Assert.Equal(HttpStatusCode.Forbidden, toAdmin.StatusCode);
        Assert.Contains("PRIVILEGE_ESCALATION", await toAdmin.Content.ReadAsStringAsync());

        // Build a role with a permission they lack: refused too.
        var create = await client.PostAsJsonAsync("/admin/roles", new { name = NewRole("Sneaky"), permissions = new[] { Permissions.AuditRead } });
        Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);

        // Within their own permissions it works.
        var ok = await client.PostAsJsonAsync("/admin/roles", new { name = NewRole("Helper"), permissions = new[] { Permissions.RolesAssign } });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
    }

    [Fact]
    public async Task Changing_a_roles_permissions_applies_to_members_immediately()
    {
        var admin = await AdminAsync();
        var role = NewRole("Auditor");
        await CreateRoleAsync(admin, role, Permissions.AuditRead);
        var (member, _) = await UserWithRoleAsync(admin, role);
        Assert.Equal(HttpStatusCode.OK, (await member.GetAsync("/admin/audit")).StatusCode); // warms the session cache

        var change = await admin.PutAsJsonAsync($"/admin/roles/{role}/permissions", new { permissions = new[] { Permissions.UsersRead } });
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/admin/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await member.GetAsync("/admin/users")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/admin/roles/{role}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/admin/users")).StatusCode);
    }

    [Fact]
    public async Task Stale_permissions_in_an_old_token_do_not_authorize_here()
    {
        var admin = await AdminAsync();
        var role = NewRole("Temp");
        await CreateRoleAsync(admin, role, Permissions.UsersRead);
        var (member, memberId) = await UserWithRoleAsync(admin, role);

        // Re-login so the token itself carries users.read, then take the role away.
        var email = (await member.GetFromJsonAsync<UserResponse>("/auth/me"))!.Email;
        var tokens = await IdentityFactory.LoginAsync(member, email, "Passw0rd!");
        Assert.Contains(Permissions.UsersRead, MfaTests.TokenClaims(tokens.AccessToken, "perm"));
        await admin.DeleteAsync($"/admin/users/{memberId}/roles/{role}");

        Assert.Equal(HttpStatusCode.Forbidden, (await member.GetAsync("/admin/users")).StatusCode);
    }

    [Fact]
    public async Task System_roles_are_protected()
    {
        var admin = await AdminAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.DeleteAsync("/admin/roles/User")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PutAsJsonAsync("/admin/roles/Admin/permissions", new { permissions = Array.Empty<string>() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PostAsJsonAsync("/admin/roles", new { name = NewRole("Bad"), permissions = new[] { "made.up" } })).StatusCode);

        var roles = await admin.GetFromJsonAsync<List<RoleResponse>>("/admin/roles");
        Assert.Equal(Permissions.All.Order(), roles!.Single(r => r.Name == "Admin").Permissions);
        Assert.True(roles!.Single(r => r.Name == "User").IsSystem);
    }

    [Fact]
    public async Task Admin_tokens_carry_roles_and_every_permission_for_other_services()
    {
        var client = factory.CreateClient();
        var tokens = await IdentityFactory.LoginAsync(client, IdentityFactory.AdminEmail, IdentityFactory.AdminPassword);

        Assert.Contains("Admin", MfaTests.TokenClaims(tokens.AccessToken, "role"));
        Assert.Equal(Permissions.All.Order(), MfaTests.TokenClaims(tokens.AccessToken, "perm").Order());
        Assert.Equal(["pwd"], MfaTests.TokenClaims(tokens.AccessToken, "amr"));
    }
}
