using Identity.Application.Abstractions.Persistence;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Domain.Entities;

namespace Identity.Application.Services;

public sealed class AdminService(
    IUserRepository users,
    IRoleRepository roles,
    ISessionRepository sessions,
    IUnitOfWork uow,
    TimeProvider clock)
{
    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    public async Task<PagedResult<AdminUserResponse>> ListUsersAsync(int page, int pageSize, bool includeDeleted, CancellationToken ct = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var result = await users.ListAsync(page, pageSize, includeDeleted, ct);
        return result.Map(u => u.ToAdminResponse());
    }

    public async Task<AdminUserResponse> GetUserAsync(Guid id, CancellationToken ct = default) =>
        (await users.GetWithRolesAsync(id, includeDeleted: true, ct) ?? throw new NotFoundException("User not found"))
        .ToAdminResponse();

    public async Task<IReadOnlyList<RoleResponse>> ListRolesAsync(CancellationToken ct = default) =>
        (await roles.ListAsync(ct)).Select(r => r.ToResponse()).ToList();

    public async Task<AdminUserResponse> AssignRoleAsync(Guid userId, AssignRoleRequest req, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        var role = await roles.GetByNameAsync(req.Role, ct) ?? throw new NotFoundException($"Role '{req.Role}' not found");

        if (user.UserRoles.All(ur => ur.RoleId != role.Id))
        {
            user.UserRoles.Add(new UserRole { UserId = user.Id, Role = role });
            await uow.SaveChangesAsync(ct);
        }
        return user.ToAdminResponse();
    }

    public async Task<AdminUserResponse> RemoveRoleAsync(Guid actingUserId, Guid userId, string roleName, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        var link = user.UserRoles.FirstOrDefault(ur => string.Equals(ur.Role.Name, roleName, StringComparison.OrdinalIgnoreCase))
            ?? throw new NotFoundException($"User does not have role '{roleName}'");

        if (link.Role.Name == Role.Admin && userId == actingUserId)
            throw new BadRequestException("You cannot remove your own Admin role", "SELF_DEMOTION");

        // The repository turns this removal into a logical delete of the user_roles row.
        user.UserRoles.Remove(link);
        await uow.SaveChangesAsync(ct);
        return user.ToAdminResponse();
    }

    public async Task DeleteUserAsync(Guid actingUserId, Guid userId, CancellationToken ct = default)
    {
        if (userId == actingUserId) throw new BadRequestException("Use DELETE /auth/me to delete your own account");

        var user = await users.GetByIdAsync(userId, ct) ?? throw new NotFoundException("User not found");
        await uow.ExecuteInTransactionAsync(async t =>
        {
            await sessions.RevokeAllForUserAsync(userId, Now, ct: t);
            users.Remove(user);
            await uow.SaveChangesAsync(t);
        }, ct);
    }

    public async Task<AdminUserResponse> RestoreUserAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, includeDeleted: true, ct) ?? throw new NotFoundException("User not found");
        if (!user.IsDeleted) return user.ToAdminResponse();

        if (await users.EmailExistsAsync(user.Email, ct))
            throw new ConflictException("Another active user already uses this email", "EMAIL_TAKEN");

        users.Restore(user);
        await uow.SaveChangesAsync(ct);
        return user.ToAdminResponse();
    }
}
