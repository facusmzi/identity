using Identity.Domain.Enums;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Domain.Authorization;
using Identity.Domain.Entities;

namespace Identity.Application.Services;

/// <summary>
/// Every action is written to the audit log in the same transaction as the change.
/// <list type="bullet">
/// <item>No privilege escalation: you can only grant, revoke, assign or remove permissions you hold yourself.</item>
/// <item>Admin accounts are protected: an admin must be demoted before being deleted, and the last admin can
/// never be demoted or deleted.</item>
/// <item>Admin and User are system roles: they cannot be deleted, and Admin's permissions cannot be edited.</item>
/// </list>
/// </summary>
public sealed class AdminService(
    IUserRepository users,
    IRoleRepository roles,
    ISessionRepository sessions,
    IAuditLogRepository auditLog,
    IUnitOfWork uow,
    AuditTrail audit,
    ISessionCache sessionCache,
    TimeProvider clock)
{
    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    public async Task<PagedResult<AdminUserResponse>> ListUsersAsync(int page, int pageSize, bool includeDeleted, CancellationToken ct = default)
    {
        (page, pageSize) = Paging(page, pageSize);
        var result = await users.ListAsync(page, pageSize, includeDeleted, ct);
        return result.Map(u => u.ToAdminResponse());
    }

    public async Task<AdminUserResponse> GetUserAsync(Guid id, CancellationToken ct = default) =>
        (await users.GetWithRolesAsync(id, includeDeleted: true, ct) ?? throw new NotFoundException("User not found"))
        .ToAdminResponse();

    public async Task<PagedResult<AuditEntryResponse>> ListAuditAsync(
        Guid? userId, string? action, int page, int pageSize, CancellationToken ct = default)
    {
        (page, pageSize) = Paging(page, pageSize);
        var result = await auditLog.ListAsync(userId, action, page, pageSize, ct);
        return result.Map(e => e.ToResponse());
    }

    // ---- roles ----

    public static IReadOnlyList<string> ListPermissions() => Permissions.All;

    public async Task<IReadOnlyList<RoleResponse>> ListRolesAsync(CancellationToken ct = default) =>
        (await roles.ListAsync(ct)).Select(r => r.ToResponse()).ToList();

    public async Task<RoleResponse> CreateRoleAsync(Guid actingUserId, CreateRoleRequest req, CancellationToken ct = default)
    {
        var name = req.Name.Trim();
        var permissions = ValidatePermissions(req.Permissions);
        await EnsureActorHoldsAsync(actingUserId, permissions, ct);
        if (await roles.GetByNameAsync(name, ct) is not null)
            throw new ConflictException($"Role '{name}' already exists", "ROLE_EXISTS");

        var role = new Role { Name = name, Description = req.Description?.Trim() };
        foreach (var p in permissions) role.RolePermissions.Add(new RolePermission { Role = role, Permission = p });
        await roles.AddAsync(role, ct);
        audit.Record(AuditActions.AdminRoleCreated, actingUserId, null, new { role = name, permissions });

        try
        {
            await uow.SaveChangesAsync(ct);
        }
        catch (UniqueConstraintViolationException)
        {
            throw new ConflictException($"Role '{name}' already exists", "ROLE_EXISTS");
        }
        return role.ToResponse();
    }

    public async Task<RoleResponse> SetRolePermissionsAsync(Guid actingUserId, string roleName, SetRolePermissionsRequest req, CancellationToken ct = default)
    {
        var role = await roles.GetByNameAsync(roleName, ct) ?? throw new NotFoundException($"Role '{roleName}' not found");
        if (role.Name == Role.Admin)
            throw new BadRequestException("The Admin role always has every permission", "ADMIN_ROLE_IMMUTABLE");

        var wanted = ValidatePermissions(req.Permissions);
        var current = role.RolePermissions.Select(p => p.Permission).ToHashSet();
        var added = wanted.Except(current).ToList();
        var removed = current.Except(wanted).ToList();
        // Changing a permission (either way) requires holding it.
        await EnsureActorHoldsAsync(actingUserId, added.Concat(removed), ct);

        foreach (var link in role.RolePermissions.Where(p => removed.Contains(p.Permission)).ToList())
            role.RolePermissions.Remove(link); // logical delete through the interceptor
        foreach (var p in added) role.RolePermissions.Add(new RolePermission { RoleId = role.Id, Permission = p });

        audit.Record(AuditActions.AdminRolePermissionsChanged, actingUserId, null, new { role = role.Name, added, removed });
        await uow.SaveChangesAsync(ct);
        await InvalidateMembersAsync(role.Id, ct);
        return role.ToResponse();
    }

    public async Task DeleteRoleAsync(Guid actingUserId, string roleName, CancellationToken ct = default)
    {
        var role = await roles.GetForDeletionAsync(roleName, ct) ?? throw new NotFoundException($"Role '{roleName}' not found");
        if (role.IsSystem) throw new BadRequestException("System roles cannot be deleted", "SYSTEM_ROLE");
        await EnsureActorHoldsAsync(actingUserId, role.EffectivePermissions(), ct);

        var members = role.UserRoles.Select(ur => ur.UserId).Distinct().ToList();
        foreach (var link in role.UserRoles.ToList()) role.UserRoles.Remove(link);
        foreach (var link in role.RolePermissions.ToList()) role.RolePermissions.Remove(link);
        roles.Remove(role);

        audit.Record(AuditActions.AdminRoleDeleted, actingUserId, null, new { role = role.Name, members = members.Count });
        await uow.SaveChangesAsync(ct);
        foreach (var userId in members) await sessionCache.InvalidateUserAsync(userId, ct);
    }

    public async Task<AdminUserResponse> AssignRoleAsync(Guid actingUserId, Guid userId, AssignRoleRequest req, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        var role = await roles.GetByNameAsync(req.Role, ct) ?? throw new NotFoundException($"Role '{req.Role}' not found");
        await EnsureActorHoldsAsync(actingUserId, role.EffectivePermissions(), ct);

        if (user.UserRoles.All(ur => ur.RoleId != role.Id))
        {
            user.UserRoles.Add(new UserRole { UserId = user.Id, Role = role });
            audit.Record(AuditActions.AdminRoleAssigned, actingUserId, userId, new { role = role.Name });
            await uow.SaveChangesAsync(ct);
            await sessionCache.InvalidateUserAsync(userId, ct); // cached sessions carry the roles
        }
        return user.ToAdminResponse();
    }

    public async Task<AdminUserResponse> RemoveRoleAsync(Guid actingUserId, Guid userId, string roleName, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        var link = user.UserRoles.FirstOrDefault(ur => string.Equals(ur.Role.Name, roleName, StringComparison.OrdinalIgnoreCase))
            ?? throw new NotFoundException($"User does not have role '{roleName}'");
        await EnsureActorHoldsAsync(actingUserId, link.Role.EffectivePermissions(), ct);

        if (link.Role.Name == Role.Admin)
        {
            if (userId == actingUserId)
                throw new BadRequestException("You cannot remove your own Admin role", "SELF_DEMOTION");
            await EnsureNotLastAdminAsync(userId, ct);
        }

        // The repository turns this removal into a logical delete of the user_roles row.
        user.UserRoles.Remove(link);
        audit.Record(AuditActions.AdminRoleRemoved, actingUserId, userId, new { role = link.Role.Name });
        await uow.SaveChangesAsync(ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
        return user.ToAdminResponse();
    }

    // ---- users ----

    public async Task DeleteUserAsync(Guid actingUserId, Guid userId, CancellationToken ct = default)
    {
        if (userId == actingUserId) throw new BadRequestException("Use DELETE /auth/me to delete your own account");

        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        if (user.RoleNames().Contains(Role.Admin))
            throw new BadRequestException("Remove the Admin role before deleting an admin", "TARGET_IS_ADMIN");
        await EnsureActorHoldsAsync(actingUserId, user.EffectivePermissions(), ct);

        audit.Record(AuditActions.AdminUserDeleted, actingUserId, userId);
        await uow.ExecuteInTransactionAsync(async t =>
        {
            await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.AdminDeleted, ct: t);
            users.Remove(user);
            await uow.SaveChangesAsync(t);
        }, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
    }

    public async Task<AdminUserResponse> RestoreUserAsync(Guid actingUserId, Guid userId, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, includeDeleted: true, ct) ?? throw new NotFoundException("User not found");
        if (!user.IsDeleted) return user.ToAdminResponse();

        if (await users.EmailExistsAsync(user.Email, ct))
            throw new ConflictException("Another active user already uses this email", "EMAIL_TAKEN");

        users.Restore(user);
        audit.Record(AuditActions.AdminUserRestored, actingUserId, userId);
        await uow.SaveChangesAsync(ct);
        return user.ToAdminResponse();
    }

    /// <summary>
    /// Incident response: the account stops working at once (all sessions revoked, login, refresh and password
    /// reset refused) until an admin unlocks it. Unlike deleting, nothing is hidden and it is fully reversible.
    /// </summary>
    public async Task<AdminUserResponse> LockUserAsync(Guid actingUserId, Guid userId, CancellationToken ct = default)
    {
        if (userId == actingUserId) throw new BadRequestException("You cannot lock your own account", "SELF_LOCK");

        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        await EnsureActorHoldsAsync(actingUserId, user.EffectivePermissions(), ct);
        if (user.RoleNames().Contains(Role.Admin)) await EnsureNotLastAdminAsync(userId, ct);
        if (user.LockedAt is not null) return user.ToAdminResponse();

        user.LockedAt = Now;
        audit.Record(AuditActions.AdminUserLocked, actingUserId, userId);
        await uow.ExecuteInTransactionAsync(async t =>
        {
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.AdminLocked, ct: t);
        }, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
        return user.ToAdminResponse();
    }

    public async Task<AdminUserResponse> UnlockUserAsync(Guid actingUserId, Guid userId, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        await EnsureActorHoldsAsync(actingUserId, user.EffectivePermissions(), ct);
        if (user.LockedAt is null) return user.ToAdminResponse();

        user.LockedAt = null;
        audit.Record(AuditActions.AdminUserUnlocked, actingUserId, userId);
        await uow.SaveChangesAsync(ct);
        return user.ToAdminResponse();
    }

    // ---- sessions of any user ----

    public async Task<IReadOnlyList<AdminSessionResponse>> ListUserSessionsAsync(Guid userId, CancellationToken ct = default)
    {
        _ = await users.GetByIdIncludingDeletedAsync(userId, ct) ?? throw new NotFoundException("User not found");
        var now = Now;
        return (await sessions.ListForUserAsync(userId, ct)).Select(s => s.ToAdminResponse(now)).ToList();
    }

    /// <param name="sessionId">One session, or null for all of them.</param>
    public async Task<int> RevokeUserSessionsAsync(Guid actingUserId, Guid userId, Guid? sessionId, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        await EnsureActorHoldsAsync(actingUserId, user.EffectivePermissions(), ct);

        int revoked;
        if (sessionId is { } id)
        {
            var session = await sessions.GetByIdAsync(id, ct);
            if (session is null || session.UserId != userId) throw new NotFoundException("Session not found");
            revoked = await sessions.RevokeAsync(id, Now, RevocationReason.AdminRevoked, ct);
        }
        else
        {
            revoked = await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.AdminRevoked, ct: ct);
        }

        audit.Record(AuditActions.AdminSessionsRevoked, actingUserId, userId, new { sessionId, revoked });
        await uow.SaveChangesAsync(ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
        return revoked;
    }

    // ---- helpers ----

    /// <summary>
    /// The anti-escalation rule: whoever grants, revokes, assigns or removes a set of permissions (directly or
    /// through a role) must hold all of them. Someone with roles.assign but not audit.read cannot hand out a role
    /// that includes audit.read, and cannot assign Admin unless they effectively are one.
    /// </summary>
    private async Task EnsureActorHoldsAsync(Guid actingUserId, IEnumerable<string> permissions, CancellationToken ct)
    {
        var held = (await users.GetAccessAsync(actingUserId, ct)).Permissions.ToHashSet();
        var missing = permissions.Where(p => !held.Contains(p)).Distinct().Order().ToList();
        if (missing.Count > 0)
            throw new ForbiddenException($"You cannot grant or revoke permissions you do not have: {string.Join(", ", missing)}",
                "PRIVILEGE_ESCALATION");
    }

    private static List<string> ValidatePermissions(IEnumerable<string> permissions)
    {
        var list = permissions.Select(p => p.Trim()).Distinct().ToList();
        var unknown = list.Where(p => !Permissions.IsKnown(p)).ToList();
        if (unknown.Count > 0)
            throw new BadRequestException($"Unknown permissions: {string.Join(", ", unknown)}", "UNKNOWN_PERMISSION");
        return list;
    }

    private async Task InvalidateMembersAsync(Guid roleId, CancellationToken ct)
    {
        foreach (var userId in await users.ListIdsWithRoleAsync(roleId, ct))
            await sessionCache.InvalidateUserAsync(userId, ct);
    }

    private async Task EnsureNotLastAdminAsync(Guid userId, CancellationToken ct)
    {
        if (!await users.AnyOtherInRoleAsync(Role.Admin, userId, ct))
            throw new BadRequestException("This is the last admin", "LAST_ADMIN");
    }

    private static (int Page, int PageSize) Paging(int page, int pageSize) => (Math.Max(page, 1), Math.Clamp(pageSize, 1, 100));
}
