using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Common;
using Identity.Domain.Authorization;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Repositories;

public sealed class UserRepository(AppDbContext db) : Repository<User>(db), IUserRepository
{
    public Task<User?> GetByEmailAsync(string email, CancellationToken ct = default) =>
        Set.FirstOrDefaultAsync(u => u.Email == email, ct);

    public Task<User?> GetWithRolesAsync(Guid id, bool includeDeleted = false, CancellationToken ct = default)
    {
        var query = Set.AsQueryable();
        if (includeDeleted) query = query.IgnoreQueryFilters();
        // IgnoreQueryFilters also drops the filters of the includes, so they are spelled out.
        return query
            .Include(u => u.UserRoles.Where(ur => ur.DeletedAt == null && ur.Role.DeletedAt == null)).ThenInclude(ur => ur.Role)
            .ThenInclude(r => r.RolePermissions.Where(p => p.DeletedAt == null))
            .FirstOrDefaultAsync(u => u.Id == id, ct);
    }

    public async Task<UserAccess> GetAccessAsync(Guid userId, CancellationToken ct = default)
    {
        var roles = await Db.UserRoles.AsNoTracking()
            .Where(ur => ur.UserId == userId)
            .Select(ur => new { ur.Role.Name, Permissions = ur.Role.RolePermissions.Select(p => p.Permission).ToList() })
            .ToListAsync(ct);

        var permissions = roles
            .SelectMany(r => r.Name == Role.Admin ? Permissions.All : r.Permissions)
            .Distinct().Order().ToList();
        return new UserAccess(roles.Select(r => r.Name).Order().ToList(), permissions);
    }

    public Task<bool> EmailExistsAsync(string email, CancellationToken ct = default) =>
        Set.AnyAsync(u => u.Email == email, ct);

    public Task<bool> AnyOtherInRoleAsync(string roleName, Guid exceptUserId, CancellationToken ct = default) =>
        Db.UserRoles.AnyAsync(ur => ur.Role.Name == roleName && ur.UserId != exceptUserId && ur.User.DeletedAt == null, ct);

    public async Task<IReadOnlyList<Guid>> ListIdsWithRoleAsync(Guid roleId, CancellationToken ct = default) =>
        await Db.UserRoles.AsNoTracking().Where(ur => ur.RoleId == roleId).Select(ur => ur.UserId).Distinct().ToListAsync(ct);

    public async Task<PagedResult<User>> ListAsync(int page, int pageSize, bool includeDeleted, CancellationToken ct = default)
    {
        var query = Set.AsNoTracking();
        if (includeDeleted) query = query.IgnoreQueryFilters();

        var total = await query.CountAsync(ct);
        var items = await query
            // IgnoreQueryFilters also removes the filter on the included user_roles, so filter them explicitly.
            .Include(u => u.UserRoles.Where(ur => ur.DeletedAt == null && ur.Role.DeletedAt == null)).ThenInclude(ur => ur.Role)
            .OrderBy(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return new PagedResult<User>(items, page, pageSize, total);
    }
}
