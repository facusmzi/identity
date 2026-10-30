using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Common;
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
        return query
            .Include(u => u.UserRoles.Where(ur => ur.DeletedAt == null)).ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == id, ct);
    }

    public Task<bool> EmailExistsAsync(string email, CancellationToken ct = default) =>
        Set.AnyAsync(u => u.Email == email, ct);

    public Task<bool> AnyInRoleAsync(string roleName, CancellationToken ct = default) =>
        Db.UserRoles.AnyAsync(ur => ur.Role.Name == roleName && ur.User.DeletedAt == null, ct);

    public async Task<PagedResult<User>> ListAsync(int page, int pageSize, bool includeDeleted, CancellationToken ct = default)
    {
        var query = Set.AsNoTracking();
        if (includeDeleted) query = query.IgnoreQueryFilters();

        var total = await query.CountAsync(ct);
        var items = await query
            // IgnoreQueryFilters also removes the filter on the included user_roles, so filter them explicitly.
            .Include(u => u.UserRoles.Where(ur => ur.DeletedAt == null)).ThenInclude(ur => ur.Role)
            .OrderBy(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return new PagedResult<User>(items, page, pageSize, total);
    }
}
