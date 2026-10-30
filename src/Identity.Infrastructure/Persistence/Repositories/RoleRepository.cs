using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Repositories;

public sealed class RoleRepository(AppDbContext db) : Repository<Role>(db), IRoleRepository
{
    public Task<Role?> GetByNameAsync(string name, CancellationToken ct = default) =>
        Set.Include(r => r.RolePermissions).FirstOrDefaultAsync(r => r.Name.ToLower() == name.ToLower(), ct);

    public Task<Role?> GetForDeletionAsync(string name, CancellationToken ct = default) =>
        Set.Include(r => r.RolePermissions).Include(r => r.UserRoles)
            .FirstOrDefaultAsync(r => r.Name.ToLower() == name.ToLower(), ct);

    public async Task<IReadOnlyList<Role>> ListAsync(CancellationToken ct = default) =>
        await Set.AsNoTracking().Include(r => r.RolePermissions).OrderBy(r => r.Name).ToListAsync(ct);
}
