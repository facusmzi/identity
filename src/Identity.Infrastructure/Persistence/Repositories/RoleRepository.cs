using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Repositories;

public sealed class RoleRepository(AppDbContext db) : Repository<Role>(db), IRoleRepository
{
    public Task<Role?> GetByNameAsync(string name, CancellationToken ct = default) =>
        Set.FirstOrDefaultAsync(r => r.Name.ToLower() == name.ToLower(), ct);

    public async Task<IReadOnlyList<Role>> ListAsync(CancellationToken ct = default) =>
        await Set.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct);
}
