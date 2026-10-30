using Identity.Domain.Entities;

namespace Identity.Application.Abstractions.Persistence;

public interface IRoleRepository : IRepository<Role>
{
    Task<Role?> GetByNameAsync(string name, CancellationToken ct = default);
    Task<IReadOnlyList<Role>> ListAsync(CancellationToken ct = default);
}
