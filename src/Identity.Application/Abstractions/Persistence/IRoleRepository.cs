using Identity.Domain.Entities;

namespace Identity.Application.Abstractions.Persistence;

public interface IRoleRepository : IRepository<Role>
{
    /// <summary>Tracked, with its permissions.</summary>
    Task<Role?> GetByNameAsync(string name, CancellationToken ct = default);

    /// <summary>Tracked, with its permissions and user links (to delete it logically with everything).</summary>
    Task<Role?> GetForDeletionAsync(string name, CancellationToken ct = default);

    Task<IReadOnlyList<Role>> ListAsync(CancellationToken ct = default);
}
