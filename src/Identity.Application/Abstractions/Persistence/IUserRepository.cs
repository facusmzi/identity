using Identity.Application.Common;
using Identity.Domain.Entities;

namespace Identity.Application.Abstractions.Persistence;

/// <summary>Roles and effective permissions of a user, as names.</summary>
public sealed record UserAccess(IReadOnlyList<string> Roles, IReadOnlyList<string> Permissions);

public interface IUserRepository : IRepository<User>
{
    Task<User?> GetByEmailAsync(string email, CancellationToken ct = default);

    /// <summary>With roles and each role's permissions.</summary>
    Task<User?> GetWithRolesAsync(Guid id, bool includeDeleted = false, CancellationToken ct = default);

    Task<UserAccess> GetAccessAsync(Guid userId, CancellationToken ct = default);
    Task<bool> EmailExistsAsync(string email, CancellationToken ct = default);

    /// <summary>Whether an active user other than <paramref name="exceptUserId"/> has the role.</summary>
    Task<bool> AnyOtherInRoleAsync(string roleName, Guid exceptUserId, CancellationToken ct = default);

    Task<IReadOnlyList<Guid>> ListIdsWithRoleAsync(Guid roleId, CancellationToken ct = default);
    Task<PagedResult<User>> ListAsync(int page, int pageSize, bool includeDeleted, CancellationToken ct = default);
}
