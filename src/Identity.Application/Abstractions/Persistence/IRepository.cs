using Identity.Domain.Common;

namespace Identity.Application.Abstractions.Persistence;

public interface IRepository<T> where T : BaseEntity
{
    Task<T?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<T?> GetByIdIncludingDeletedAsync(Guid id, CancellationToken ct = default);
    Task AddAsync(T entity, CancellationToken ct = default);
    void Update(T entity);

    /// <summary>Logical delete: marks the entity as deleted, it stays in the database.</summary>
    void Remove(T entity);

    void Restore(T entity);
}
