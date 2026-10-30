using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Common;

namespace Identity.Infrastructure.Persistence.Repositories;

/// <summary>
/// Base repository for soft-deletable entities.
/// <para>
/// WARNING: never call <c>ExecuteDelete</c>/<c>ExecuteDeleteAsync</c> on a soft-deletable entity. Bulk
/// operations bypass SaveChanges, so <see cref="Interceptors.AuditAndSoftDeleteInterceptor"/> never sees them
/// and the rows are physically deleted. The only allowed hard deletes are the explicit retention purges
/// (methods named <c>Purge*</c>); <c>ArchitectureTests</c> fails the build for any other use.
/// </para>
/// </summary>
public class Repository<T>(AppDbContext db) : IRepository<T> where T : BaseEntity
{
    protected AppDbContext Db { get; } = db;
    protected DbSet<T> Set => Db.Set<T>();

    public Task<T?> GetByIdAsync(Guid id, CancellationToken ct = default) =>
        Set.FirstOrDefaultAsync(e => e.Id == id, ct);

    public Task<T?> GetByIdIncludingDeletedAsync(Guid id, CancellationToken ct = default) =>
        Set.IgnoreQueryFilters().FirstOrDefaultAsync(e => e.Id == id, ct);

    public async Task AddAsync(T entity, CancellationToken ct = default) => await Set.AddAsync(entity, ct);

    public void Update(T entity) => Set.Update(entity);

    // Marked as Deleted; AuditAndSoftDeleteInterceptor rewrites it to an UPDATE of deleted_at.
    public void Remove(T entity) => Set.Remove(entity);

    public void Restore(T entity) => entity.DeletedAt = null;
}
