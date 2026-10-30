namespace Identity.Application.Abstractions.Persistence;

public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken ct = default);

    /// <summary>
    /// Runs <paramref name="action"/> in a single database transaction: tracked changes saved inside it and
    /// bulk updates (e.g. revoking sessions) are committed together or not at all.
    /// </summary>
    Task ExecuteInTransactionAsync(Func<CancellationToken, Task> action, CancellationToken ct = default);
}
