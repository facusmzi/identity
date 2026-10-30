using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Common;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options), IUnitOfWork
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();

    public Task ExecuteInTransactionAsync(Func<CancellationToken, Task> action, CancellationToken ct = default) =>
        // Going through the execution strategy keeps this compatible with retrying strategies (EnableRetryOnFailure).
        Database.CreateExecutionStrategy().ExecuteAsync(async token =>
        {
            await using var tx = await Database.BeginTransactionAsync(token);
            await action(token);
            await tx.CommitAsync(token);
        }, ct);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);

        foreach (var entityType in modelBuilder.Model.GetEntityTypes()
                     .Where(t => typeof(BaseEntity).IsAssignableFrom(t.ClrType)))
        {
            // Ids are generated client-side (Guid v7) by BaseEntity. Telling EF they are never
            // store-generated makes new entities added through a navigation be INSERTed, not UPDATEd.
            modelBuilder.Entity(entityType.ClrType).Property(nameof(BaseEntity.Id)).ValueGeneratedNever();

            // Global soft-delete filter: every query hides rows with deleted_at set,
            // unless the repository explicitly calls IgnoreQueryFilters().
            var param = Expression.Parameter(entityType.ClrType, "e");
            var body = Expression.Equal(
                Expression.Property(param, nameof(ISoftDeletable.DeletedAt)),
                Expression.Constant(null, typeof(DateTime?)));
            modelBuilder.Entity(entityType.ClrType).HasQueryFilter(Expression.Lambda(body, param));
        }
    }
}
