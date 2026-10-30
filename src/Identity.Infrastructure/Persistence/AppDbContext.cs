using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Common;
using Identity.Domain.Common;
using Identity.Domain.Entities;
using Identity.Infrastructure.Messaging;

namespace Identity.Infrastructure.Persistence;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options), IUnitOfWork
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<MfaRecoveryCode> MfaRecoveryCodes => Set<MfaRecoveryCode>();
    public DbSet<MfaChallenge> MfaChallenges => Set<MfaChallenge>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<OutboxEmail> OutboxEmails => Set<OutboxEmail>();
    public DbSet<OutboxWebhook> OutboxWebhooks => Set<OutboxWebhook>();

    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken ct = default)
    {
        try
        {
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, ct);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            throw new UniqueConstraintViolationException(ex);
        }
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        try
        {
            return base.SaveChanges(acceptAllChangesOnSuccess);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            throw new UniqueConstraintViolationException(ex);
        }
    }

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

    // SQLite is only used by the test suite; matching on the type name avoids a package reference here.
    private static bool IsUniqueViolation(DbUpdateException ex) => ex.InnerException switch
    {
        PostgresException pg => pg.SqlState == PostgresErrorCodes.UniqueViolation,
        { } inner => inner.GetType().Name == "SqliteException" && inner.Message.Contains("UNIQUE constraint failed"),
        _ => false,
    };
}
