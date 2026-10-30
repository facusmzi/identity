using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence;

public static class DbInitializer
{
    /// <summary>
    /// Checks the schema, seeds the base roles and, if configured, a first admin user.
    /// Migrations are applied here only when Database:MigrateOnStartup is true (Development). Everywhere else they
    /// are a deploy step (migration bundle / migrator image), so several instances never race to migrate, and the
    /// API refuses to start against a database that is behind.
    /// </summary>
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken ct = default)
    {
        await using var scope = services.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<AppDbContext>();
        var config = sp.GetRequiredService<IConfiguration>();
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(DbInitializer));

        if (!db.Database.IsNpgsql())
        {
            await db.Database.EnsureCreatedAsync(ct); // test suite (SQLite)
        }
        else if (config.GetValue("Database:MigrateOnStartup", false))
        {
            await db.Database.MigrateAsync(ct);
        }
        else
        {
            var pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToList();
            if (pending.Count > 0)
                throw new InvalidOperationException(
                    $"The database is missing {pending.Count} migration(s) ({string.Join(", ", pending)}). " +
                    "Run the migration bundle (scripts/migrate.ps1 or the 'migrator' image) before starting the API.");
        }

        await SeedRolesAsync(db, ct);
        await SeedAdminAsync(db, config, sp.GetRequiredService<IPasswordHasher>(), logger, ct);
    }

    private static async Task SeedRolesAsync(AppDbContext db, CancellationToken ct)
    {
        foreach (var (name, description) in new[] { (Role.Admin, "Full access"), (Role.User, "Default role") })
        {
            if (!await db.Roles.AnyAsync(r => r.Name == name, ct))
                db.Roles.Add(new Role { Name = name, Description = description });
        }
        await SaveIgnoringRaceAsync(db, ct);
    }

    private static async Task SeedAdminAsync(
        AppDbContext db, IConfiguration config, IPasswordHasher hasher, ILogger logger, CancellationToken ct)
    {
        var adminEmail = config["Seed:AdminEmail"]?.Trim().ToLowerInvariant();
        var adminPassword = config["Seed:AdminPassword"];
        if (string.IsNullOrEmpty(adminEmail) || string.IsNullOrEmpty(adminPassword)) return;
        if (await db.Users.AnyAsync(u => u.Email == adminEmail, ct)) return;

        var roles = await db.Roles.Where(r => r.Name == Role.Admin || r.Name == Role.User).ToListAsync(ct);
        var admin = new User { Email = adminEmail, PasswordHash = await hasher.HashAsync(adminPassword, ct), EmailVerified = true };
        foreach (var role in roles) admin.UserRoles.Add(new UserRole { User = admin, Role = role });

        db.Users.Add(admin);
        if (await SaveIgnoringRaceAsync(db, ct))
            logger.LogInformation("Seeded admin user {Email}", adminEmail);
    }

    /// <summary>Another instance starting at the same time may seed first; that is fine.</summary>
    private static async Task<bool> SaveIgnoringRaceAsync(AppDbContext db, CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (UniqueConstraintViolationException)
        {
            db.ChangeTracker.Clear();
            return false;
        }
    }
}
