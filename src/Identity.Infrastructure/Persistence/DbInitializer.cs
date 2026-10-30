using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Identity.Application.Abstractions.Security;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence;

public static class DbInitializer
{
    /// <summary>Applies migrations, seeds the base roles and, if configured, a first admin user.</summary>
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken ct = default)
    {
        await using var scope = services.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<AppDbContext>();
        var config = sp.GetRequiredService<IConfiguration>();
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(nameof(DbInitializer));

        if (db.Database.IsNpgsql()) await db.Database.MigrateAsync(ct);
        else await db.Database.EnsureCreatedAsync(ct);

        foreach (var (name, description) in new[] { (Role.Admin, "Full access"), (Role.User, "Default role") })
        {
            if (!await db.Roles.AnyAsync(r => r.Name == name, ct))
                db.Roles.Add(new Role { Name = name, Description = description });
        }
        await db.SaveChangesAsync(ct);

        var adminEmail = config["Seed:AdminEmail"]?.Trim().ToLowerInvariant();
        var adminPassword = config["Seed:AdminPassword"];
        if (string.IsNullOrEmpty(adminEmail) || string.IsNullOrEmpty(adminPassword)) return;
        if (await db.Users.AnyAsync(u => u.Email == adminEmail, ct)) return;

        var hasher = sp.GetRequiredService<IPasswordHasher>();
        var roles = await db.Roles.Where(r => r.Name == Role.Admin || r.Name == Role.User).ToListAsync(ct);
        var admin = new User { Email = adminEmail, PasswordHash = await hasher.HashAsync(adminPassword, ct), EmailVerified = true };
        foreach (var role in roles) admin.UserRoles.Add(new UserRole { User = admin, Role = role });

        db.Users.Add(admin);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Seeded admin user {Email}", adminEmail);
    }
}
