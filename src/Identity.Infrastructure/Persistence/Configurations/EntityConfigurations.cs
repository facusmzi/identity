using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Configurations;

// Unique indexes are filtered on deleted_at IS NULL so a logically deleted row
// does not block re-using its email / role name / user-role pair.
internal static class SoftDelete
{
    public const string ActiveOnly = "deleted_at IS NULL";
}

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> b)
    {
        b.ToTable("users");
        b.Property(u => u.Email).HasMaxLength(254).IsRequired();
        b.Property(u => u.PasswordHash).HasMaxLength(256);
        b.Property(u => u.EmailVerificationCodeHash).HasMaxLength(64);
        b.Property(u => u.PasswordResetTokenHash).HasMaxLength(64);
        b.HasIndex(u => u.Email).IsUnique().HasFilter(SoftDelete.ActiveOnly);
        b.HasIndex(u => u.DeletedAt);
        b.Ignore(u => u.IsDeleted);
    }
}

internal sealed class SessionConfiguration : IEntityTypeConfiguration<Session>
{
    public void Configure(EntityTypeBuilder<Session> b)
    {
        b.ToTable("sessions");
        b.Property(s => s.RefreshTokenHash).HasMaxLength(64).IsRequired();
        b.Property(s => s.PreviousRefreshTokenHash).HasMaxLength(64);
        b.Property(s => s.IpAddress).HasMaxLength(64);
        b.Property(s => s.UserAgent).HasMaxLength(512);
        b.Property(s => s.LoginMethod).HasConversion<string>().HasMaxLength(32);
        b.HasIndex(s => s.RefreshTokenHash).IsUnique();
        b.HasIndex(s => new { s.UserId, s.RevokedAt });
        b.HasOne(s => s.User).WithMany(u => u.Sessions).HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
        b.Ignore(s => s.IsDeleted);
    }
}

internal sealed class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> b)
    {
        b.ToTable("roles");
        b.Property(r => r.Name).HasMaxLength(64).IsRequired();
        b.Property(r => r.Description).HasMaxLength(256);
        b.HasIndex(r => r.Name).IsUnique().HasFilter(SoftDelete.ActiveOnly);
        b.Ignore(r => r.IsDeleted);
    }
}

internal sealed class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> b)
    {
        b.ToTable("user_roles");
        b.HasIndex(ur => new { ur.UserId, ur.RoleId }).IsUnique().HasFilter(SoftDelete.ActiveOnly);
        b.HasOne(ur => ur.User).WithMany(u => u.UserRoles).HasForeignKey(ur => ur.UserId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne(ur => ur.Role).WithMany(r => r.UserRoles).HasForeignKey(ur => ur.RoleId).OnDelete(DeleteBehavior.Cascade);
        b.Ignore(ur => ur.IsDeleted);
    }
}
