using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Identity.Domain.Entities;
using Identity.Infrastructure.Messaging;

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
        b.Property(u => u.MfaSecretEncrypted).HasMaxLength(256);
        b.Property(u => u.MfaPendingSecretEncrypted).HasMaxLength(256);
        b.HasIndex(u => u.Email).IsUnique().HasFilter(SoftDelete.ActiveOnly);
        b.HasIndex(u => u.DeletedAt);
        b.Ignore(u => u.IsDeleted);
    }
}

internal sealed class RolePermissionConfiguration : IEntityTypeConfiguration<RolePermission>
{
    public void Configure(EntityTypeBuilder<RolePermission> b)
    {
        b.ToTable("role_permissions");
        b.Property(p => p.Permission).HasMaxLength(64).IsRequired();
        b.HasIndex(p => new { p.RoleId, p.Permission }).IsUnique().HasFilter(SoftDelete.ActiveOnly);
        b.HasOne(p => p.Role).WithMany(r => r.RolePermissions).HasForeignKey(p => p.RoleId).OnDelete(DeleteBehavior.Cascade);
        b.Ignore(p => p.IsDeleted);
    }
}

internal sealed class MfaRecoveryCodeConfiguration : IEntityTypeConfiguration<MfaRecoveryCode>
{
    public void Configure(EntityTypeBuilder<MfaRecoveryCode> b)
    {
        b.ToTable("mfa_recovery_codes");
        b.Property(c => c.CodeHash).HasMaxLength(64).IsRequired();
        b.HasIndex(c => new { c.UserId, c.CodeHash });
        b.HasOne(c => c.User).WithMany(u => u.RecoveryCodes).HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);
        b.Ignore(c => c.IsDeleted);
    }
}

internal sealed class MfaChallengeConfiguration : IEntityTypeConfiguration<MfaChallenge>
{
    public void Configure(EntityTypeBuilder<MfaChallenge> b)
    {
        b.ToTable("mfa_challenges");
        b.Property(c => c.Id).ValueGeneratedNever();
        b.Property(c => c.TokenHash).HasMaxLength(64).IsRequired();
        b.Property(c => c.IpAddress).HasMaxLength(64);
        b.Property(c => c.UserAgent).HasMaxLength(512);
        b.HasIndex(c => c.TokenHash).IsUnique();
        b.HasIndex(c => c.ExpiresAt);
        b.HasOne<User>().WithMany().HasForeignKey(c => c.UserId).OnDelete(DeleteBehavior.Cascade);
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

internal sealed class AuditEntryConfiguration : IEntityTypeConfiguration<AuditEntry>
{
    public void Configure(EntityTypeBuilder<AuditEntry> b)
    {
        b.ToTable("audit_log");
        b.Property(e => e.Id).ValueGeneratedNever();
        b.Property(e => e.Action).HasMaxLength(64).IsRequired();
        b.Property(e => e.IpAddress).HasMaxLength(64);
        b.Property(e => e.Details).HasMaxLength(2000);
        b.HasIndex(e => e.OccurredAt);
        b.HasIndex(e => new { e.TargetUserId, e.OccurredAt });
        b.HasIndex(e => new { e.Action, e.OccurredAt });
        // No FKs to users on purpose: the log must outlive (and not block purging of) the rows it mentions.
    }
}

internal sealed class OutboxEmailConfiguration : IEntityTypeConfiguration<OutboxEmail>
{
    public void Configure(EntityTypeBuilder<OutboxEmail> b)
    {
        b.ToTable("outbox_emails");
        b.Property(m => m.Id).ValueGeneratedNever();
        b.Property(m => m.Kind).HasMaxLength(32).IsRequired();
        b.Property(m => m.To).HasMaxLength(254).IsRequired();
        b.Property(m => m.Payload).HasMaxLength(4000);
        b.Property(m => m.LastError).HasMaxLength(1000);
        b.HasIndex(m => new { m.SentAt, m.FailedAt, m.NextAttemptAt });
    }
}
