namespace Identity.Domain.Entities;

/// <summary>
/// Append-only record of a security-relevant action. Deliberately not a BaseEntity: audit entries are never
/// edited or logically deleted, only purged after the retention period.
/// </summary>
public class AuditEntry
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public DateTime OccurredAt { get; set; }

    /// <summary>Who did it (null for anonymous actions such as a failed login).</summary>
    public Guid? ActorUserId { get; set; }

    /// <summary>Who it was done to (null when the target account does not exist).</summary>
    public Guid? TargetUserId { get; set; }

    public required string Action { get; set; }
    public string? IpAddress { get; set; }

    /// <summary>Optional JSON with extra context (never secrets).</summary>
    public string? Details { get; set; }
}

public static class AuditActions
{
    public const string LoginSucceeded = "login.succeeded";
    public const string LoginFailed = "login.failed";
    public const string AccountLocked = "login.account_locked";
    public const string EmailVerified = "email.verified";
    public const string PasswordChanged = "password.changed";
    public const string PasswordReset = "password.reset";
    public const string RefreshTokenReused = "session.refresh_token_reused";
    public const string AccountDeleted = "account.deleted";

    public const string AdminUserDeleted = "admin.user_deleted";
    public const string AdminUserRestored = "admin.user_restored";
    public const string AdminRoleAssigned = "admin.role_assigned";
    public const string AdminRoleRemoved = "admin.role_removed";
    public const string AdminRoleCreated = "admin.role_created";
    public const string AdminRolePermissionsChanged = "admin.role_permissions_changed";
    public const string AdminRoleDeleted = "admin.role_deleted";

    public const string MfaEnabled = "mfa.enabled";
    public const string MfaDisabled = "mfa.disabled";
    public const string MfaFailed = "mfa.failed";
    public const string MfaRecoveryCodeUsed = "mfa.recovery_code_used";
    public const string MfaRecoveryCodesRegenerated = "mfa.recovery_codes_regenerated";
    public const string PasswordBreachCheckUnavailable = "password.breach_check_unavailable";
}
