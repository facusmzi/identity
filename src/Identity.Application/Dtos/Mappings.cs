using Identity.Domain.Entities;

namespace Identity.Application.Dtos;

internal static class Mappings
{
    public static IReadOnlyList<string> RoleNames(this User user) =>
        user.UserRoles.Select(ur => ur.Role.Name).Order().ToList();

    /// <summary>Union of the permissions of every role the user has (requires roles and their permissions loaded).</summary>
    public static IReadOnlyList<string> EffectivePermissions(this User user) =>
        user.UserRoles.SelectMany(ur => ur.Role.EffectivePermissions()).Distinct().Order().ToList();

    public static UserResponse ToResponse(this User user) =>
        new(user.Id, user.Email, user.EmailVerified, user.RoleNames(), user.EffectivePermissions(), user.MfaEnabled, user.CreatedAt);

    public static AdminUserResponse ToAdminResponse(this User user) =>
        new(user.Id, user.Email, user.EmailVerified, user.RoleNames(), user.MfaEnabled, user.LockedAt, user.CreatedAt, user.UpdatedAt, user.DeletedAt);

    public static RoleResponse ToResponse(this Role role) =>
        new(role.Id, role.Name, role.Description, role.EffectivePermissions(), role.IsSystem);

    public static AuditEntryResponse ToResponse(this AuditEntry e) =>
        new(e.Id, e.OccurredAt, e.Action, e.ActorUserId, e.TargetUserId, e.IpAddress, e.Details);

    public static AdminSessionResponse ToAdminResponse(this Session s, DateTime now) =>
        new(s.Id, s.IpAddress, s.UserAgent, s.LoginMethod.ToString(), s.CreatedAt, s.ExpiresAt, s.AbsoluteExpiresAt,
            s.RevokedAt, s.RevokedReason?.ToString(), s.IsActive(now));

    public static SessionResponse ToResponse(this Session s, Guid currentSessionId) =>
        new(s.Id, s.IpAddress, s.UserAgent, s.LoginMethod.ToString().ToLowerInvariant(), s.ExpiresAt, s.CreatedAt, s.Id == currentSessionId);
}
