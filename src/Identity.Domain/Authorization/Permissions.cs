namespace Identity.Domain.Authorization;

/// <summary>
/// Granular permissions. Roles group permissions and authorization is always evaluated per permission.
/// The Admin role implicitly has every permission (it cannot be locked out of anything).
/// </summary>
public static class Permissions
{
    public const string UsersRead = "users.read";
    public const string UsersManage = "users.manage";
    public const string RolesRead = "roles.read";
    public const string RolesManage = "roles.manage";
    public const string RolesAssign = "roles.assign";
    public const string AuditRead = "audit.read";

    public static IReadOnlyList<string> All { get; } =
    [
        UsersRead,
        UsersManage,
        RolesRead,
        RolesManage,
        RolesAssign,
        AuditRead,
    ];

    public static bool IsKnown(string permission) => All.Contains(permission, StringComparer.Ordinal);
}
