using Identity.Domain.Authorization;
using Identity.Domain.Common;

namespace Identity.Domain.Entities;

public class Role : BaseEntity
{
    public const string Admin = "Admin";
    public const string User = "User";

    public required string Name { get; set; }
    public string? Description { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = [];
    public ICollection<RolePermission> RolePermissions { get; set; } = [];

    /// <summary>Admin and User are created by the seed and can never be renamed or deleted.</summary>
    public bool IsSystem => IsSystemName(Name);

    public static bool IsSystemName(string name) =>
        string.Equals(name, Admin, StringComparison.OrdinalIgnoreCase) || string.Equals(name, User, StringComparison.OrdinalIgnoreCase);

    /// <summary>Admin always has every permission, whatever is stored.</summary>
    public IReadOnlyList<string> EffectivePermissions() =>
        (Name == Admin ? Permissions.All : RolePermissions.Select(p => p.Permission)).Order().ToList();
}
