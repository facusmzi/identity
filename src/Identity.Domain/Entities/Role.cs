using Identity.Domain.Common;

namespace Identity.Domain.Entities;

public class Role : BaseEntity
{
    public const string Admin = "Admin";
    public const string User = "User";

    public required string Name { get; set; }
    public string? Description { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = [];
}
