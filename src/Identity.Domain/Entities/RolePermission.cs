using Identity.Domain.Common;

namespace Identity.Domain.Entities;

public class RolePermission : BaseEntity
{
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;

    public required string Permission { get; set; }
}
