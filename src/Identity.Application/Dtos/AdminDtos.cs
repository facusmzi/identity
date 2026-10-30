using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos;

public sealed record AdminUserResponse(
    Guid Id,
    string Email,
    bool EmailVerified,
    IReadOnlyList<string> Roles,
    bool MfaEnabled,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    DateTime? DeletedAt);

public sealed record AssignRoleRequest([Required, MaxLength(64)] string Role);

public sealed record RoleResponse(Guid Id, string Name, string? Description, IReadOnlyList<string> Permissions, bool IsSystem);

public sealed record CreateRoleRequest(
    [Required, RegularExpression(@"^[A-Za-z][A-Za-z0-9 _-]{1,63}$", ErrorMessage = "2-64 chars: letters, digits, space, _ or -, starting with a letter.")]
    string Name,
    [MaxLength(256)] string? Description,
    [Required] IReadOnlyList<string> Permissions);

public sealed record SetRolePermissionsRequest([Required] IReadOnlyList<string> Permissions);

public sealed record AuditEntryResponse(
    Guid Id,
    DateTime OccurredAt,
    string Action,
    Guid? ActorUserId,
    Guid? TargetUserId,
    string? IpAddress,
    string? Details);
