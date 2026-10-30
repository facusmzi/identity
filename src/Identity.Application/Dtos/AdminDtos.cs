using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos;

public sealed record AdminUserResponse(
    Guid Id,
    string Email,
    bool EmailVerified,
    IReadOnlyList<string> Roles,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    DateTime? DeletedAt);

public sealed record AssignRoleRequest([Required, MaxLength(64)] string Role);

public sealed record RoleResponse(Guid Id, string Name, string? Description);

public sealed record AuditEntryResponse(
    Guid Id,
    DateTime OccurredAt,
    string Action,
    Guid? ActorUserId,
    Guid? TargetUserId,
    string? IpAddress,
    string? Details);
