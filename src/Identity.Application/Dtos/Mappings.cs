using Identity.Domain.Entities;

namespace Identity.Application.Dtos;

internal static class Mappings
{
    public static IReadOnlyList<string> RoleNames(this User user) =>
        user.UserRoles.Select(ur => ur.Role.Name).Order().ToList();

    public static UserResponse ToResponse(this User user) =>
        new(user.Id, user.Email, user.EmailVerified, user.RoleNames(), user.CreatedAt);

    public static AdminUserResponse ToAdminResponse(this User user) =>
        new(user.Id, user.Email, user.EmailVerified, user.RoleNames(), user.CreatedAt, user.UpdatedAt, user.DeletedAt);

    public static RoleResponse ToResponse(this Role role) => new(role.Id, role.Name, role.Description);

    public static SessionResponse ToResponse(this Session s, Guid currentSessionId) =>
        new(s.Id, s.IpAddress, s.UserAgent, s.LoginMethod.ToString().ToLowerInvariant(), s.ExpiresAt, s.CreatedAt, s.Id == currentSessionId);
}
