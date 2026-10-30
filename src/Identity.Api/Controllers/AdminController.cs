using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Identity.Api.Extensions;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Application.Services;
using Identity.Domain.Authorization;

namespace Identity.Api.Controllers;

/// <summary>Each endpoint requires one permission; roles only group permissions (Admin has all of them).</summary>
[ApiController]
[Authorize]
[Route("admin")]
public sealed class AdminController(AdminService admin) : ControllerBase
{
    [HttpGet("users")]
    [HasPermission(Permissions.UsersRead)]
    public async Task<ActionResult<PagedResult<AdminUserResponse>>> ListUsers(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 20, [FromQuery] bool includeDeleted = false, CancellationToken ct = default) =>
        await admin.ListUsersAsync(page, pageSize, includeDeleted, ct);

    [HttpGet("users/{id:guid}")]
    [HasPermission(Permissions.UsersRead)]
    public async Task<ActionResult<AdminUserResponse>> GetUser(Guid id, CancellationToken ct) =>
        await admin.GetUserAsync(id, ct);

    /// <summary>Logical delete: the row stays with deleted_at set and all its sessions are revoked.</summary>
    [HttpDelete("users/{id:guid}")]
    [HasPermission(Permissions.UsersManage)]
    public async Task<IActionResult> DeleteUser(Guid id, CancellationToken ct)
    {
        await admin.DeleteUserAsync(User.GetUserId(), id, ct);
        return NoContent();
    }

    [HttpPost("users/{id:guid}/restore")]
    [HasPermission(Permissions.UsersManage)]
    public async Task<ActionResult<AdminUserResponse>> RestoreUser(Guid id, CancellationToken ct) =>
        await admin.RestoreUserAsync(User.GetUserId(), id, ct);

    [HttpPost("users/{id:guid}/roles")]
    [HasPermission(Permissions.RolesAssign)]
    public async Task<ActionResult<AdminUserResponse>> AssignRole(Guid id, AssignRoleRequest req, CancellationToken ct) =>
        await admin.AssignRoleAsync(User.GetUserId(), id, req, ct);

    [HttpDelete("users/{id:guid}/roles/{role}")]
    [HasPermission(Permissions.RolesAssign)]
    public async Task<ActionResult<AdminUserResponse>> RemoveRole(Guid id, string role, CancellationToken ct) =>
        await admin.RemoveRoleAsync(User.GetUserId(), id, role, ct);

    [HttpGet("permissions")]
    [HasPermission(Permissions.RolesRead)]
    public ActionResult<IReadOnlyList<string>> ListPermissions() => Ok(AdminService.ListPermissions());

    [HttpGet("roles")]
    [HasPermission(Permissions.RolesRead)]
    public async Task<ActionResult<IReadOnlyList<RoleResponse>>> ListRoles(CancellationToken ct) =>
        Ok(await admin.ListRolesAsync(ct));

    [HttpPost("roles")]
    [HasPermission(Permissions.RolesManage)]
    public async Task<ActionResult<RoleResponse>> CreateRole(CreateRoleRequest req, CancellationToken ct) =>
        StatusCode(StatusCodes.Status201Created, await admin.CreateRoleAsync(User.GetUserId(), req, ct));

    [HttpPut("roles/{name}/permissions")]
    [HasPermission(Permissions.RolesManage)]
    public async Task<ActionResult<RoleResponse>> SetRolePermissions(string name, SetRolePermissionsRequest req, CancellationToken ct) =>
        await admin.SetRolePermissionsAsync(User.GetUserId(), name, req, ct);

    /// <summary>Logical delete of the role and of its links to users and permissions.</summary>
    [HttpDelete("roles/{name}")]
    [HasPermission(Permissions.RolesManage)]
    public async Task<IActionResult> DeleteRole(string name, CancellationToken ct)
    {
        await admin.DeleteRoleAsync(User.GetUserId(), name, ct);
        return NoContent();
    }

    /// <summary>Security and admin events, newest first. <paramref name="userId"/> matches actor or target.</summary>
    [HttpGet("audit")]
    [HasPermission(Permissions.AuditRead)]
    public async Task<ActionResult<PagedResult<AuditEntryResponse>>> ListAudit(
        [FromQuery] Guid? userId, [FromQuery] string? action,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50, CancellationToken ct = default) =>
        await admin.ListAuditAsync(userId, action, page, pageSize, ct);
}
