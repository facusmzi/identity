using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Identity.Api.Extensions;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Application.Services;
using Identity.Domain.Entities;

namespace Identity.Api.Controllers;

[ApiController]
[Authorize(Roles = Role.Admin)]
[Route("admin")]
public sealed class AdminController(AdminService admin) : ControllerBase
{
    [HttpGet("users")]
    public async Task<ActionResult<PagedResult<AdminUserResponse>>> ListUsers(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 20, [FromQuery] bool includeDeleted = false, CancellationToken ct = default) =>
        await admin.ListUsersAsync(page, pageSize, includeDeleted, ct);

    [HttpGet("users/{id:guid}")]
    public async Task<ActionResult<AdminUserResponse>> GetUser(Guid id, CancellationToken ct) =>
        await admin.GetUserAsync(id, ct);

    /// <summary>Logical delete: the row stays with deleted_at set and all its sessions are revoked.</summary>
    [HttpDelete("users/{id:guid}")]
    public async Task<IActionResult> DeleteUser(Guid id, CancellationToken ct)
    {
        await admin.DeleteUserAsync(User.GetUserId(), id, ct);
        return NoContent();
    }

    [HttpPost("users/{id:guid}/restore")]
    public async Task<ActionResult<AdminUserResponse>> RestoreUser(Guid id, CancellationToken ct) =>
        await admin.RestoreUserAsync(id, ct);

    [HttpPost("users/{id:guid}/roles")]
    public async Task<ActionResult<AdminUserResponse>> AssignRole(Guid id, AssignRoleRequest req, CancellationToken ct) =>
        await admin.AssignRoleAsync(id, req, ct);

    [HttpDelete("users/{id:guid}/roles/{role}")]
    public async Task<ActionResult<AdminUserResponse>> RemoveRole(Guid id, string role, CancellationToken ct) =>
        await admin.RemoveRoleAsync(User.GetUserId(), id, role, ct);

    [HttpGet("roles")]
    public async Task<ActionResult<IReadOnlyList<RoleResponse>>> ListRoles(CancellationToken ct) =>
        Ok(await admin.ListRolesAsync(ct));
}
