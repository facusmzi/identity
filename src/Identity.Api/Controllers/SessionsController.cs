using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Identity.Api.Extensions;
using Identity.Application.Dtos;
using Identity.Application.Services;

namespace Identity.Api.Controllers;

[ApiController]
[Authorize]
[Route("sessions")]
public sealed class SessionsController(SessionService sessions) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<SessionResponse>>> List(CancellationToken ct) =>
        Ok(await sessions.ListActiveAsync(User.GetUserId(), User.GetSessionId(), ct));

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Revoke(Guid id, CancellationToken ct)
    {
        var wasCurrent = await sessions.RevokeAsync(User.GetUserId(), User.GetSessionId(), id, ct);
        return Ok(new { message = wasCurrent ? "Current session revoked" : "Session revoked" });
    }
}
