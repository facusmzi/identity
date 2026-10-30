using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Identity.Api.Extensions;
using Identity.Application.Dtos;
using Identity.Application.Services;

namespace Identity.Api.Controllers;

/// <summary>
/// Two-factor (TOTP) management for the signed-in user. Flow: setup → scan the QR / type the secret →
/// enable with a code (returns the recovery codes once) → from then on, login asks for the second factor.
/// </summary>
[ApiController]
[Authorize]
[Route("auth/mfa")]
[EnableRateLimiting(RateLimitingExtensions.Default)]
public sealed class MfaController(MfaService mfa) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<MfaStatusResponse>> Status(CancellationToken ct) =>
        await mfa.GetStatusAsync(User.GetUserId(), ct);

    [HttpPost("setup")]
    public async Task<ActionResult<MfaSetupResponse>> Setup(CancellationToken ct) =>
        await mfa.SetupAsync(User.GetUserId(), ct);

    /// <summary>Turns MFA on and revokes the other sessions. The recovery codes are shown only here.</summary>
    [HttpPost("enable")]
    public async Task<ActionResult<RecoveryCodesResponse>> Enable(MfaCodeRequest req, CancellationToken ct) =>
        await mfa.EnableAsync(User.GetUserId(), User.GetSessionId(), req, ct);

    /// <summary>Needs the password and a TOTP code or a recovery code. Revokes the other sessions.</summary>
    [HttpPost("disable")]
    public async Task<IActionResult> Disable(MfaDisableRequest req, CancellationToken ct)
    {
        await mfa.DisableAsync(User.GetUserId(), User.GetSessionId(), req, ct);
        return NoContent();
    }

    [HttpPost("recovery-codes")]
    public async Task<ActionResult<RecoveryCodesResponse>> RegenerateRecoveryCodes(MfaCodeRequest req, CancellationToken ct) =>
        await mfa.RegenerateRecoveryCodesAsync(User.GetUserId(), req, ct);
}
