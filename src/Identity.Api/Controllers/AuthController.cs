using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Identity.Api.Extensions;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Application.Services;

namespace Identity.Api.Controllers;

[ApiController]
[Route("auth")]
public sealed class AuthController(AuthService auth) : ControllerBase
{
    /// <summary>Always 202, whether or not the email is already registered (no account enumeration).</summary>
    [HttpPost("register")]
    [EnableRateLimiting(RateLimitingExtensions.Strict)]
    public async Task<IActionResult> Register(RegisterRequest req, CancellationToken ct)
    {
        await auth.RegisterAsync(req, ct);
        return Accepted(new { message = "If the email can be registered, a verification code has been sent" });
    }

    /// <summary>Requires the code from the email and the password chosen at registration.</summary>
    [HttpPost("verify-email")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<IActionResult> VerifyEmail(VerifyEmailRequest req, CancellationToken ct)
    {
        await auth.VerifyEmailAsync(req, ct);
        return Ok(new { message = "Email verified" });
    }

    [HttpPost("resend-verification")]
    [EnableRateLimiting(RateLimitingExtensions.Strict)]
    public async Task<IActionResult> ResendVerification(ResendVerificationRequest req, CancellationToken ct)
    {
        await auth.ResendVerificationAsync(req, ct);
        return Ok(new { message = "If the account is pending verification, a new code has been sent" });
    }

    [HttpPost("login")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<ActionResult<AuthTokensResponse>> Login(LoginRequest req, CancellationToken ct) =>
        await auth.LoginAsync(req, ClientMeta(), ct);

    [HttpPost("refresh")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<ActionResult<AuthTokensResponse>> Refresh(RefreshRequest req, CancellationToken ct) =>
        await auth.RefreshAsync(req, ClientMeta(), ct);

    /// <summary>Always 200, whether or not the email exists (no account enumeration).</summary>
    [HttpPost("forgot-password")]
    [EnableRateLimiting(RateLimitingExtensions.Strict)]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest req, CancellationToken ct)
    {
        await auth.ForgotPasswordAsync(req, ct);
        return Ok(new { message = "If the account exists, a reset email has been sent" });
    }

    [HttpPost("reset-password")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest req, CancellationToken ct)
    {
        await auth.ResetPasswordAsync(req, ct);
        return Ok(new { message = "Password reset. All sessions revoked." });
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        await auth.LogoutAsync(User.GetSessionId(), ct);
        return Ok(new { message = "Logged out" });
    }

    [Authorize]
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAll(CancellationToken ct)
    {
        await auth.LogoutAllAsync(User.GetUserId(), ct);
        return Ok(new { message = "All sessions revoked" });
    }

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest req, CancellationToken ct)
    {
        await auth.ChangePasswordAsync(User.GetUserId(), User.GetSessionId(), req, ct);
        return Ok(new { message = "Password changed. Other sessions revoked." });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserResponse>> Me(CancellationToken ct) =>
        await auth.GetMeAsync(User.GetUserId(), ct);

    /// <summary>Logical delete of your own account (requires the current password).</summary>
    [Authorize]
    [HttpDelete("me")]
    public async Task<IActionResult> DeleteMe(DeleteAccountRequest req, CancellationToken ct)
    {
        await auth.DeleteAccountAsync(User.GetUserId(), req, ct);
        return NoContent();
    }

    private ClientMeta ClientMeta() =>
        new(HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null);
}
