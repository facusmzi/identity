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
    [AllowAnonymous]
    [HttpPost("register")]
    [EnableRateLimiting(RateLimitingExtensions.Strict)]
    public async Task<IActionResult> Register(RegisterRequest req, CancellationToken ct)
    {
        await auth.RegisterAsync(req, ct);
        return Accepted(new { message = "If the email can be registered, a verification code has been sent" });
    }

    /// <summary>Requires the code from the email and the password chosen at registration.</summary>
    [AllowAnonymous]
    [HttpPost("verify-email")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<IActionResult> VerifyEmail(VerifyEmailRequest req, CancellationToken ct)
    {
        await auth.VerifyEmailAsync(req, ct);
        return Ok(new { message = "Email verified" });
    }

    [AllowAnonymous]
    [HttpPost("resend-verification")]
    [EnableRateLimiting(RateLimitingExtensions.Strict)]
    public async Task<IActionResult> ResendVerification(ResendVerificationRequest req, CancellationToken ct)
    {
        await auth.ResendVerificationAsync(req, ct);
        return Ok(new { message = "If the account is pending verification, a new code has been sent" });
    }

    /// <summary>
    /// Returns the tokens, or <c>mfaRequired: true</c> plus an <c>mfaToken</c> for POST /auth/login/mfa.
    /// With <c>useCookies: true</c> the tokens are set as HttpOnly cookies instead (the body keeps the expiries).
    /// </summary>
    [AllowAnonymous]
    [HttpPost("login")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<ActionResult<LoginResponse>> Login(LoginRequest req, CancellationToken ct)
    {
        var result = await auth.LoginAsync(req, ClientMeta(), ct);
        if (!req.UseCookies || result.MfaRequired) return result;

        SessionCookies.Write(Response, new AuthTokensResponse(result.AccessToken!, result.RefreshToken!,
            result.AccessExpiresAt!.Value, result.RefreshExpiresAt!.Value));
        return result with { AccessToken = null, RefreshToken = null };
    }

    /// <summary>Second login step with a TOTP <c>code</c> or a <c>recoveryCode</c>.</summary>
    [AllowAnonymous]
    [HttpPost("login/mfa")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<ActionResult<AuthTokensResponse>> LoginMfa(MfaLoginRequest req, CancellationToken ct)
    {
        var tokens = await auth.LoginWithMfaAsync(req, ClientMeta(), ct);
        if (!req.UseCookies) return tokens;

        SessionCookies.Write(Response, tokens);
        return SessionCookies.WithoutSecrets(tokens);
    }

    /// <summary>
    /// The current CSRF token, for a page that was reloaded and lost it from memory. Only readable by the origins
    /// allowed in CORS (other sites can trigger the request but cannot see the answer).
    /// </summary>
    [AllowAnonymous]
    [HttpGet("csrf")]
    public IActionResult Csrf() =>
        Request.Cookies.TryGetValue(SessionCookies.Csrf, out var token) && !string.IsNullOrEmpty(token)
            ? Ok(new { csrfToken = token })
            : Unauthorized();

    /// <summary>Bearer clients send <c>refreshToken</c>; browsers send nothing and the session cookie is used.</summary>
    [AllowAnonymous]
    [HttpPost("refresh")]
    [EnableRateLimiting(RateLimitingExtensions.Default)]
    public async Task<ActionResult<AuthTokensResponse>> Refresh(RefreshRequest? req, CancellationToken ct)
    {
        var fromCookie = string.IsNullOrEmpty(req?.RefreshToken) && Request.Cookies.TryGetValue(SessionCookies.Refresh, out _);
        var token = fromCookie ? Request.Cookies[SessionCookies.Refresh] : req?.RefreshToken;

        AuthTokensResponse tokens;
        try
        {
            tokens = await auth.RefreshAsync(new RefreshRequest(token), ClientMeta(), ct);
        }
        catch (UnauthorizedException ex) when (fromCookie)
        {
            // A dead session: drop the cookies so the page shows the login. Answered here, not rethrown, because
            // the exception handler clears the response, Set-Cookie headers included.
            SessionCookies.Clear(Response);
            var problem = ProblemDetailsFactory.CreateProblemDetails(HttpContext, StatusCodes.Status401Unauthorized, ex.Message);
            problem.Extensions["code"] = ex.Code;
            return Unauthorized(problem);
        }

        if (!fromCookie) return tokens;
        SessionCookies.Write(Response, tokens);
        return SessionCookies.WithoutSecrets(tokens);
    }

    /// <summary>Always 200, whether or not the email exists (no account enumeration).</summary>
    [AllowAnonymous]
    [HttpPost("forgot-password")]
    [EnableRateLimiting(RateLimitingExtensions.Strict)]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest req, CancellationToken ct)
    {
        await auth.ForgotPasswordAsync(req, ct);
        return Ok(new { message = "If the account exists, a reset email has been sent" });
    }

    [AllowAnonymous]
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
        await auth.LogoutAsync(User.GetUserId(), User.GetSessionId(), ct);
        SessionCookies.Clear(Response);
        return Ok(new { message = "Logged out" });
    }

    [Authorize]
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAll(CancellationToken ct)
    {
        await auth.LogoutAllAsync(User.GetUserId(), ct);
        SessionCookies.Clear(Response);
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
