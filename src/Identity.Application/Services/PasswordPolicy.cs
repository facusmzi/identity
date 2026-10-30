using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;
using Identity.Application.Options;
using Identity.Domain.Entities;

namespace Identity.Application.Services;

/// <summary>
/// Checks on a NEW password that DataAnnotations cannot do: not equal to the email and not in a known breach
/// (Have I Been Pwned, k-anonymity). Run it before looking up the account, so the answer never depends on
/// whether the email is registered.
/// </summary>
public sealed class PasswordPolicy(
    IPasswordBreachChecker breachChecker,
    AuditTrail audit,
    IOptions<BreachCheckOptions> options,
    ILogger<PasswordPolicy> logger)
{
    private readonly BreachCheckOptions _opt = options.Value;

    public async Task EnsureAcceptableAsync(string password, string email, Guid? userId, CancellationToken ct = default)
    {
        if (string.Equals(password.Trim(), email.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new BadRequestException("The password cannot be your email address", "PASSWORD_EQUALS_EMAIL");

        if (!_opt.Enabled) return;

        switch (await breachChecker.CheckAsync(password, ct))
        {
            case BreachCheckStatus.Breached:
                throw new BadRequestException(
                    "This password has appeared in a data breach and cannot be used. Choose a different one.", "PASSWORD_BREACHED");

            case BreachCheckStatus.Unavailable:
                audit.Record(AuditActions.PasswordBreachCheckUnavailable, userId, userId, new { failOpen = _opt.FailOpen });
                if (!_opt.FailOpen)
                    throw new BadRequestException(
                        "The password could not be checked right now. Please try again in a moment.", "PASSWORD_CHECK_UNAVAILABLE");
                logger.LogWarning("Breach check unavailable: password accepted without it (fail-open)");
                break;
        }
    }
}
