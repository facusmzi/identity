namespace Identity.Application.Abstractions.Messaging;

public interface IEmailSender
{
    Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default);

    /// <param name="link">Reset page URL with the token, when Auth:PasswordResetUrl is configured.</param>
    Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default);
}
