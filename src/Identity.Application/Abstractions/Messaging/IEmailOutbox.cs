namespace Identity.Application.Abstractions.Messaging;

/// <summary>
/// Transactional outbox for emails. Enqueuing only stages the message: it is stored by the next
/// SaveChanges together with the change that caused it (so no email for a rolled-back change, and no
/// lost email if the process dies) and delivered later by a background dispatcher.
/// Always enqueue BEFORE calling SaveChanges.
/// </summary>
public interface IEmailOutbox
{
    void EnqueueVerificationCode(string to, string code);

    /// <param name="link">Reset page URL with the token, when Auth:PasswordResetUrl is configured.</param>
    void EnqueuePasswordReset(string to, string token, string? link);
}
