using System.Net;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Identity.Infrastructure.Messaging;

public sealed class SmtpOptions
{
    public const string Section = "Smtp";

    /// <summary>Empty host = emails are only written to the log (handy for local development).</summary>
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public bool UseStartTls { get; set; } = true;
    public string From { get; set; } = "Identity <no-reply@identity.local>";
}

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailTransport
{
    private readonly SmtpOptions _opt = options.Value;

    public Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default) =>
        SendAsync(to, "Your verification code", new BodyBuilder
        {
            TextBody = $"Your verification code is {code}",
            HtmlBody = $"<p>Your verification code is:</p><h2 style=\"letter-spacing:4px\">{code}</h2>",
        }, ct);

    public Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default)
    {
        var text = link is null
            ? $"Use this token to reset your password: {token}"
            : $"Reset your password here: {link}";
        var html = link is null
            ? $"<p>Use this token to reset your password:</p><pre>{WebUtility.HtmlEncode(token)}</pre>"
            : $"<p><a href=\"{WebUtility.HtmlEncode(link)}\">Reset your password</a></p>";

        return SendAsync(to, "Reset your password", new BodyBuilder
        {
            TextBody = text + "\n\nIf you did not request this, you can ignore this email.",
            HtmlBody = html + "<p>If you did not request this, you can ignore this email.</p>",
        }, ct);
    }

    public Task SendSecurityNoticeAsync(string to, string subject, string message, CancellationToken ct = default) =>
        SendAsync(to, subject, new BodyBuilder
        {
            TextBody = message,
            HtmlBody = $"<p>{WebUtility.HtmlEncode(message)}</p>",
        }, ct);

    private async Task SendAsync(string to, string subject, BodyBuilder body, CancellationToken ct)
    {
        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(_opt.From));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = body.ToMessageBody();

        using var client = new SmtpClient();
        await client.ConnectAsync(_opt.Host!, _opt.Port, _opt.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.None, ct);
        if (!string.IsNullOrEmpty(_opt.Username))
            await client.AuthenticateAsync(_opt.Username, _opt.Password ?? "", ct);
        await client.SendAsync(message, ct);
        await client.DisconnectAsync(true, ct);
    }
}

public sealed class LoggingEmailSender(ILogger<LoggingEmailSender> logger) : IEmailTransport
{
    public Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default)
    {
        logger.LogWarning("SMTP not configured. Verification code for {Email}: {Code}", to, code);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default)
    {
        logger.LogWarning("SMTP not configured. Password reset for {Email}: {Link}", to, link ?? token);
        return Task.CompletedTask;
    }

    public Task SendSecurityNoticeAsync(string to, string subject, string message, CancellationToken ct = default)
    {
        logger.LogWarning("SMTP not configured. Security notice for {Email}: {Subject}", to, subject);
        return Task.CompletedTask;
    }
}
